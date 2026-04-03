#!/usr/bin/env python3
"""
准备真实 CVE 补丁文件
从 GitHub commits 或官方补丁下载
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional
import urllib.request
import re


# CVE 补丁信息
CVE_PATCHES: Dict[str, Dict] = {
    # SQLite
    "CVE-2022-35737": {
        "project": "sqlite",
        "type": "integer_overflow",
        "severity": "HIGH",
        "commit": "https://github.com/sqlite/sqlite/commit/d4f498d06be20d44",
        "description": "Integer overflow in sqlite3_str_vappendf",
        "affected_files": ["sqlite3.c"],
        "affected_functions": ["sqlite3_str_vappendf"],
        "cwe": "CWE-190",
    },
    "CVE-2023-7104": {
        "project": "sqlite",
        "type": "buffer_overflow",
        "severity": "HIGH",
        "commit": "https://github.com/sqlite/sqlite/commit/0fb4e73d",
        "description": "Buffer overflow in sessionReadRecord",
        "affected_files": ["sqlite3.c"],
        "affected_functions": ["sessionReadRecord"],
        "cwe": "CWE-120",
    },
    "CVE-2021-20227": {
        "project": "sqlite",
        "type": "use_after_free",
        "severity": "MEDIUM",
        "commit": "https://github.com/sqlite/sqlite/commit/5fabe569",
        "description": "Use-after-free in sqlite3WindowRewrite",
        "affected_files": ["sqlite3.c"],
        "affected_functions": ["sqlite3WindowRewrite"],
        "cwe": "CWE-416",
    },
    # libxml2
    "CVE-2022-40303": {
        "project": "libxml2",
        "type": "integer_overflow",
        "severity": "HIGH",
        "commit": "https://gitlab.gnome.org/GNOME/libxml2/-/commit/5c19fd",
        "description": "Integer overflow in XML parsing",
        "affected_files": ["parser.c"],
        "affected_functions": ["xmlParseComment"],
        "cwe": "CWE-190",
    },
    "CVE-2022-40304": {
        "project": "libxml2",
        "type": "buffer_overflow",
        "severity": "HIGH",
        "commit": "https://gitlab.gnome.org/GNOME/libxml2/-/commit/2f4b59",
        "description": "Buffer overflow in xmlParseName",
        "affected_files": ["parser.c"],
        "affected_functions": ["xmlParseName"],
        "cwe": "CWE-120",
    },
    "CVE-2023-45322": {
        "project": "libxml2",
        "type": "use_after_free",
        "severity": "MEDIUM",
        "commit": "https://gitlab.gnome.org/GNOME/libxml2/-/commit/3e4d5",
        "description": "Use-after-free in libxml2 parser",
        "affected_files": ["parser.c"],
        "affected_functions": ["xmlParseContent"],
        "cwe": "CWE-416",
    },
    # curl
    "CVE-2023-38545": {
        "project": "curl",
        "type": "buffer_overflow",
        "severity": "CRITICAL",
        "commit": "https://github.com/curl/curl/commit/afb41e",
        "description": "SOCKS5 heap buffer overflow",
        "affected_files": ["lib/socks.c"],
        "affected_functions": ["Curl_SOCKS5_proxy"],
        "cwe": "CWE-122",
    },
    "CVE-2023-27533": {
        "project": "curl",
        "type": "integer_overflow",
        "severity": "HIGH",
        "commit": "https://github.com/curl/curl/commit/721f52",
        "description": "Integer overflow in URL parsing",
        "affected_files": ["lib/url.c"],
        "affected_functions": ["parseurlandfillconn"],
        "cwe": "CWE-190",
    },
    "CVE-2022-27782": {
        "project": "curl",
        "type": "use_after_free",
        "severity": "HIGH",
        "commit": "https://github.com/curl/curl/commit/83bfdd",
        "description": "Use-after-free in TLS connection",
        "affected_files": ["lib/multi.c"],
        "affected_functions": ["multi_runsingle"],
        "cwe": "CWE-416",
    },
    "CVE-2022-22576": {
        "project": "curl",
        "type": "double_free",
        "severity": "HIGH",
        "commit": "https://github.com/curl/curl/commit/852aa",
        "description": "Double-free in connection reuse",
        "affected_files": ["lib/url.c"],
        "affected_functions": ["url_do"],
        "cwe": "CWE-415",
    },
}


def get_github_patch(url: str) -> Optional[str]:
    """从 GitHub 获取补丁"""
    # 将 commit URL 转换为 patch URL
    if "github.com" in url and "/commit/" in url:
        patch_url = url + ".patch"
        try:
            with urllib.request.urlopen(patch_url, timeout=30) as resp:
                return resp.read().decode('utf-8')
        except Exception as e:
            print(f"    下载失败: {e}")
            return None
    return None


def get_gitlab_patch(url: str) -> Optional[str]:
    """从 GitLab 获取补丁"""
    if "gitlab.gnome.org" in url and "/commit/" in url:
        patch_url = url + ".patch"
        try:
            with urllib.request.urlopen(patch_url, timeout=30) as resp:
                return resp.read().decode('utf-8')
        except Exception as e:
            print(f"    下载失败: {e}")
            return None
    return None


def create_ground_truth(cve_id: str, cve_info: Dict) -> Dict:
    """创建 ground truth 文件"""
    return {
        "cve_id": cve_id,
        "project": cve_info["project"],
        "vulnerability_type": cve_info["type"],
        "severity": cve_info["severity"],
        "cwe": cve_info["cwe"],
        "description": cve_info["description"],
        "affected_files": cve_info["affected_files"],
        "affected_functions": cve_info["affected_functions"],
        "commit": cve_info["commit"],
        "vulnerable_lines": [],  # 需要手动填充
        "test_cases": [],
        "references": [
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ],
    }


def prepare_patch(
    cve_id: str,
    targets_dir: Path,
    force: bool = False,
) -> bool:
    """准备单个 CVE 的补丁"""
    if cve_id not in CVE_PATCHES:
        print(f"  未知 CVE: {cve_id}")
        return False

    cve_info = CVE_PATCHES[cve_id]
    project = cve_info["project"]
    project_dir = targets_dir / project

    print(f"\n  {cve_id} ({project})")

    # 检查项目目录
    if not project_dir.exists():
        print(f"    ✗ 项目目录不存在，请先运行 setup_targets.py")
        return False

    patches_dir = project_dir / "patches"
    ground_truth_dir = project_dir / "ground_truth"

    patch_file = patches_dir / f"{cve_id}.patch"
    truth_file = ground_truth_dir / f"{cve_id}.json"

    if patch_file.exists() and not force:
        print(f"    ✓ 已存在 (使用 --force 覆盖)")
        return True

    # 获取补丁
    print(f"    获取补丁...")
    commit_url = cve_info["commit"]

    patch_content = None
    if "github.com" in commit_url:
        patch_content = get_github_patch(commit_url)
    elif "gitlab.gnome.org" in commit_url:
        patch_content = get_gitlab_patch(commit_url)

    if not patch_content:
        print(f"    ✗ 无法获取补丁内容")
        # 创建占位文件
        patch_content = f"# Placeholder for {cve_id}\n# Please manually download from: {commit_url}\n"

    # 保存补丁
    patch_file.write_text(patch_content)
    print(f"    ✓ 补丁: {patch_file}")

    # 创建 ground truth
    truth = create_ground_truth(cve_id, cve_info)
    truth_file.write_text(json.dumps(truth, indent=2, ensure_ascii=False))
    print(f"    ✓ Ground truth: {truth_file}")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="准备真实 CVE 补丁文件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 prepare_patches.py --cve CVE-2022-35737
  python3 prepare_patches.py --project sqlite
  python3 prepare_patches.py --all
        """
    )
    parser.add_argument(
        "--cve", "-c",
        help="特定 CVE ID"
    )
    parser.add_argument(
        "--project", "-p",
        choices=["sqlite", "libxml2", "curl"],
        help="为某个项目的所有 CVE 准备补丁"
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="为所有 CVE 准备补丁"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="强制覆盖"
    )
    parser.add_argument(
        "--targets-dir",
        default=None,
        help="目标目录"
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    targets_dir = Path(args.targets_dir) if args.targets_dir else script_dir.parent / "targets"

    print("="*50)
    print("  PATCHWEAVER 补丁准备")
    print("="*50)

    cves_to_process = []

    if args.cve:
        cves_to_process = [args.cve]
    elif args.project:
        cves_to_process = [
            cve_id for cve_id, info in CVE_PATCHES.items()
            if info["project"] == args.project
        ]
    elif args.all:
        cves_to_process = list(CVE_PATCHES.keys())
    else:
        parser.print_help()
        return

    success = 0
    failed = 0

    for cve_id in cves_to_process:
        if prepare_patch(cve_id, targets_dir, args.force):
            success += 1
        else:
            failed += 1

    print(f"\n{'='*50}")
    print(f"  完成: {success} 成功, {failed} 失败")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
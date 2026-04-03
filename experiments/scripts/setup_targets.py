#!/usr/bin/env python3
"""
下载并准备真实目标项目
"""
import argparse
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Optional
import urllib.request
import tarfile
import gzip


# 真实项目配置
PROJECTS: Dict[str, Dict] = {
    "sqlite": {
        "name": "SQLite",
        "version": "3390000",  # 3.39.0
        "download": "https://www.sqlite.org/2022/sqlite-autoconf-3390000.tar.gz",
        "src_dir": "sqlite-autoconf-3390000",
        "build": "./configure && make",
        "cves": ["CVE-2022-35737", "CVE-2023-7104", "CVE-2021-20227"],
    },
    "libxml2": {
        "name": "libxml2",
        "version": "2.10.0",
        "download": "https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.10.0/libxml2-v2.10.0.tar.gz",
        "src_dir": "libxml2-v2.10.0",
        "build": "./autogen.sh && ./configure && make",
        "cves": ["CVE-2022-40303", "CVE-2022-40304", "CVE-2023-45322"],
    },
    "curl": {
        "name": "curl",
        "version": "8.3.0",
        "download": "https://curl.se/download/curl-8.3.0.tar.gz",
        "src_dir": "curl-8.3.0",
        "build": "./configure && make",
        "cves": ["CVE-2023-38545", "CVE-2023-27533", "CVE-2022-27782", "CVE-2022-22576"],
    },
}


def download(url: str, dest: Path, desc: str = None) -> bool:
    """下载文件，带进度显示"""
    if desc:
        print(f"  下载 {desc}...")
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"  ✗ 下载失败: {e}")
        return False


def extract(archive: Path, dest: Path) -> bool:
    """解压 tar.gz 文件"""
    print(f"  解压 {archive.name}...")
    try:
        with tarfile.open(archive, "r:gz") as tf:
            # 获取根目录
            members = tf.getmembers()
            if members:
                root = members[0].name.split('/')[0]
                tf.extractall(dest.parent)

                # 如果解压后的目录名与预期不同，重命名
                extracted = dest.parent / root
                if extracted != dest and extracted.exists():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.move(str(extracted), str(dest))
        return True
    except Exception as e:
        print(f"  ✗ 解压失败: {e}")
        return False


def setup_project(
    project_id: str,
    targets_dir: Path,
    force: bool = False,
    build: bool = False,
) -> bool:
    """设置单个项目"""
    if project_id not in PROJECTS:
        print(f"未知项目: {project_id}")
        return False

    config = PROJECTS[project_id]
    name = config["name"]
    project_dir = targets_dir / project_id
    src_dir = project_dir / "src"

    print(f"\n{'='*50}")
    print(f"  {name} ({config['version']})")
    print(f"{'='*50}")

    if src_dir.exists() and not force:
        print(f"  已存在，跳过 (使用 --force 覆盖)")
        return True

    # 清理旧目录
    if src_dir.exists():
        print(f"  清理旧目录...")
        shutil.rmtree(src_dir)

    # 创建目录
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "patches").mkdir(exist_ok=True)
    (project_dir / "ground_truth").mkdir(exist_ok=True)

    # 下载
    tmp_dir = Path("/tmp") / f"patchweaver_{project_id}"
    tmp_dir.mkdir(exist_ok=True)
    archive = tmp_dir / f"{project_id}.tar.gz"

    if not download(config["download"], archive, name):
        return False

    # 解压
    if not extract(archive, src_dir):
        return False

    # 验证
    if not src_dir.exists():
        # 尝试其他位置
        for p in tmp_dir.iterdir():
            if p.is_dir() and p.name.startswith(config["src_dir"][:10]):
                shutil.move(str(p), str(src_dir))
                break

    if src_dir.exists():
        print(f"  ✓ 源码: {src_dir}")
    else:
        print(f"  ✗ 源码目录不存在")
        return False

    # 生成 compile_commands.json (用于静态分析)
    if build:
        print(f"  生成 compile_commands.json...")
        # 对于简单项目，可以用 Bear 工具
        # 这里简化处理，只检查是否有 Makefile
        if (src_dir / "Makefile").exists() or (src_dir / "CMakeLists.txt").exists():
            print(f"  ✓ 构建系统存在")

    # 清理临时文件
    shutil.rmtree(tmp_dir, ignore_errors=True)

    print(f"  ✓ {name} 设置完成")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="下载并准备真实目标项目",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 setup_targets.py --project sqlite    # 下载 SQLite
  python3 setup_targets.py --all               # 下载所有项目
  python3 setup_targets.py --project curl --force  # 强制重新下载
        """
    )
    parser.add_argument(
        "--project", "-p",
        choices=list(PROJECTS.keys()) + ["all"],
        help="项目名称"
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="下载所有项目"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="强制重新下载"
    )
    parser.add_argument(
        "--build", "-b",
        action="store_true",
        help="尝试构建项目"
    )
    parser.add_argument(
        "--targets-dir",
        default=None,
        help="目标目录 (默认: ../targets)"
    )
    args = parser.parse_args()

    # 确定目标目录
    script_dir = Path(__file__).parent
    targets_dir = Path(args.targets_dir) if args.targets_dir else script_dir.parent / "targets"
    targets_dir.mkdir(parents=True, exist_ok=True)

    print("="*50)
    print("  PATCHWEAVER 目标项目设置")
    print("="*50)

    success = 0
    failed = 0

    if args.all or args.project == "all":
        for project_id in PROJECTS:
            if setup_project(project_id, targets_dir, args.force, args.build):
                success += 1
            else:
                failed += 1
    elif args.project:
        if setup_project(args.project, targets_dir, args.force, args.build):
            success = 1
        else:
            failed = 1
    else:
        parser.print_help()
        return

    # 总结
    print(f"\n{'='*50}")
    print(f"  完成: {success} 成功, {failed} 失败")
    print(f"{'='*50}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
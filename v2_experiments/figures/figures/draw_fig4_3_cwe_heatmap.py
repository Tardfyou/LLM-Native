#!/usr/bin/env python3
"""Draw Figure 4-3: sample-level CWE heatmap for generation quality.

Values are derived from v2_experiments/tables/generate_results.csv. The thesis
figure is explicitly sample-level: for each CWE, there are two samples. A sample
is counted as successful for a metric if either backend run for that sample
satisfies that metric. Therefore values are in 50-point increments.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
DATA_PATH = ROOT / "v2_experiments" / "tables" / "generate_results.csv"

CWE_ORDER = [
    "CWE-119",
    "CWE-120",
    "CWE-125",
    "CWE-190",
    "CWE-20",
    "CWE-369",
    "CWE-415",
    "CWE-416",
    "CWE-476",
    "CWE-787",
]

VULN_LABELS = {
    "CWE-119": "buffer overflow",
    "CWE-120": "classic buffer overflow",
    "CWE-125": "out-of-bounds read",
    "CWE-190": "integer overflow",
    "CWE-20": "input validation error",
    "CWE-369": "divide by zero",
    "CWE-415": "double free",
    "CWE-416": "use after free",
    "CWE-476": "NULL pointer dereference",
    "CWE-787": "out-of-bounds write",
}

METRICS = ["VHR", "FSR", "PDS"]


def _configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.sans-serif": [
                "Noto Sans CJK SC",
                "Noto Sans CJK JP",
                "DejaVu Sans",
                "Arial",
            ],
            "axes.unicode_minus": False,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.03,
        }
    )


def _load_matrix() -> pd.DataFrame:
    df = pd.read_csv(DATA_PATH)
    rows = []
    for cwe in CWE_ORDER:
        group = df[df["cwe_id"] == cwe]
        if group.empty:
            raise ValueError(f"missing rows for {cwe}")
        # Sample-level aggregation: one row per sample_id, OR across CSA/CodeQL.
        sample_metrics = group.groupby("sample_id", sort=False)[
            ["vuln_hit", "fixed_silent", "pds"]
        ].max()
        n = float(len(sample_metrics))
        rows.append(
            {
                "CWE": cwe,
                "VHR": float(sample_metrics["vuln_hit"].sum()) / n * 100.0,
                "FSR": float(sample_metrics["fixed_silent"].sum()) / n * 100.0,
                "PDS": float(sample_metrics["pds"].sum()) / n * 100.0,
            }
        )
    matrix = pd.DataFrame(rows).set_index("CWE")[METRICS]
    return matrix


def draw() -> None:
    _configure_style()
    matrix = _load_matrix()

    # Warm, paper-friendly sequential palette: near-white -> sand -> terracotta.
    # It is deliberately less saturated than common orange heatmaps.
    cmap = LinearSegmentedColormap.from_list(
        "paper_warm",
        ["#FFF9F0", "#F2D8B5", "#D69058", "#A95943"],
        N=256,
    )

    fig, ax = plt.subplots(figsize=(3.55, 3.18), dpi=500)

    annot = matrix.map(lambda v: f"{int(v)}%" if float(v).is_integer() else f"{v:.1f}%")
    sns.heatmap(
        matrix,
        ax=ax,
        cmap=cmap,
        vmin=0,
        vmax=100,
        linewidths=0.85,
        linecolor="white",
        cbar=True,
        square=False,
        annot=annot,
        fmt="",
        annot_kws={"fontsize": 6.2, "color": "#2F3136"},
        cbar_kws={
            "ticks": [0, 25, 50, 75, 100],
            "fraction": 0.034,
            "pad": 0.025,
            "shrink": 0.86,
        },
    )

    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.set_xticklabels(ax.get_xticklabels(), fontsize=7.2, fontweight="bold", rotation=0)
    ax.set_yticklabels(ax.get_yticklabels(), fontsize=6.6, rotation=0)
    ax.tick_params(axis="both", length=0, colors="#2C3440")

    for spine in ax.spines.values():
        spine.set_visible(False)

    cbar = ax.collections[0].colorbar
    cbar.ax.tick_params(labelsize=6.8, length=2.2, width=0.55, colors="#2C3440")
    cbar.outline.set_linewidth(0.55)
    cbar.outline.set_edgecolor("#B7BEC8")
    cbar.set_label("Rate (%)", fontsize=7.0, labelpad=5, color="#2C3440")

    fig.subplots_adjust(left=0.145, right=0.90, bottom=0.085, top=0.99)

    for suffix in ("png", "pdf", "svg"):
        fig.savefig(OUT_DIR / f"fig4_3_cwe_heatmap.{suffix}", dpi=500)
    plt.close(fig)


if __name__ == "__main__":
    draw()

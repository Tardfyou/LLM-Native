#!/usr/bin/env python3
"""Draw Figure 4-5: backend resource profiles for generation/refinement.

The raw metrics mix different units, so bars are normalized within each row
while the labels keep the original measured means.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
GENERATE_PATH = ROOT / "v2_experiments" / "tables" / "generate_results.csv"
REFINE_PATH = ROOT / "v2_experiments" / "tables" / "refine_results.csv"

ANALYZERS = ("csa", "codeql")
ANALYZER_LABELS = {"csa": "CSA", "codeql": "CodeQL"}
COLORS = {"csa": "#3F6FA6", "codeql": "#C97937"}


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
            "savefig.pad_inches": 0.018,
            "axes.linewidth": 0.45,
            "xtick.major.width": 0.45,
        }
    )


def _fmt_plain(value: float) -> str:
    return f"{value:.1f}"


def _fmt_compile(value: float) -> str:
    return f"{value:.2f}"


def _fmt_seconds(value: float) -> str:
    return f"{value:.1f}s"


def _fmt_tokens(value: float) -> str:
    return f"{value / 1000.0:.1f}k"


Metric = tuple[str, str, Callable[[float], str]]

GENERATE_METRICS: list[Metric] = [
    ("Iterations", "iterations", _fmt_plain),
    ("Compile attempts", "compile_attempts", _fmt_compile),
    ("Total time", "total_seconds", _fmt_seconds),
    ("Pipeline tokens", "pipeline_total_tokens", _fmt_tokens),
    ("LLM calls", "llm_calls", _fmt_plain),
]

REFINE_METRICS: list[Metric] = [
    ("Rounds", "refinement_rounds", _fmt_plain),
    ("Iterations", "iterations", _fmt_plain),
    ("Total time", "total_seconds", _fmt_seconds),
    ("Pipeline tokens", "pipeline_total_tokens", _fmt_tokens),
    ("Added lines", "delta_nonempty_lines", _fmt_plain),
]


def _load_panel(path: Path, analyzer_col: str, metrics: list[Metric]) -> pd.DataFrame:
    df = pd.read_csv(path)
    rows = []
    for metric_name, col, formatter in metrics:
        values = {}
        labels = {}
        for analyzer in ANALYZERS:
            group = df[df[analyzer_col] == analyzer]
            if group.empty:
                raise ValueError(f"missing analyzer rows: {analyzer}")
            value = float(group[col].mean(skipna=True))
            values[analyzer] = value
            labels[analyzer] = formatter(value)
        max_value = max(values.values())
        if max_value <= 0:
            normalized = {analyzer: 0.0 for analyzer in ANALYZERS}
        else:
            normalized = {analyzer: values[analyzer] / max_value for analyzer in ANALYZERS}
        rows.append(
            {
                "metric": metric_name,
                "csa": values["csa"],
                "codeql": values["codeql"],
                "csa_norm": normalized["csa"],
                "codeql_norm": normalized["codeql"],
                "csa_label": labels["csa"],
                "codeql_label": labels["codeql"],
            }
        )
    return pd.DataFrame(rows)


def _draw_panel(ax: plt.Axes, data: pd.DataFrame, title: str) -> None:
    ink = "#2B3340"
    muted = "#5F6874"
    grid = "#E5EAF0"
    rule = "#C9D1DB"
    rowline = "#EEF2F6"

    n = len(data)
    centers = np.arange(n)[::-1]
    offsets = {"csa": 0.132, "codeql": -0.132}
    height = 0.118

    ax.set_xlim(0, 1.12)
    ax.set_ylim(-0.55, n - 0.45)
    ax.set_title(title, fontsize=7.0, fontweight="bold", color=ink, pad=3.8)
    ax.set_yticks(centers)
    ax.set_yticklabels(data["metric"], fontsize=6.05, color=ink)
    ax.set_xticks([0, 0.5, 1.0])
    ax.set_xticklabels(["0", "0.5", "1.0"], fontsize=5.65, color=ink)
    ax.grid(axis="x", color=grid, linewidth=0.38, zorder=0)
    ax.grid(axis="y", visible=False)

    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color("#9CA6B2")
    ax.spines["bottom"].set_linewidth(0.5)
    ax.tick_params(axis="y", length=0, pad=3.5)
    ax.tick_params(axis="x", length=2.0, width=0.45, pad=2)

    ax.axhline(n - 0.50, color=rule, linewidth=0.48, zorder=1)
    ax.axhline(-0.50, color=rule, linewidth=0.48, zorder=1)
    for sep in np.arange(0.5, n - 0.5, 1.0):
        ax.axhline(sep, color=rowline, linewidth=0.38, zorder=1)

    for row_idx, row in data.iterrows():
        center = centers[row_idx]
        for analyzer in ANALYZERS:
            y = center + offsets[analyzer]
            width = row[f"{analyzer}_norm"]
            ax.barh(
                y,
                width,
                height=height,
                color=COLORS[analyzer],
                edgecolor="white",
                linewidth=0.35,
                alpha=0.93,
                zorder=3,
            )
            label = row[f"{analyzer}_label"]
            x_text = width + 0.018
            if width >= 0.98:
                x_text = 1.017
            ax.text(
                x_text,
                y,
                label,
                ha="left",
                va="center",
                fontsize=5.35,
                color=ink if analyzer == "csa" else "#3C3A36",
                zorder=4,
            )

    ax.set_xlabel("Normalized cost within each metric", fontsize=5.65, color=muted, labelpad=3.4)


def draw() -> None:
    _configure_style()

    generate = _load_panel(GENERATE_PATH, "analyzer", GENERATE_METRICS)
    refine = _load_panel(REFINE_PATH, "analyzer", REFINE_METRICS)

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(6.25, 2.34),
        dpi=420,
        gridspec_kw={"wspace": 0.43},
    )

    _draw_panel(axes[0], generate, "(a) Generation")
    _draw_panel(axes[1], refine, "(b) Refinement")

    handles = [
        mpl.patches.Patch(facecolor=COLORS[analyzer], edgecolor="none", label=ANALYZER_LABELS[analyzer])
        for analyzer in ANALYZERS
    ]
    fig.legend(
        handles=handles,
        loc="upper center",
        bbox_to_anchor=(0.52, 1.012),
        ncol=2,
        frameon=False,
        fontsize=5.75,
        handlelength=1.1,
        handleheight=0.65,
        handletextpad=0.35,
        columnspacing=1.0,
        borderaxespad=0.0,
    )
    fig.subplots_adjust(left=0.104, right=0.995, bottom=0.210, top=0.790)

    for suffix in ("png", "pdf", "svg"):
        fig.savefig(OUT_DIR / f"fig4_5_resource_profile.{suffix}", dpi=420)
    plt.close(fig)


if __name__ == "__main__":
    draw()

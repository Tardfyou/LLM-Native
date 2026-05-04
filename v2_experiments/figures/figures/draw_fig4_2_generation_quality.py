#!/usr/bin/env python3
"""Draw Figure 4-2: generation-stage quality comparison.

The data is copied from Table 4-4 in the thesis draft and intentionally kept
unchanged.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np


OUT_DIR = Path(__file__).resolve().parent


METRICS = ["GSR", "VHR", "FSR", "PDS"]
SERIES = {
    "Overall": [100.0, 67.5, 60.0, 30.0],
    "CSA": [100.0, 75.0, 65.0, 40.0],
    "CodeQL": [100.0, 60.0, 55.0, 20.0],
}


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
            "savefig.pad_inches": 0.025,
        }
    )


def _fmt_percent(value: float) -> str:
    return f"{int(value)}%" if float(value).is_integer() else f"{value:.1f}%"


def draw() -> None:
    _configure_style()

    labels = list(SERIES.keys())
    values = np.array([SERIES[label] for label in labels], dtype=float)
    x = np.arange(len(METRICS))
    width = 0.18

    # CVPR-style muted, colorblind-safe palette. Keep Overall neutral and use
    # subdued blue / burnt orange for the two backends instead of bright
    # presentation colors.
    colors = {
        "Overall": "#9AA0A8",
        "CSA": "#3E6FA3",
        "CodeQL": "#C97937",
    }

    fig, ax = plt.subplots(figsize=(6.35, 2.28), dpi=500)

    offsets = (np.arange(len(labels)) - (len(labels) - 1) / 2) * width
    for idx, label in enumerate(labels):
        bars = ax.bar(
            x + offsets[idx],
            values[idx],
            width=width,
            label=label,
            color=colors[label],
            edgecolor="white",
            linewidth=0.55,
            zorder=3,
        )
        for bar, value in zip(bars, values[idx]):
            ax.annotate(
                _fmt_percent(value).replace("%", ""),
                xy=(bar.get_x() + bar.get_width() / 2, value),
                xytext=(0, 2.7),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=6.7,
                color="#2C3440",
                zorder=4,
            )

    ax.set_ylim(0, 108)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_yticklabels([f"{tick}" for tick in [0, 25, 50, 75, 100]], fontsize=7.2)
    ax.set_ylabel("Rate (%)", fontsize=7.4, labelpad=5, color="#2C3440")
    ax.set_xticks(x)
    ax.set_xticklabels(METRICS, fontsize=8.2, fontweight="bold")

    ax.grid(axis="y", color="#E1E5EC", linewidth=0.45, alpha=1.0, zorder=0)
    ax.grid(axis="x", visible=False)

    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color("#9AA3AF")
    ax.spines["bottom"].set_color("#9AA3AF")
    ax.spines["left"].set_linewidth(0.55)
    ax.spines["bottom"].set_linewidth(0.55)
    ax.tick_params(axis="both", colors="#2C3440", length=2.0, width=0.55)

    legend = ax.legend(
        ncol=3,
        loc="upper right",
        bbox_to_anchor=(0.995, 1.105),
        frameon=False,
        fontsize=7.4,
        handlelength=1.1,
        columnspacing=1.05,
        handletextpad=0.36,
        borderaxespad=0.0,
    )
    for text in legend.get_texts():
        text.set_color("#2C3440")

    ax.margins(x=0.035)
    fig.subplots_adjust(left=0.074, right=0.995, bottom=0.145, top=0.86)

    for suffix in ("png", "pdf", "svg"):
        fig.savefig(OUT_DIR / f"fig4_2_generation_quality.{suffix}", dpi=400)
    plt.close(fig)


if __name__ == "__main__":
    draw()

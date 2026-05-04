#!/usr/bin/env python3
"""Draw Figure 4-4: backend-specific refinement gain.

Values are derived from v2_experiments/tables/refine_results.csv. The figure
shows before/after rates for CSA and CodeQL on VHR, FSR, and PDS.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
DATA_PATH = ROOT / "v2_experiments" / "tables" / "refine_results.csv"

METRICS = [
    ("VHR", "baseline_vuln_hit", "refine_vuln_hit"),
    ("FSR", "baseline_fixed_silent", "refine_fixed_silent"),
    ("PDS", "baseline_pds", "refine_pds"),
]


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


def _load_summary() -> dict[str, dict[str, tuple[float, float]]]:
    df = pd.read_csv(DATA_PATH)
    summary: dict[str, dict[str, tuple[float, float]]] = {}
    for analyzer in ("csa", "codeql"):
        group = df[df["analyzer"] == analyzer]
        if group.empty:
            raise ValueError(f"missing analyzer rows: {analyzer}")
        summary[analyzer] = {}
        for metric, before_col, after_col in METRICS:
            before = float(group[before_col].mean()) * 100.0
            after = float(group[after_col].mean()) * 100.0
            summary[analyzer][metric] = (before, after)
    return summary


def _fmt(value: float) -> str:
    return f"{int(round(value))}"


def draw() -> None:
    _configure_style()
    summary = _load_summary()

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(5.15, 1.78),
        dpi=420,
        sharex=True,
        sharey=True,
        gridspec_kw={"wspace": 0.17},
    )

    metric_names = [item[0] for item in METRICS]
    y_positions = list(reversed(range(len(metric_names))))  # VHR at top
    before_color = "#8E97A3"
    after_colors = {"csa": "#3F6FA6", "codeql": "#C97937"}
    panel_labels = {"csa": "CSA", "codeql": "CodeQL"}
    ink = "#2B3340"
    muted = "#626B77"
    grid = "#E6EAF0"
    rule = "#CBD2DA"

    for ax, analyzer in zip(axes, ("csa", "codeql")):
        after_color = after_colors[analyzer]
        ax.set_xlim(0, 105)
        ax.set_ylim(-0.56, len(metric_names) - 0.34)
        ax.set_xticks([0, 50, 100])
        ax.set_xticks([25, 75], minor=True)
        ax.set_xticklabels([0, 50, 100], fontsize=6.0)
        ax.set_yticks(y_positions)
        ax.set_yticklabels(metric_names, fontsize=6.6, fontweight="bold")
        ax.grid(axis="x", which="major", color=grid, linewidth=0.38, zorder=0)
        ax.grid(axis="x", which="minor", color=grid, linewidth=0.28, alpha=0.72, zorder=0)
        ax.grid(axis="y", visible=False)
        ax.set_title(panel_labels[analyzer], fontsize=7.5, fontweight="bold", pad=3.0, color=ink)

        for spine in ("top", "right", "left"):
            ax.spines[spine].set_visible(False)
        ax.spines["bottom"].set_linewidth(0.5)
        ax.spines["bottom"].set_color("#98A2AE")
        ax.tick_params(axis="y", length=0, colors=ink, pad=5)
        ax.tick_params(axis="x", length=2.0, width=0.45, colors=ink, pad=2)
        ax.tick_params(axis="x", which="minor", length=1.5, width=0.35, colors="#AAB2BC")

        # CVPR-style light booktabs rules: enough structure for scanability
        # without turning the small figure into a dense spreadsheet.
        ax.axhline(len(metric_names) - 0.50, color=rule, linewidth=0.48, zorder=1)
        ax.axhline(-0.50, color=rule, linewidth=0.48, zorder=1)
        for sep in (0.5, 1.5):
            ax.axhline(sep, color="#EEF1F5", linewidth=0.40, zorder=1)

        for ypos, metric in zip(y_positions, metric_names):
            before, after = summary[analyzer][metric]
            delta = after - before
            line_color = after_color if delta >= 0 else "#A55B4C"
            ax.plot(
                [before, after],
                [ypos, ypos],
                color=line_color,
                linewidth=1.18,
                alpha=0.84,
                solid_capstyle="round",
                zorder=2,
            )
            ax.scatter(
                before,
                ypos,
                s=23,
                color=before_color,
                edgecolor="white",
                linewidth=0.55,
                zorder=3,
            )
            ax.scatter(
                after,
                ypos,
                s=27,
                color=after_color,
                edgecolor="white",
                linewidth=0.55,
                zorder=4,
            )

            mid = (before + after) / 2.0
            delta_label = f"{delta:+.0f}pp"
            ax.text(
                mid,
                ypos + 0.145,
                delta_label,
                ha="center",
                va="bottom",
                fontsize=5.7,
                color=ink if delta >= 0 else "#914E43",
                zorder=5,
            )

            # Endpoint labels are outside the markers to keep the quantitative
            # values readable even after Word scaling.
            before_dx = -2.15 if before >= after else -1.9
            after_dx = 2.0 if after >= before else 1.9
            ax.text(
                before + before_dx,
                ypos - 0.165,
                _fmt(before),
                ha="right",
                va="top",
                fontsize=5.5,
                color=muted,
            )
            ax.text(
                after + after_dx,
                ypos - 0.165,
                _fmt(after),
                ha="left",
                va="top",
                fontsize=5.5,
                color=ink,
            )

    axes[0].set_xlabel("Rate (%)", fontsize=6.2, labelpad=3.5, color=ink)
    axes[1].set_xlabel("Rate (%)", fontsize=6.2, labelpad=3.5, color=ink)

    handles = [
        mpl.lines.Line2D([0], [0], marker="o", color="none", markerfacecolor=before_color, markeredgecolor="white", markersize=4.0, label="Before"),
        mpl.lines.Line2D([0], [0], marker="o", color="none", markerfacecolor=after_colors["csa"], markeredgecolor="white", markersize=4.0, label="CSA after"),
        mpl.lines.Line2D([0], [0], marker="o", color="none", markerfacecolor=after_colors["codeql"], markeredgecolor="white", markersize=4.0, label="CodeQL after"),
    ]
    fig.legend(
        handles=handles,
        loc="upper center",
        bbox_to_anchor=(0.52, 1.012),
        ncol=3,
        frameon=False,
        fontsize=5.55,
        handletextpad=0.30,
        columnspacing=0.78,
        borderaxespad=0.0,
    )

    fig.subplots_adjust(left=0.074, right=0.995, bottom=0.205, top=0.805)

    for suffix in ("png", "pdf", "svg"):
        fig.savefig(OUT_DIR / f"fig4_4_backend_refine_gain.{suffix}", dpi=420)
    plt.close(fig)


if __name__ == "__main__":
    draw()

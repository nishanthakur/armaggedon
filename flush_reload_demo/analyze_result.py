#!/usr/bin/env python3
"""
analyze_results.py — Post-processing for Flush+Reload HPC Experiment
=====================================================================
Reads the CSV output from run_experiment.sh and produces:
  1. Summary statistics table (mean, std, median, IQR) per noise level
  2. Per-event comparison across noise levels
  3. Filtered vs. raw comparison (IQR-based outlier removal)
  4. Optional plots if matplotlib is available

Usage:
    python3 analyze_results.py --csv results/csv/all_results.csv
    python3 analyze_results.py --csvdir results/csv/
    python3 analyze_results.py --csv results/csv/all_results.csv --plot
"""

import argparse
import csv
import os
import sys
import math
from collections import defaultdict

# ── optional matplotlib ───────────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")           # non-interactive backend (no display needed)
    import matplotlib.pyplot as plt
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False

# ── stats helpers ─────────────────────────────────────────────────────────────

def mean(vals):
    return sum(vals) / len(vals) if vals else float("nan")

def variance(vals):
    if len(vals) < 2:
        return float("nan")
    m = mean(vals)
    return sum((x - m) ** 2 for x in vals) / (len(vals) - 1)

def stdev(vals):
    v = variance(vals)
    return math.sqrt(v) if not math.isnan(v) else float("nan")

def median(vals):
    if not vals:
        return float("nan")
    s = sorted(vals)
    n = len(s)
    mid = n // 2
    return (s[mid - 1] + s[mid]) / 2 if n % 2 == 0 else s[mid]

def percentile(vals, p):
    """Simple linear interpolation percentile."""
    if not vals:
        return float("nan")
    s = sorted(vals)
    idx = (p / 100) * (len(s) - 1)
    lo = int(idx)
    hi = lo + 1
    if hi >= len(s):
        return s[lo]
    return s[lo] + (idx - lo) * (s[hi] - s[lo])

def iqr_filter(vals):
    """Remove values outside [Q1 - 1.5*IQR, Q3 + 1.5*IQR]."""
    if len(vals) < 4:
        return vals
    q1 = percentile(vals, 25)
    q3 = percentile(vals, 75)
    iqr = q3 - q1
    lo = q1 - 1.5 * iqr
    hi = q3 + 1.5 * iqr
    return [v for v in vals if lo <= v <= hi]

# ── CSV loading ───────────────────────────────────────────────────────────────

def load_csv(path):
    """
    Returns:
        headers : list of column names (excluding noise_level, rep)
        data    : dict { noise_level (int) -> { event -> [values] } }
    """
    data = defaultdict(lambda: defaultdict(list))
    headers = []

    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            print(f"[ERROR] Empty or invalid CSV: {path}")
            sys.exit(1)
        headers = [h for h in reader.fieldnames if h not in ("noise_level", "rep")]
        for row in reader:
            try:
                noise = int(row["noise_level"])
            except (KeyError, ValueError):
                continue
            for event in headers:
                raw = row.get(event, "NA").strip()
                if raw not in ("NA", "", "<not counted>"):
                    try:
                        data[noise][event].append(float(raw))
                    except ValueError:
                        pass

    return headers, dict(data)


def load_csvdir(dirpath):
    """Load and merge all CSV files in a directory."""
    all_headers = []
    merged = defaultdict(lambda: defaultdict(list))
    for fname in sorted(os.listdir(dirpath)):
        if not fname.endswith(".csv"):
            continue
        path = os.path.join(dirpath, fname)
        headers, data = load_csv(path)
        if not all_headers:
            all_headers = headers
        for noise, events in data.items():
            for evt, vals in events.items():
                merged[noise][evt].extend(vals)
    return all_headers, dict(merged)

# ── reporting ─────────────────────────────────────────────────────────────────

def fmt(v, width=12):
    if math.isnan(v):
        return f"{'N/A':>{width}}"
    if v >= 1e9:
        return f"{v/1e9:>{width}.3f}G"
    if v >= 1e6:
        return f"{v/1e6:>{width}.3f}M"
    if v >= 1e3:
        return f"{v/1e3:>{width}.3f}K"
    return f"{v:>{width}.2f}"

def print_summary(headers, data):
    noise_levels = sorted(data.keys())
    print()
    print("=" * 80)
    print("  SUMMARY STATISTICS  (per noise level, IQR-filtered)")
    print("=" * 80)

    for event in headers:
        print(f"\n  Event: {event}")
        print(f"  {'Noise':>8}  {'N':>6}  {'Mean':>12}  {'Std':>12}  "
              f"{'Median':>12}  {'P5':>12}  {'P95':>12}  {'Filtered N':>12}")
        print("  " + "-" * 90)
        for nl in noise_levels:
            label = "baseline" if nl == 1 else f"noise={nl:>3}"
            vals_raw = data[nl].get(event, [])
            vals_filt = iqr_filter(vals_raw)
            if not vals_raw:
                print(f"  {label:>8}  {'N/A':>6}")
                continue
            print(f"  {label:>8}  {len(vals_raw):>6}  "
                  f"{fmt(mean(vals_filt))}  "
                  f"{fmt(stdev(vals_filt))}  "
                  f"{fmt(median(vals_filt))}  "
                  f"{fmt(percentile(vals_filt, 5))}  "
                  f"{fmt(percentile(vals_filt, 95))}  "
                  f"{len(vals_filt):>12}")

def print_noise_impact(headers, data):
    """Show % change from baseline for each event at each noise level."""
    noise_levels = sorted(data.keys())
    baseline_nl = noise_levels[0]      # lowest level = baseline

    print()
    print("=" * 80)
    print("  NOISE IMPACT  (% change vs baseline)")
    print("=" * 80)
    print(f"\n  {'Event':<30}  " +
          "  ".join(f"noise={nl:>3}" for nl in noise_levels if nl != baseline_nl))
    print("  " + "-" * 70)

    for event in headers:
        base_vals = iqr_filter(data[baseline_nl].get(event, []))
        base_mean = mean(base_vals)
        if math.isnan(base_mean) or base_mean == 0:
            continue
        row = f"  {event:<30}"
        for nl in noise_levels:
            if nl == baseline_nl:
                continue
            vals = iqr_filter(data[nl].get(event, []))
            m = mean(vals)
            if math.isnan(m):
                row += f"  {'N/A':>12}"
            else:
                pct = (m - base_mean) / base_mean * 100
                sign = "+" if pct >= 0 else ""
                row += f"  {sign}{pct:>10.1f}%"
        print(row)

def write_filtered_csv(headers, data, outpath):
    """Write a filtered CSV (IQR outliers removed) for use in R/Python."""
    with open(outpath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["noise_level", "rep"] + headers)
        for nl in sorted(data.keys()):
            # Per-event filtered values (may have different lengths after filtering)
            # Strategy: filter per event independently, report per-rep rows where
            # all events survived filtering.
            events_filtered = {}
            for evt in headers:
                raw = data[nl].get(evt, [])
                events_filtered[evt] = set(iqr_filter(raw))  # use as set for quick lookup

            raw_vals = {evt: data[nl].get(evt, []) for evt in headers}
            n_reps = max(len(v) for v in raw_vals.values()) if raw_vals else 0
            kept = 0
            for i in range(n_reps):
                row_vals = []
                skip = False
                for evt in headers:
                    vals = raw_vals[evt]
                    v = vals[i] if i < len(vals) else None
                    if v is None:
                        skip = True
                        break
                    row_vals.append(v)
                if not skip:
                    writer.writerow([nl, i + 1] + row_vals)
                    kept += 1
    print(f"\n  Filtered CSV written: {outpath}  ({kept} rows)")

# ── plotting ──────────────────────────────────────────────────────────────────

def make_plots(headers, data, outdir):
    if not HAS_PLOT:
        print("\n  [plot] matplotlib not available — skipping plots.")
        print("         Install: pip3 install matplotlib --break-system-packages")
        return

    noise_levels = sorted(data.keys())
    labels = ["baseline" if nl == 1 else f"noise={nl}" for nl in noise_levels]
    os.makedirs(outdir, exist_ok=True)

    for event in headers:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.suptitle(f"Event: {event}", fontsize=13, fontweight="bold")

        # Left: box plot
        ax = axes[0]
        box_data = [iqr_filter(data[nl].get(event, [])) for nl in noise_levels]
        ax.boxplot(box_data, tick_labels=labels, showfliers=False)
        ax.set_title("Distribution (IQR filtered, no outliers shown)")
        ax.set_xlabel("Noise level")
        ax.set_ylabel("Count")
        ax.tick_params(axis="x", rotation=30)

        # Right: mean ± std bar chart
        ax2 = axes[1]
        means  = [mean(iqr_filter(data[nl].get(event, []))) for nl in noise_levels]
        stdevs = [stdev(iqr_filter(data[nl].get(event, []))) for nl in noise_levels]
        x = range(len(noise_levels))
        bars = ax2.bar(x, means, yerr=stdevs, capsize=5,
                       color=["steelblue", "orange", "green", "red"][:len(noise_levels)],
                       alpha=0.75)
        ax2.set_xticks(list(x))
        ax2.set_xticklabels(labels, rotation=30)
        ax2.set_title("Mean ± Std (IQR filtered)")
        ax2.set_ylabel("Count")
        for bar, m in zip(bars, means):
            if not math.isnan(m):
                ax2.text(bar.get_x() + bar.get_width() / 2,
                         bar.get_height() * 1.02,
                         fmt(m, 6).strip(),
                         ha="center", va="bottom", fontsize=8)

        plt.tight_layout()
        safe_name = event.replace("/", "_").replace(":", "_").replace("-", "_")
        out = os.path.join(outdir, f"plot_{safe_name}.png")
        plt.savefig(out, dpi=120)
        plt.close()
        print(f"  Saved plot: {out}")

    # Combined cache-miss rate across noise levels
    if "cache-misses" in headers and "cache-references" in headers:
        fig, ax = plt.subplots(figsize=(8, 5))
        rates = []
        for nl in noise_levels:
            misses = iqr_filter(data[nl].get("cache-misses", []))
            refs   = iqr_filter(data[nl].get("cache-references", []))
            n = min(len(misses), len(refs))
            if n > 0:
                rate = mean([misses[i] / refs[i] * 100
                             for i in range(n) if refs[i] > 0])
            else:
                rate = float("nan")
            rates.append(rate)
        ax.plot(labels, rates, marker="o", linewidth=2, color="crimson")
        ax.set_title("Cache Miss Rate vs Noise Level")
        ax.set_ylabel("Miss rate (%)")
        ax.set_xlabel("Noise level")
        ax.grid(True, alpha=0.3)
        out = os.path.join(outdir, "plot_cache_miss_rate.png")
        plt.savefig(out, dpi=120)
        plt.close()
        print(f"  Saved plot: {out}")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyze Flush+Reload HPC experiment results")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--csv",    help="Path to all_results.csv")
    grp.add_argument("--csvdir", help="Directory containing per-level CSVs")
    parser.add_argument("--plot",   action="store_true", help="Generate PNG plots")
    parser.add_argument("--outdir", default=None,
                        help="Output dir for filtered CSV and plots (default: same as CSV)")
    args = parser.parse_args()

    if args.csv:
        print(f"Loading: {args.csv}")
        headers, data = load_csv(args.csv)
        base_dir = os.path.dirname(args.csv)
    else:
        print(f"Loading CSVs from: {args.csvdir}")
        headers, data = load_csvdir(args.csvdir)
        base_dir = args.csvdir

    if not data:
        print("[ERROR] No data loaded — check CSV paths.")
        sys.exit(1)

    outdir = args.outdir or base_dir

    print(f"\nLoaded {sum(len(list(evts.values())[0]) for evts in data.values() if evts)} "
          f"total samples across {len(data)} noise levels")
    print(f"Events: {', '.join(headers)}")
    print(f"Noise levels: {sorted(data.keys())}")

    print_summary(headers, data)
    print_noise_impact(headers, data)

    filtered_path = os.path.join(outdir, "all_results_filtered.csv")
    write_filtered_csv(headers, data, filtered_path)

    if args.plot:
        plot_dir = os.path.join(outdir, "plots")
        print(f"\nGenerating plots → {plot_dir}")
        make_plots(headers, data, plot_dir)

    print("\nDone.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

"""Compare two JSON outputs from Seastar perf-tests benchmarks.

Usage:
    scripts/perftests-compare.py baseline.json candidate.json [options]

The script loads two benchmark JSON files (produced via --json-output),
matches tests by name, and reports per-metric deltas. Regressions and
improvements are highlighted based on a configurable threshold.
"""

import argparse
import json
import sys


# Metrics where lower is better (time, resource usage).
LOWER_IS_BETTER = {
    "median",
    "mad",
    "min",
    "max",
    "allocs",
    "tasks",
    "inst",
    "cycles",
    "overhead",
}

# Default columns shown in the comparison table.
DEFAULT_COLUMNS = ["median", "allocs", "tasks", "inst", "cycles"]

# ANSI color codes.
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _color(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{code}{text}{_RESET}"


def _plain(s: str) -> str:
    for code in (_RED, _GREEN, _YELLOW, _BOLD, _RESET):
        s = s.replace(code, "")
    return s


def _fmt_value(v: float) -> str:
    if abs(v) < 0.005:
        return "0.00"
    return f"{v:.2f}"


def _regression(pct: float, metric: str) -> bool:
    lower_better = metric in LOWER_IS_BETTER
    return (pct > 0 and lower_better) or (pct < 0 and not lower_better)


def _colorize(text: str, pct: float, metric: str, use_color: bool) -> str:
    if abs(pct) < 0.5:
        return text
    if _regression(pct, metric):
        return _color(text, _RED, use_color)
    return _color(text, _GREEN, use_color)


def load_results(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    if "results" in data:
        return data["results"]
    return data


# A cell holds separately-aligned parts for a metric column.
# For default mode: (delta_str, pct_str)
# For show_values:  (base_str, cand_str, delta_str, pct_str)
# None means the test is missing from candidate entirely.
CellParts = tuple


def compare(
    baseline: dict,
    candidate: dict,
    columns: list[str],
    threshold: float,
    use_color: bool,
    show_values: bool = False,
) -> tuple[list[str], list[list[CellParts]], list[str], dict]:
    """Return (test_names, cell_grid, missing_in_candidate, summary).

    cell_grid[row][col] is a CellParts tuple for independent alignment.
    """
    all_tests = sorted(set(baseline) | set(candidate))
    test_names: list[str] = []
    cell_grid: list[list[CellParts]] = []
    missing_in_candidate: list[str] = []
    regressions = 0
    improvements = 0

    for test in all_tests:
        if test not in candidate:
            missing_in_candidate.append(test)
            continue

        cand_metrics = candidate[test]
        in_baseline = test in baseline
        base_metrics = baseline[test] if in_baseline else {}
        test_names.append(test)
        row_cells: list[CellParts] = []

        for col in columns:
            bv = base_metrics.get(col)
            cv = cand_metrics.get(col)
            if cv is None:
                if show_values:
                    row_cells.append(("-", "-", "-", ""))
                else:
                    row_cells.append(("-", ""))
                continue
            if bv is None:
                val = _fmt_value(cv)
                tag = _color("(new)", _YELLOW, use_color)
                if show_values:
                    row_cells.append(("-", val, tag, ""))
                else:
                    row_cells.append((val, tag))
                continue

            delta = cv - bv
            pct = (
                ((cv - bv) / bv * 100) if bv != 0 else (0 if cv == 0 else float("inf"))
            )

            d_sign = "+" if delta >= 0 else ""
            d_str = _colorize(f"{d_sign}{_fmt_value(delta)}", pct, col, use_color)
            p_sign = "+" if pct >= 0 else ""
            p_str = _colorize(f"({p_sign}{pct:.1f}%)", pct, col, use_color)

            if show_values:
                row_cells.append((_fmt_value(bv), _fmt_value(cv), d_str, p_str))
            else:
                row_cells.append((d_str, p_str))

            if abs(pct) >= threshold:
                if _regression(pct, col):
                    regressions += 1
                else:
                    improvements += 1

        cell_grid.append(row_cells)

    summary = {
        "total_tests": len(all_tests),
        "compared": len(test_names),
        "regressions": regressions,
        "improvements": improvements,
        "missing_in_candidate": missing_in_candidate,
    }
    return test_names, cell_grid, missing_in_candidate, summary


def print_table(
    test_names: list[str],
    cell_grid: list[list[CellParts]],
    columns: list[str],
    use_color: bool,
    show_values: bool = False,
) -> None:
    n_parts = 4 if show_values else 2
    n_cols = len(columns)

    # Compute max width per sub-part per metric column.
    part_widths = [[0] * n_parts for _ in range(n_cols)]
    for row in cell_grid:
        for ci, cell in enumerate(row):
            for pi, part in enumerate(cell):
                part_widths[ci][pi] = max(part_widths[ci][pi], len(_plain(part)))

    # Header sub-parts.
    if show_values:
        hdrs = [(f"{c}(base)", f"{c}(cand)", f"{c}(d)", "") for c in columns]
    else:
        hdrs = [(f"{c}(d)", "") for c in columns]
    for ci, hdr in enumerate(hdrs):
        for pi, h in enumerate(hdr):
            part_widths[ci][pi] = max(part_widths[ci][pi], len(h))

    # Test name width.
    name_w = max((len(n) for n in test_names), default=4)
    name_w = max(name_w, 4)  # "Test"

    def fmt_cell(cell: CellParts, ci: int) -> str:
        parts = []
        for pi, part in enumerate(cell):
            w = part_widths[ci][pi]
            if w == 0:
                continue
            pad = w - len(_plain(part))
            parts.append(" " * pad + part)
        return " ".join(parts)

    def fmt_hdr(hdr: CellParts, ci: int) -> str:
        parts = []
        for pi, h in enumerate(hdr):
            w = part_widths[ci][pi]
            if w == 0:
                continue
            pad = w - len(h)
            parts.append(" " * pad + _color(h, _BOLD, use_color))
        return " ".join(parts)

    # Print header.
    hdr_line = _color("Test", _BOLD, use_color) + " " * (name_w - 4)
    for ci, hdr in enumerate(hdrs):
        hdr_line += "   " + fmt_hdr(hdr, ci)
    print(hdr_line)

    # Separator.
    total_w = name_w
    for ci in range(n_cols):
        col_w = sum(
            part_widths[ci][pi] for pi in range(n_parts) if part_widths[ci][pi] > 0
        )
        col_w += (
            sum(1 for pi in range(n_parts) if part_widths[ci][pi] > 0) - 1
        )  # spaces between parts
        total_w += 3 + col_w
    print("-" * total_w)

    # Print rows.
    for ri, name in enumerate(test_names):
        line = name + " " * (name_w - len(name))
        for ci, cell in enumerate(cell_grid[ri]):
            line += "   " + fmt_cell(cell, ci)
        print(line)


def print_markdown(
    test_names: list[str],
    cell_grid: list[list[CellParts]],
    columns: list[str],
    show_values: bool = False,
) -> None:
    n_parts = 4 if show_values else 2

    def cell_text(cell: CellParts) -> str:
        return " ".join(p for p in cell if p)

    header = ["Test"]
    for col in columns:
        if show_values:
            header.extend([f"{col}(base)", f"{col}(cand)"])
        header.append(col)

    # Flatten cells to single strings for markdown.
    flat_rows = []
    for ri, name in enumerate(test_names):
        row = [name]
        for ci, cell in enumerate(cell_grid[ri]):
            if show_values:
                row.extend(
                    [
                        _plain(cell[0]),
                        _plain(cell[1]),
                        _plain(cell[2]) + " " + _plain(cell[3]),
                    ]
                )
            else:
                row.append(_plain(cell[0]) + " " + _plain(cell[1]))
        flat_rows.append(row)

    widths = [len(h) for h in header]
    for row in flat_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells: list[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            pad = widths[i] - len(cell)
            parts.append(cell + " " * pad)
        return "| " + " | ".join(parts) + " |"

    print(fmt_row(header))
    print("|" + "|".join("-" * (w + 2) for w in widths) + "|")
    for row in flat_rows:
        print(fmt_row(row))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare two Seastar perf-tests JSON outputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s baseline.json candidate.json
  %(prog)s baseline.json candidate.json --columns median,allocs,inst
  %(prog)s baseline.json candidate.json --threshold 5 --markdown
""",
    )
    parser.add_argument("baseline", help="Path to baseline JSON results")
    parser.add_argument("candidate", help="Path to candidate JSON results")
    parser.add_argument(
        "-c",
        "--columns",
        default=",".join(DEFAULT_COLUMNS),
        help=f"Comma-separated list of metrics to compare (default: {','.join(DEFAULT_COLUMNS)})",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=1.0,
        help="Minimum absolute percent change to count as regression/improvement (default: 1.0)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "--markdown", action="store_true", help="Output a Markdown table"
    )
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="Show baseline and candidate values alongside the delta",
    )
    parser.add_argument(
        "--only-regressions",
        action="store_true",
        help="Only show tests with at least one regression",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Write comparison results as JSON to FILE (use - for stdout)",
    )
    args = parser.parse_args()

    columns = [c.strip() for c in args.columns.split(",")]
    use_color = not args.no_color and sys.stdout.isatty() and not args.markdown

    baseline = load_results(args.baseline)
    candidate = load_results(args.candidate)

    test_names, cell_grid, missing, summary = compare(
        baseline, candidate, columns, args.threshold, use_color, args.show_values
    )

    if args.only_regressions:
        filtered_names = []
        filtered_grid = []
        for ri, test in enumerate(test_names):
            if test in baseline and test in candidate:
                has_regression = False
                for col in columns:
                    bv = baseline[test].get(col, 0)
                    cv = candidate[test].get(col, 0)
                    if bv == 0:
                        continue
                    pct = (cv - bv) / bv * 100
                    if abs(pct) >= args.threshold and _regression(pct, col):
                        has_regression = True
                        break
                if not has_regression:
                    continue
            filtered_names.append(test)
            filtered_grid.append(cell_grid[ri])
        test_names, cell_grid = filtered_names, filtered_grid

    # Print table.
    if test_names:
        if args.markdown:
            print_markdown(test_names, cell_grid, columns, args.show_values)
        else:
            print_table(test_names, cell_grid, columns, use_color, args.show_values)
    print()

    # Print summary.
    if summary["missing_in_candidate"]:
        print(f"Tests only in baseline ({len(summary['missing_in_candidate'])}):")
        for t in summary["missing_in_candidate"]:
            print(f"  - {t}")

    reg_str = (
        _color(str(summary["regressions"]), _RED, use_color)
        if summary["regressions"]
        else "0"
    )
    imp_str = (
        _color(str(summary["improvements"]), _GREEN, use_color)
        if summary["improvements"]
        else "0"
    )
    print(
        f"\nCompared {summary['compared']} tests: "
        f"{reg_str} regressions, {imp_str} improvements "
        f"(threshold: {args.threshold}%)"
    )

    # Optional JSON output.
    if args.json:
        json_data = {"summary": summary, "comparisons": {}}
        for test in sorted(set(baseline) & set(candidate)):
            entry = {}
            for col in columns:
                bv = baseline[test].get(col)
                cv = candidate[test].get(col)
                if bv is None or cv is None:
                    continue
                pct = ((cv - bv) / bv * 100) if bv != 0 else 0
                entry[col] = {
                    "baseline": bv,
                    "candidate": cv,
                    "change_pct": round(pct, 4),
                }
            json_data["comparisons"][test] = entry

        json_str = json.dumps(json_data, indent=2)
        if args.json == "-":
            print(json_str)
        else:
            with open(args.json, "w") as f:
                f.write(json_str + "\n")
            print(f"JSON comparison written to {args.json}")

    if summary["regressions"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

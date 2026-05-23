#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path('.tmp-smoke/bench-matrix')
THROUGHPUT_DELTA_THRESHOLD_PCT = 5.0
LATENCY_DELTA_THRESHOLD_PCT = 10.0
AVG_LATENCY_NOISE_FLOOR_MS = 0.25
P95_LATENCY_NOISE_FLOOR_MS = 0.5


class GateFailure(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Compare benchmark summary.json against baseline.json and fail on regressions.'
    )
    parser.add_argument(
        '--summary',
        default=str(DEFAULT_ROOT / 'summary.json'),
        help='Path to current benchmark summary.json',
    )
    parser.add_argument(
        '--baseline',
        default=str(DEFAULT_ROOT / 'baseline.json'),
        help='Path to baseline benchmark summary.json',
    )
    parser.add_argument(
        '--report-json',
        default=None,
        help='Optional path to write machine-readable gate report JSON',
    )
    parser.add_argument(
        '--max-regressions',
        type=int,
        default=0,
        help='Maximum allowed regression classifications before failing (default: 0).',
    )
    parser.add_argument(
        '--fail-on-new',
        action='store_true',
        help='Treat scenarios missing in baseline as gate failures.',
    )
    parser.add_argument(
        '--throughput-regression-pct',
        type=float,
        default=THROUGHPUT_DELTA_THRESHOLD_PCT,
        help='Throughput drop percent that classifies a scenario as regression (default: 5.0).',
    )
    parser.add_argument(
        '--avg-latency-regression-pct',
        type=float,
        default=LATENCY_DELTA_THRESHOLD_PCT,
        help='Average latency increase percent that classifies a scenario as regression (default: 10.0).',
    )
    parser.add_argument(
        '--p95-latency-regression-pct',
        type=float,
        default=LATENCY_DELTA_THRESHOLD_PCT,
        help='P95 latency increase percent that classifies a scenario as regression (default: 10.0).',
    )
    parser.add_argument(
        '--avg-latency-floor-ms',
        type=float,
        default=AVG_LATENCY_NOISE_FLOOR_MS,
        help='Minimum absolute avg latency delta in ms required before a relative delta can classify (default: 0.25).',
    )
    parser.add_argument(
        '--p95-latency-floor-ms',
        type=float,
        default=P95_LATENCY_NOISE_FLOOR_MS,
        help='Minimum absolute p95 latency delta in ms required before a relative delta can classify (default: 0.5).',
    )
    parser.add_argument(
        '--throughput-improvement-pct',
        type=float,
        default=THROUGHPUT_DELTA_THRESHOLD_PCT,
        help='Throughput gain percent that classifies a scenario as improvement (default: 5.0).',
    )
    parser.add_argument(
        '--latency-improvement-pct',
        type=float,
        default=LATENCY_DELTA_THRESHOLD_PCT,
        help='Latency decrease percent that classifies a scenario as improvement (default: 10.0).',
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise GateFailure(f'missing benchmark artifact: {path}') from exc
    except json.JSONDecodeError as exc:
        raise GateFailure(f'invalid benchmark json {path}: {exc}') from exc


def pct_delta(current: float, baseline: float) -> float | None:
    if abs(baseline) < sys.float_info.epsilon:
        return None
    return ((current - baseline) / baseline) * 100.0


def fmt_pct(value: float | None) -> str:
    if value is None:
        return '—'
    sign = '+' if value > 0 else ''
    return f'{sign}{value:.2f}%'


def normalized_aggregation(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get('aggregation')
    if not isinstance(raw, dict):
        return {'method': 'single-run', 'runs': 1}
    method = str(raw.get('method') or 'single-run')
    try:
        runs = int(raw.get('runs') or 1)
    except (TypeError, ValueError):
        runs = 1
    return {'method': method, 'runs': max(1, runs)}


def scenario_rank(item: dict[str, Any]) -> tuple[int, float]:
    severity = {'regression': 0, 'new': 1, 'improvement': 2, 'unchanged': 3}.get(
        item.get('classification', 'unchanged'),
        4,
    )
    score = sum(
        abs(float(item.get(key) or 0.0))
        for key in ('throughput_delta_pct', 'avg_delta_pct', 'p95_delta_pct')
    )
    return (severity, -score)


def latency_regressed(
    current_ms: float,
    baseline_ms: float,
    delta_pct: float | None,
    pct_threshold: float,
    floor_ms: float,
) -> bool:
    return (
        delta_pct is not None
        and delta_pct >= pct_threshold
        and (current_ms - baseline_ms) >= floor_ms
    )


def latency_improved(
    current_ms: float,
    baseline_ms: float,
    delta_pct: float | None,
    pct_threshold: float,
    floor_ms: float,
) -> bool:
    return (
        delta_pct is not None
        and delta_pct <= -pct_threshold
        and (baseline_ms - current_ms) >= floor_ms
    )


def aggregated_metric(scenario: dict[str, Any], metric: str) -> float:
    if metric == 'throughput_rps':
        return float(scenario.get('throughput_rps') or 0.0)
    if metric == 'avg_ms':
        return float(scenario.get('latency_ms', {}).get('avg') or 0.0)
    if metric == 'p95_ms':
        return float(scenario.get('latency_ms', {}).get('p95') or 0.0)
    raise KeyError(f'unsupported benchmark metric: {metric}')


def sample_metric_values(scenario: dict[str, Any], metric: str) -> list[float]:
    aggregation = scenario.get('aggregation')
    sample_runs = aggregation.get('sample_runs') if isinstance(aggregation, dict) else None
    values: list[float] = []
    if isinstance(sample_runs, list):
        for run in sample_runs:
            if not isinstance(run, dict):
                continue
            raw = run.get(metric)
            if raw is None:
                continue
            try:
                values.append(float(raw))
            except (TypeError, ValueError):
                continue
    if values:
        return values
    return [aggregated_metric(scenario, metric)]


def volatility_band(scenario: dict[str, Any], metric: str) -> dict[str, Any]:
    center = aggregated_metric(scenario, metric)
    samples = sample_metric_values(scenario, metric)
    low = min(samples)
    high = max(samples)
    spread_abs = max(abs(center - low), abs(high - center))
    spread_pct = None
    if abs(center) >= sys.float_info.epsilon:
        spread_pct = (spread_abs / abs(center)) * 100.0
    return {
        'metric': metric,
        'sample_count': len(samples),
        'low': low,
        'high': high,
        'spread_abs': spread_abs,
        'spread_pct': spread_pct,
    }


def throughput_band_decisive(
    current_band: dict[str, Any],
    baseline_band: dict[str, Any],
    *,
    direction: str,
) -> bool:
    if direction == 'regression':
        return float(current_band['high']) < float(baseline_band['low'])
    if direction == 'improvement':
        return float(current_band['low']) > float(baseline_band['high'])
    raise KeyError(f'unsupported throughput direction: {direction}')


def latency_band_decisive(
    current_band: dict[str, Any],
    baseline_band: dict[str, Any],
    *,
    direction: str,
) -> bool:
    if direction == 'regression':
        return float(current_band['low']) > float(baseline_band['high'])
    if direction == 'improvement':
        return float(current_band['high']) < float(baseline_band['low'])
    raise KeyError(f'unsupported latency direction: {direction}')


def compare_scenario(
    current: dict[str, Any],
    baseline: dict[str, Any] | None,
    args: argparse.Namespace,
) -> dict[str, Any]:
    if baseline is None:
        return {
            'scenario': current['scenario'],
            'classification': 'new',
            'throughput_rps_current': float(current.get('throughput_rps') or 0.0),
            'throughput_rps_baseline': None,
            'throughput_delta_pct': None,
            'avg_ms_current': float(current.get('latency_ms', {}).get('avg') or 0.0),
            'avg_ms_baseline': None,
            'avg_delta_pct': None,
            'p95_ms_current': float(current.get('latency_ms', {}).get('p95') or 0.0),
            'p95_ms_baseline': None,
            'p95_delta_pct': None,
            'raw_regression_metrics': [],
            'raw_improvement_metrics': [],
            'suppressed_regression_metrics': [],
            'suppressed_improvement_metrics': [],
            'volatility_bands': {
                'throughput_rps': {
                    'current': volatility_band(current, 'throughput_rps'),
                    'baseline': None,
                },
                'avg_ms': {
                    'current': volatility_band(current, 'avg_ms'),
                    'baseline': None,
                },
                'p95_ms': {
                    'current': volatility_band(current, 'p95_ms'),
                    'baseline': None,
                },
            },
            'ok': bool(current.get('ok', False)),
        }

    throughput_delta_pct = pct_delta(
        float(current.get('throughput_rps') or 0.0),
        float(baseline.get('throughput_rps') or 0.0),
    )
    avg_delta_pct = pct_delta(
        float(current.get('latency_ms', {}).get('avg') or 0.0),
        float(baseline.get('latency_ms', {}).get('avg') or 0.0),
    )
    p95_delta_pct = pct_delta(
        float(current.get('latency_ms', {}).get('p95') or 0.0),
        float(baseline.get('latency_ms', {}).get('p95') or 0.0),
    )
    current_avg_ms = float(current.get('latency_ms', {}).get('avg') or 0.0)
    baseline_avg_ms = float(baseline.get('latency_ms', {}).get('avg') or 0.0)
    current_p95_ms = float(current.get('latency_ms', {}).get('p95') or 0.0)
    baseline_p95_ms = float(baseline.get('latency_ms', {}).get('p95') or 0.0)
    throughput_current_band = volatility_band(current, 'throughput_rps')
    throughput_baseline_band = volatility_band(baseline, 'throughput_rps')
    avg_current_band = volatility_band(current, 'avg_ms')
    avg_baseline_band = volatility_band(baseline, 'avg_ms')
    p95_current_band = volatility_band(current, 'p95_ms')
    p95_baseline_band = volatility_band(baseline, 'p95_ms')

    throughput_regression_signal = (
        throughput_delta_pct is not None
        and throughput_delta_pct <= -float(args.throughput_regression_pct)
    )
    avg_regression_signal = latency_regressed(
        current_avg_ms,
        baseline_avg_ms,
        avg_delta_pct,
        float(args.avg_latency_regression_pct),
        float(args.avg_latency_floor_ms),
    )
    p95_regression_signal = latency_regressed(
        current_p95_ms,
        baseline_p95_ms,
        p95_delta_pct,
        float(args.p95_latency_regression_pct),
        float(args.p95_latency_floor_ms),
    )
    throughput_improvement_signal = (
        throughput_delta_pct is not None
        and throughput_delta_pct >= float(args.throughput_improvement_pct)
    )
    avg_improvement_signal = latency_improved(
        current_avg_ms,
        baseline_avg_ms,
        avg_delta_pct,
        float(args.latency_improvement_pct),
        float(args.avg_latency_floor_ms),
    )
    p95_improvement_signal = latency_improved(
        current_p95_ms,
        baseline_p95_ms,
        p95_delta_pct,
        float(args.latency_improvement_pct),
        float(args.p95_latency_floor_ms),
    )
    throughput_regressed = throughput_regression_signal and throughput_band_decisive(
        throughput_current_band,
        throughput_baseline_band,
        direction='regression',
    )
    avg_regressed = avg_regression_signal and latency_band_decisive(
        avg_current_band,
        avg_baseline_band,
        direction='regression',
    )
    p95_regressed = p95_regression_signal and latency_band_decisive(
        p95_current_band,
        p95_baseline_band,
        direction='regression',
    )
    throughput_improved = throughput_improvement_signal and throughput_band_decisive(
        throughput_current_band,
        throughput_baseline_band,
        direction='improvement',
    )
    avg_improved = avg_improvement_signal and latency_band_decisive(
        avg_current_band,
        avg_baseline_band,
        direction='improvement',
    )
    p95_improved = p95_improvement_signal and latency_band_decisive(
        p95_current_band,
        p95_baseline_band,
        direction='improvement',
    )
    raw_regression_metrics = [
        metric
        for metric, active in (
            ('throughput_rps', throughput_regression_signal),
            ('avg_ms', avg_regression_signal),
            ('p95_ms', p95_regression_signal),
        )
        if active
    ]
    raw_improvement_metrics = [
        metric
        for metric, active in (
            ('throughput_rps', throughput_improvement_signal),
            ('avg_ms', avg_improvement_signal),
            ('p95_ms', p95_improvement_signal),
        )
        if active
    ]
    suppressed_regression_metrics = [
        metric
        for metric, raw_active, decisive in (
            ('throughput_rps', throughput_regression_signal, throughput_regressed),
            ('avg_ms', avg_regression_signal, avg_regressed),
            ('p95_ms', p95_regression_signal, p95_regressed),
        )
        if raw_active and not decisive
    ]
    suppressed_improvement_metrics = [
        metric
        for metric, raw_active, decisive in (
            ('throughput_rps', throughput_improvement_signal, throughput_improved),
            ('avg_ms', avg_improvement_signal, avg_improved),
            ('p95_ms', p95_improvement_signal, p95_improved),
        )
        if raw_active and not decisive
    ]

    if throughput_regressed or avg_regressed or p95_regressed:
        classification = 'regression'
    elif throughput_improved or avg_improved or p95_improved:
        classification = 'improvement'
    else:
        classification = 'unchanged'

    return {
        'scenario': current['scenario'],
        'classification': classification,
        'throughput_rps_current': float(current.get('throughput_rps') or 0.0),
        'throughput_rps_baseline': float(baseline.get('throughput_rps') or 0.0),
        'throughput_delta_pct': throughput_delta_pct,
        'avg_ms_current': current_avg_ms,
        'avg_ms_baseline': baseline_avg_ms,
        'avg_delta_pct': avg_delta_pct,
        'p95_ms_current': current_p95_ms,
        'p95_ms_baseline': baseline_p95_ms,
        'p95_delta_pct': p95_delta_pct,
        'raw_regression_metrics': raw_regression_metrics,
        'raw_improvement_metrics': raw_improvement_metrics,
        'suppressed_regression_metrics': suppressed_regression_metrics,
        'suppressed_improvement_metrics': suppressed_improvement_metrics,
        'volatility_bands': {
            'throughput_rps': {
                'current': throughput_current_band,
                'baseline': throughput_baseline_band,
            },
            'avg_ms': {
                'current': avg_current_band,
                'baseline': avg_baseline_band,
            },
            'p95_ms': {
                'current': p95_current_band,
                'baseline': p95_baseline_band,
            },
        },
        'ok': bool(current.get('ok', False)),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    summary_path = Path(args.summary)
    baseline_path = Path(args.baseline)
    summary = load_json(summary_path)
    baseline = load_json(baseline_path)

    current_scenarios = summary.get('scenarios')
    baseline_scenarios = baseline.get('scenarios')
    if not isinstance(current_scenarios, list) or not current_scenarios:
        raise GateFailure(f'benchmark summary has no scenarios: {summary_path}')
    if not isinstance(baseline_scenarios, list) or not baseline_scenarios:
        raise GateFailure(f'benchmark baseline has no scenarios: {baseline_path}')

    summary_aggregation = normalized_aggregation(summary)
    baseline_aggregation = normalized_aggregation(baseline)
    aggregation_compatible = summary_aggregation == baseline_aggregation

    baseline_map = {
        item.get('scenario'): item
        for item in baseline_scenarios
        if isinstance(item, dict) and item.get('scenario')
    }

    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    regressions = 0
    improvements = 0
    unchanged = 0
    new_scenarios = 0

    for current in current_scenarios:
        if not isinstance(current, dict) or not current.get('scenario'):
            raise GateFailure(f'malformed scenario entry in {summary_path}')
        row = compare_scenario(current, baseline_map.get(current['scenario']), args)
        rows.append(row)
        classification = row['classification']
        if classification == 'regression':
            regressions += 1
        elif classification == 'improvement':
            improvements += 1
        elif classification == 'new':
            new_scenarios += 1
        else:
            unchanged += 1
        if not row['ok']:
            failures.append(f"scenario {row['scenario']} marked not ok in summary.json")

    if not aggregation_compatible:
        failures.append(
            'aggregation mismatch: '
            f"summary={summary_aggregation['method']}/{summary_aggregation['runs']} "
            f"baseline={baseline_aggregation['method']}/{baseline_aggregation['runs']} · "
            'promote baseline before treating drift as release-blocking'
        )
    elif regressions > int(args.max_regressions):
        failures.append(
            f'regression count {regressions} exceeds allowed {int(args.max_regressions)}'
        )
        for row in rows:
            if row['classification'] == 'regression':
                failures.append(
                    'regression '
                    f"{row['scenario']}: throughput {fmt_pct(row['throughput_delta_pct'])} · "
                    f"avg {fmt_pct(row['avg_delta_pct'])} · p95 {fmt_pct(row['p95_delta_pct'])}"
                )
    if args.fail_on_new and new_scenarios:
        failures.append(
            f'new scenario count {new_scenarios} exceeds allowed 0'
        )
        for row in rows:
            if row['classification'] == 'new':
                failures.append(f"new scenario {row['scenario']} is missing in baseline")

    status = 'fail' if failures else 'pass'
    return {
        'status': status,
        'summary_path': str(summary_path),
        'baseline_path': str(baseline_path),
        'summary_generated_at': summary.get('generated_at'),
        'baseline_generated_at': baseline.get('generated_at'),
        'summary_aggregation': summary_aggregation,
        'baseline_aggregation': baseline_aggregation,
        'aggregation_compatible': aggregation_compatible,
        'scenario_count': len(current_scenarios),
        'baseline_scenario_count': len(baseline_scenarios),
        'regressions': regressions,
        'improvements': improvements,
        'unchanged': unchanged,
        'new_scenarios': new_scenarios,
        'thresholds': {
            'max_regressions': int(args.max_regressions),
            'fail_on_new': bool(args.fail_on_new),
            'throughput_regression_pct': float(args.throughput_regression_pct),
            'avg_latency_regression_pct': float(args.avg_latency_regression_pct),
            'p95_latency_regression_pct': float(args.p95_latency_regression_pct),
            'avg_latency_floor_ms': float(args.avg_latency_floor_ms),
            'p95_latency_floor_ms': float(args.p95_latency_floor_ms),
            'throughput_improvement_pct': float(args.throughput_improvement_pct),
            'latency_improvement_pct': float(args.latency_improvement_pct),
            'volatility_guard_mode': 'sample-range-overlap',
        },
        'rows': sorted(rows, key=scenario_rank),
        'failures': failures,
    }


def emit_text(report: dict[str, Any]) -> str:
    lines = [
        f"benchmark_regression_gate: {report['status'].upper()}",
        f"summary={report['summary_path']}",
        f"baseline={report['baseline_path']}",
        (
            'aggregation='
            f"summary {report.get('summary_aggregation', {}).get('method', 'single-run')}/"
            f"{report.get('summary_aggregation', {}).get('runs', 1)} "
            f"baseline {report.get('baseline_aggregation', {}).get('method', 'single-run')}/"
            f"{report.get('baseline_aggregation', {}).get('runs', 1)} "
            f"compatible={'yes' if report.get('aggregation_compatible', True) else 'no'}"
        ),
        (
            'scenarios='
            f"{report['scenario_count']} matched≈{report['scenario_count'] - report['new_scenarios']} "
            f"new={report['new_scenarios']} regressions={report['regressions']} "
            f"improvements={report['improvements']} unchanged={report['unchanged']}"
        ),
    ]
    lines.append('classification grid:')
    for row in report['rows']:
        suppressed_parts: list[str] = []
        if row.get('suppressed_regression_metrics'):
            suppressed_parts.append(
                'regression:' + ','.join(row['suppressed_regression_metrics'])
            )
        if row.get('suppressed_improvement_metrics'):
            suppressed_parts.append(
                'improvement:' + ','.join(row['suppressed_improvement_metrics'])
            )
        suppressed_suffix = ''
        if suppressed_parts:
            suppressed_suffix = f" noise-suppressed={'; '.join(suppressed_parts)}"
        lines.append(
            '  - '
            f"{row['scenario']:<22} {row['classification']:<11} "
            f"thr={fmt_pct(row['throughput_delta_pct'])} "
            f"avg={fmt_pct(row['avg_delta_pct'])} "
            f"p95={fmt_pct(row['p95_delta_pct'])}"
            f"{suppressed_suffix}"
        )
    if report['failures']:
        lines.append('failures:')
        lines.extend(f'  - {item}' for item in report['failures'])
    return '\n'.join(lines)


def write_report(path_value: str | None, report: dict[str, Any]) -> None:
    if not path_value:
        return
    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')


def main() -> int:
    args = parse_args()
    try:
        report = build_report(args)
    except GateFailure as exc:
        report = {
            'status': 'fail',
            'summary_path': str(Path(args.summary)),
            'baseline_path': str(Path(args.baseline)),
            'summary_aggregation': {'method': 'single-run', 'runs': 1},
            'baseline_aggregation': {'method': 'single-run', 'runs': 1},
            'aggregation_compatible': True,
            'scenario_count': 0,
            'baseline_scenario_count': 0,
            'regressions': 0,
            'improvements': 0,
            'unchanged': 0,
            'new_scenarios': 0,
            'thresholds': {
                'max_regressions': int(args.max_regressions),
                'fail_on_new': bool(args.fail_on_new),
                'throughput_regression_pct': float(args.throughput_regression_pct),
                'avg_latency_regression_pct': float(args.avg_latency_regression_pct),
                'p95_latency_regression_pct': float(args.p95_latency_regression_pct),
                'avg_latency_floor_ms': float(args.avg_latency_floor_ms),
                'p95_latency_floor_ms': float(args.p95_latency_floor_ms),
                'throughput_improvement_pct': float(args.throughput_improvement_pct),
                'latency_improvement_pct': float(args.latency_improvement_pct),
            },
            'rows': [],
            'failures': [str(exc)],
        }
    write_report(args.report_json, report)
    print(emit_text(report))
    return 1 if report['status'] == 'fail' else 0


if __name__ == '__main__':
    raise SystemExit(main())

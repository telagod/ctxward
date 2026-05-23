use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::BenchmarkConfig;

const THROUGHPUT_DELTA_THRESHOLD_PCT: f64 = 5.0;
const LATENCY_DELTA_THRESHOLD_PCT: f64 = 10.0;
const AVG_LATENCY_NOISE_FLOOR_MS: f64 = 0.25;
const P95_LATENCY_NOISE_FLOOR_MS: f64 = 0.5;

#[derive(Debug, Error)]
pub enum BenchmarkSummaryError {
    #[error("failed to read benchmark summary {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse benchmark summary {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("benchmark matrix is disabled")]
    Disabled,
    #[error("benchmark baseline path is not configured")]
    MissingBaselinePath,
    #[error("failed to write benchmark baseline {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkSummary {
    pub generated_at: String,
    pub scenario_count: usize,
    #[serde(default)]
    pub aggregation: Option<BenchmarkAggregationSummary>,
    #[serde(default)]
    pub scenarios: Vec<BenchmarkScenarioSummary>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkScenarioSummary {
    pub scenario: String,
    pub description: String,
    pub generated_at: String,
    pub requests: usize,
    pub concurrency: usize,
    pub throughput_rps: f64,
    pub latency_ms: BenchmarkLatencySummary,
    pub payload_request_avg_ms: f64,
    pub payload_response_avg_ms: f64,
    pub upstream_avg_ms: f64,
    pub request_payload_kind: String,
    pub decision_sources: BenchmarkDecisionSources,
    pub dependency_ready: BenchmarkDependencyReady,
    pub features: BenchmarkFeatures,
    pub artifacts_root: String,
    pub thresholds: BenchmarkThresholds,
    pub ok: bool,
    #[serde(default)]
    pub aggregation: Option<BenchmarkScenarioAggregationSummary>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkLatencySummary {
    pub min: f64,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
    pub avg: f64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkDecisionSources {
    #[serde(default)]
    pub request: Vec<String>,
    #[serde(default)]
    pub response: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkDependencyReady {
    pub opa: bool,
    pub presidio: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkFeatures {
    pub attachment_scanning: bool,
    pub opa: bool,
    pub presidio: bool,
    pub response_filtering: bool,
    pub session_correlation: bool,
    pub tokenization: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkThresholds {
    pub throughput_rps_min: f64,
    pub avg_ms_max: f64,
    pub p95_ms_max: f64,
    pub payload_request_avg_ms_max: f64,
    pub payload_response_avg_ms_max: f64,
    pub upstream_avg_ms_max: f64,
}

impl BenchmarkSummary {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BenchmarkSummaryError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| BenchmarkSummaryError::Read {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| BenchmarkSummaryError::Parse {
            path: path.display().to_string(),
            source,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct BenchmarkSurface {
    pub enabled: bool,
    pub configured_path: String,
    pub loaded: bool,
    pub generated_at: Option<String>,
    pub scenario_count: usize,
    pub aggregation: Option<BenchmarkAggregationSummary>,
    pub scenarios: Vec<BenchmarkScenarioSurface>,
    pub baseline: Option<BenchmarkBaselineSurface>,
    pub gate: Option<BenchmarkGateSurface>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct BenchmarkScenarioSurface {
    pub scenario: String,
    pub description: String,
    pub requests: usize,
    pub concurrency: usize,
    pub throughput_rps: f64,
    pub latency_ms: BenchmarkLatencySummary,
    pub payload_request_avg_ms: f64,
    pub payload_response_avg_ms: f64,
    pub upstream_avg_ms: f64,
    pub request_payload_kind: String,
    pub features: BenchmarkFeatures,
    pub dependency_ready: BenchmarkDependencyReady,
    pub decision_sources: BenchmarkDecisionSources,
    pub ok: bool,
    pub artifacts_root: String,
    pub aggregation: Option<BenchmarkScenarioAggregationSummary>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkAggregationSummary {
    pub method: String,
    pub runs: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkScenarioAggregationRun {
    pub run: String,
    pub artifacts_root: String,
    pub throughput_rps: f64,
    pub avg_ms: f64,
    pub p95_ms: f64,
    pub payload_request_avg_ms: f64,
    pub payload_response_avg_ms: f64,
    pub upstream_avg_ms: f64,
    pub ok: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkScenarioAggregationSummary {
    pub method: String,
    pub runs: usize,
    #[serde(default)]
    pub sample_runs: Vec<BenchmarkScenarioAggregationRun>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct BenchmarkBaselineSurface {
    pub configured_path: String,
    pub loaded: bool,
    pub generated_at: Option<String>,
    pub scenario_count: usize,
    pub regressions: usize,
    pub improvements: usize,
    pub unchanged: usize,
    pub missing_in_baseline: usize,
    pub scenarios: Vec<BenchmarkScenarioDeltaSurface>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct BenchmarkScenarioDeltaSurface {
    pub scenario: String,
    pub classification: String,
    pub throughput_rps_current: f64,
    pub throughput_rps_baseline: Option<f64>,
    pub throughput_delta_pct: Option<f64>,
    pub avg_ms_current: f64,
    pub avg_ms_baseline: Option<f64>,
    pub avg_delta_pct: Option<f64>,
    pub p95_ms_current: f64,
    pub p95_ms_baseline: Option<f64>,
    pub p95_delta_pct: Option<f64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkGateThresholdSurface {
    pub max_regressions: usize,
    pub fail_on_new: bool,
    pub throughput_regression_pct: f64,
    pub avg_latency_regression_pct: f64,
    pub p95_latency_regression_pct: f64,
    pub avg_latency_floor_ms: f64,
    pub p95_latency_floor_ms: f64,
    pub throughput_improvement_pct: f64,
    pub latency_improvement_pct: f64,
    #[serde(default)]
    pub volatility_guard_mode: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkGateVolatilityBandSurface {
    pub metric: String,
    pub sample_count: usize,
    pub low: f64,
    pub high: f64,
    pub spread_abs: f64,
    pub spread_pct: Option<f64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkGateVolatilityPairSurface {
    #[serde(default)]
    pub current: BenchmarkGateVolatilityBandSurface,
    pub baseline: Option<BenchmarkGateVolatilityBandSurface>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkGateVolatilitySurface {
    #[serde(default)]
    pub throughput_rps: BenchmarkGateVolatilityPairSurface,
    #[serde(default)]
    pub avg_ms: BenchmarkGateVolatilityPairSurface,
    #[serde(default)]
    pub p95_ms: BenchmarkGateVolatilityPairSurface,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkGateRowSurface {
    pub scenario: String,
    pub classification: String,
    pub throughput_rps_current: f64,
    pub throughput_rps_baseline: Option<f64>,
    pub throughput_delta_pct: Option<f64>,
    pub avg_ms_current: f64,
    pub avg_ms_baseline: Option<f64>,
    pub avg_delta_pct: Option<f64>,
    pub p95_ms_current: f64,
    pub p95_ms_baseline: Option<f64>,
    pub p95_delta_pct: Option<f64>,
    pub ok: bool,
    #[serde(default)]
    pub raw_regression_metrics: Vec<String>,
    #[serde(default)]
    pub raw_improvement_metrics: Vec<String>,
    #[serde(default)]
    pub suppressed_regression_metrics: Vec<String>,
    #[serde(default)]
    pub suppressed_improvement_metrics: Vec<String>,
    #[serde(default)]
    pub volatility_bands: BenchmarkGateVolatilitySurface,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct BenchmarkGateReport {
    pub status: String,
    pub summary_path: String,
    pub baseline_path: String,
    pub summary_generated_at: Option<String>,
    pub baseline_generated_at: Option<String>,
    #[serde(default)]
    pub summary_aggregation: BenchmarkAggregationSummary,
    #[serde(default)]
    pub baseline_aggregation: BenchmarkAggregationSummary,
    #[serde(default = "default_true")]
    pub aggregation_compatible: bool,
    pub scenario_count: usize,
    pub baseline_scenario_count: usize,
    pub regressions: usize,
    pub improvements: usize,
    pub unchanged: usize,
    pub new_scenarios: usize,
    #[serde(default)]
    pub thresholds: BenchmarkGateThresholdSurface,
    #[serde(default)]
    pub rows: Vec<BenchmarkGateRowSurface>,
    #[serde(default)]
    pub failures: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct BenchmarkGateSurface {
    pub configured_path: String,
    pub loaded: bool,
    pub fresh: bool,
    pub status: Option<String>,
    pub summary_generated_at: Option<String>,
    pub baseline_generated_at: Option<String>,
    pub summary_aggregation: Option<BenchmarkAggregationSummary>,
    pub baseline_aggregation: Option<BenchmarkAggregationSummary>,
    pub aggregation_compatible: bool,
    pub scenario_count: usize,
    pub baseline_scenario_count: usize,
    pub regressions: usize,
    pub improvements: usize,
    pub unchanged: usize,
    pub new_scenarios: usize,
    pub thresholds: Option<BenchmarkGateThresholdSurface>,
    pub rows: Vec<BenchmarkGateRowSurface>,
    pub failures: Vec<String>,
    pub error: Option<String>,
}

fn default_true() -> bool {
    true
}

pub fn promote_benchmark_baseline(
    config: &BenchmarkConfig,
) -> Result<BenchmarkBaselinePromotion, BenchmarkSummaryError> {
    if !config.enabled {
        return Err(BenchmarkSummaryError::Disabled);
    }
    let baseline_path = config
        .baseline_summary_json_path
        .as_deref()
        .filter(|path| !path.is_empty())
        .ok_or(BenchmarkSummaryError::MissingBaselinePath)?;
    let summary_path = Path::new(&config.summary_json_path);
    let baseline_path_ref = Path::new(baseline_path);
    let raw = fs::read_to_string(summary_path).map_err(|source| BenchmarkSummaryError::Read {
        path: summary_path.display().to_string(),
        source,
    })?;
    serde_json::from_str::<BenchmarkSummary>(&raw).map_err(|source| {
        BenchmarkSummaryError::Parse {
            path: summary_path.display().to_string(),
            source,
        }
    })?;
    if let Some(parent) = baseline_path_ref.parent() {
        fs::create_dir_all(parent).map_err(|source| BenchmarkSummaryError::Write {
            path: baseline_path_ref.display().to_string(),
            source,
        })?;
    }
    fs::write(baseline_path_ref, raw.as_bytes()).map_err(|source| {
        BenchmarkSummaryError::Write {
            path: baseline_path_ref.display().to_string(),
            source,
        }
    })?;
    Ok(BenchmarkBaselinePromotion {
        summary_path: summary_path.display().to_string(),
        baseline_path: baseline_path_ref.display().to_string(),
    })
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BenchmarkBaselinePromotion {
    pub summary_path: String,
    pub baseline_path: String,
}

pub fn load_benchmark_surface(config: &BenchmarkConfig) -> BenchmarkSurface {
    let mut surface = BenchmarkSurface {
        enabled: config.enabled,
        configured_path: config.summary_json_path.clone(),
        ..BenchmarkSurface::default()
    };

    if !config.enabled {
        return surface;
    }

    match BenchmarkSummary::load(&config.summary_json_path) {
        Ok(summary) => {
            surface.loaded = true;
            surface.generated_at = Some(summary.generated_at.clone());
            surface.scenario_count = summary.scenario_count;
            surface.aggregation = summary.aggregation.clone();
            surface.scenarios = summary
                .scenarios
                .iter()
                .cloned()
                .map(to_scenario_surface)
                .collect();
            let baseline_surface =
                load_benchmark_baseline(config.baseline_summary_json_path.as_deref(), &summary);
            surface.gate = Some(load_benchmark_gate(
                config.gate_report_json_path.as_deref(),
                surface.generated_at.as_deref(),
                baseline_surface.generated_at.as_deref(),
            ));
            surface.baseline = Some(baseline_surface);
        }
        Err(err) => {
            surface.error = Some(err.to_string());
            let baseline_surface = load_benchmark_baseline(
                config.baseline_summary_json_path.as_deref(),
                &BenchmarkSummary::default(),
            );
            surface.gate = Some(load_benchmark_gate(
                config.gate_report_json_path.as_deref(),
                None,
                baseline_surface.generated_at.as_deref(),
            ));
            surface.baseline = Some(baseline_surface);
        }
    }

    surface
}

fn to_scenario_surface(scenario: BenchmarkScenarioSummary) -> BenchmarkScenarioSurface {
    BenchmarkScenarioSurface {
        scenario: scenario.scenario,
        description: scenario.description,
        requests: scenario.requests,
        concurrency: scenario.concurrency,
        throughput_rps: scenario.throughput_rps,
        latency_ms: scenario.latency_ms,
        payload_request_avg_ms: scenario.payload_request_avg_ms,
        payload_response_avg_ms: scenario.payload_response_avg_ms,
        upstream_avg_ms: scenario.upstream_avg_ms,
        request_payload_kind: scenario.request_payload_kind,
        features: scenario.features,
        dependency_ready: scenario.dependency_ready,
        decision_sources: scenario.decision_sources,
        ok: scenario.ok,
        artifacts_root: scenario.artifacts_root,
        aggregation: scenario.aggregation,
    }
}

fn load_benchmark_baseline(
    baseline_path: Option<&str>,
    current: &BenchmarkSummary,
) -> BenchmarkBaselineSurface {
    let Some(path) = baseline_path.filter(|path| !path.is_empty()) else {
        return BenchmarkBaselineSurface::default();
    };

    let mut surface = BenchmarkBaselineSurface {
        configured_path: path.to_string(),
        ..BenchmarkBaselineSurface::default()
    };

    match BenchmarkSummary::load(path) {
        Ok(summary) => {
            surface.loaded = true;
            surface.generated_at = Some(summary.generated_at.clone());
            surface.scenario_count = summary.scenario_count;
            let baseline_map = summary
                .scenarios
                .into_iter()
                .map(|scenario| (scenario.scenario.clone(), scenario))
                .collect::<HashMap<_, _>>();
            let mut regressions = 0usize;
            let mut improvements = 0usize;
            let mut unchanged = 0usize;
            let mut missing = 0usize;

            surface.scenarios = current
                .scenarios
                .iter()
                .map(|current_scenario| {
                    if let Some(baseline) = baseline_map.get(&current_scenario.scenario) {
                        let delta = compare_scenarios(current_scenario, baseline);
                        match delta.classification.as_str() {
                            "regression" => regressions += 1,
                            "improvement" => improvements += 1,
                            _ => unchanged += 1,
                        }
                        delta
                    } else {
                        missing += 1;
                        BenchmarkScenarioDeltaSurface {
                            scenario: current_scenario.scenario.clone(),
                            classification: "new".to_string(),
                            throughput_rps_current: current_scenario.throughput_rps,
                            throughput_rps_baseline: None,
                            throughput_delta_pct: None,
                            avg_ms_current: current_scenario.latency_ms.avg,
                            avg_ms_baseline: None,
                            avg_delta_pct: None,
                            p95_ms_current: current_scenario.latency_ms.p95,
                            p95_ms_baseline: None,
                            p95_delta_pct: None,
                        }
                    }
                })
                .collect();

            surface.regressions = regressions;
            surface.improvements = improvements;
            surface.unchanged = unchanged;
            surface.missing_in_baseline = missing;
        }
        Err(err) => {
            surface.error = Some(err.to_string());
        }
    }

    surface
}

fn load_benchmark_gate(
    gate_path: Option<&str>,
    current_generated_at: Option<&str>,
    baseline_generated_at: Option<&str>,
) -> BenchmarkGateSurface {
    let Some(path) = gate_path.filter(|path| !path.is_empty()) else {
        return BenchmarkGateSurface::default();
    };

    let mut surface = BenchmarkGateSurface {
        configured_path: path.to_string(),
        ..BenchmarkGateSurface::default()
    };

    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<BenchmarkGateReport>(&raw) {
            Ok(report) => {
                surface.loaded = true;
                surface.status = Some(report.status.clone());
                surface.summary_generated_at = report.summary_generated_at.clone();
                surface.baseline_generated_at = report.baseline_generated_at.clone();
                surface.summary_aggregation = Some(report.summary_aggregation.clone());
                surface.baseline_aggregation = Some(report.baseline_aggregation.clone());
                surface.aggregation_compatible = report.aggregation_compatible;
                surface.scenario_count = report.scenario_count;
                surface.baseline_scenario_count = report.baseline_scenario_count;
                surface.regressions = report.regressions;
                surface.improvements = report.improvements;
                surface.unchanged = report.unchanged;
                surface.new_scenarios = report.new_scenarios;
                surface.thresholds = Some(report.thresholds);
                surface.rows = report.rows;
                surface.failures = report.failures;
                surface.fresh = current_generated_at == surface.summary_generated_at.as_deref()
                    && baseline_generated_at == surface.baseline_generated_at.as_deref();
            }
            Err(source) => {
                surface.error = Some(
                    BenchmarkSummaryError::Parse {
                        path: path.to_string(),
                        source,
                    }
                    .to_string(),
                );
            }
        },
        Err(source) => {
            surface.error = Some(
                BenchmarkSummaryError::Read {
                    path: path.to_string(),
                    source,
                }
                .to_string(),
            );
        }
    }

    surface
}

fn compare_scenarios(
    current: &BenchmarkScenarioSummary,
    baseline: &BenchmarkScenarioSummary,
) -> BenchmarkScenarioDeltaSurface {
    let throughput_delta_pct = pct_delta(current.throughput_rps, baseline.throughput_rps);
    let avg_delta_pct = pct_delta(current.latency_ms.avg, baseline.latency_ms.avg);
    let p95_delta_pct = pct_delta(current.latency_ms.p95, baseline.latency_ms.p95);

    let throughput_regressed = throughput_delta_pct
        .map(|delta| delta <= -THROUGHPUT_DELTA_THRESHOLD_PCT)
        .unwrap_or(false);
    let avg_regressed = latency_regressed(
        current.latency_ms.avg,
        baseline.latency_ms.avg,
        avg_delta_pct,
        AVG_LATENCY_NOISE_FLOOR_MS,
    );
    let p95_regressed = latency_regressed(
        current.latency_ms.p95,
        baseline.latency_ms.p95,
        p95_delta_pct,
        P95_LATENCY_NOISE_FLOOR_MS,
    );
    let throughput_improved = throughput_delta_pct
        .map(|delta| delta >= THROUGHPUT_DELTA_THRESHOLD_PCT)
        .unwrap_or(false);
    let avg_improved = latency_improved(
        current.latency_ms.avg,
        baseline.latency_ms.avg,
        avg_delta_pct,
        AVG_LATENCY_NOISE_FLOOR_MS,
    );
    let p95_improved = latency_improved(
        current.latency_ms.p95,
        baseline.latency_ms.p95,
        p95_delta_pct,
        P95_LATENCY_NOISE_FLOOR_MS,
    );

    let classification = if throughput_regressed || avg_regressed || p95_regressed {
        "regression"
    } else if throughput_improved || avg_improved || p95_improved {
        "improvement"
    } else {
        "unchanged"
    };

    BenchmarkScenarioDeltaSurface {
        scenario: current.scenario.clone(),
        classification: classification.to_string(),
        throughput_rps_current: current.throughput_rps,
        throughput_rps_baseline: Some(baseline.throughput_rps),
        throughput_delta_pct,
        avg_ms_current: current.latency_ms.avg,
        avg_ms_baseline: Some(baseline.latency_ms.avg),
        avg_delta_pct,
        p95_ms_current: current.latency_ms.p95,
        p95_ms_baseline: Some(baseline.latency_ms.p95),
        p95_delta_pct,
    }
}

fn pct_delta(current: f64, baseline: f64) -> Option<f64> {
    if baseline.abs() < f64::EPSILON {
        return None;
    }
    Some(((current - baseline) / baseline) * 100.0)
}

fn latency_regressed(
    current_ms: f64,
    baseline_ms: f64,
    delta_pct: Option<f64>,
    noise_floor_ms: f64,
) -> bool {
    delta_pct
        .map(|delta| delta >= LATENCY_DELTA_THRESHOLD_PCT)
        .unwrap_or(false)
        && (current_ms - baseline_ms) >= noise_floor_ms
}

fn latency_improved(
    current_ms: f64,
    baseline_ms: f64,
    delta_pct: Option<f64>,
    noise_floor_ms: f64,
) -> bool {
    delta_pct
        .map(|delta| delta <= -LATENCY_DELTA_THRESHOLD_PCT)
        .unwrap_or(false)
        && (baseline_ms - current_ms) >= noise_floor_ms
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{BenchmarkSummary, load_benchmark_surface};
    use crate::config::BenchmarkConfig;

    fn example_summary(throughput: f64, avg_ms: f64, p95_ms: f64) -> String {
        format!(
            r#"{{
  "generated_at": "2026-05-22T12:11:24Z",
  "scenario_count": 1,
  "scenarios": [
    {{
      "scenario": "json-redact",
      "description": "hot path",
      "generated_at": "2026-05-22T12:11:18Z",
      "requests": 80,
      "concurrency": 8,
      "throughput_rps": {throughput},
      "latency_ms": {{"min": 1.0, "p50": 2.0, "p95": {p95_ms}, "max": 4.0, "avg": {avg_ms}}},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.9,
      "request_payload_kind": "json",
      "decision_sources": {{"request": ["builtin"], "response": ["builtin"]}},
      "dependency_ready": {{"opa": false, "presidio": false}},
      "features": {{
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": false,
        "tokenization": false
      }},
      "artifacts_root": ".tmp-smoke/bench-matrix/json-redact",
      "thresholds": {{
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      }},
      "ok": true
    }}
  ]
}}"#,
            throughput = throughput,
            avg_ms = avg_ms,
            p95_ms = p95_ms,
        )
    }

    #[test]
    fn loads_benchmark_summary_surface_from_json() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut file = temp.reopen().unwrap();
        write!(file, "{}", example_summary(1618.98, 2.5, 3.0)).unwrap();

        let summary = BenchmarkSummary::load(temp.path()).unwrap();
        assert_eq!(summary.scenario_count, 1);
        assert_eq!(summary.scenarios[0].scenario, "json-redact");

        let surface = load_benchmark_surface(&BenchmarkConfig {
            enabled: true,
            summary_json_path: temp.path().display().to_string(),
            baseline_summary_json_path: None,
            gate_report_json_path: None,
        });
        assert!(surface.loaded);
        assert_eq!(surface.scenario_count, 1);
        assert_eq!(surface.scenarios[0].scenario, "json-redact");
        assert!(surface.error.is_none());
    }

    #[test]
    fn reports_benchmark_summary_load_error_without_panicking() {
        let surface = load_benchmark_surface(&BenchmarkConfig {
            enabled: true,
            summary_json_path: "/definitely/missing/bench-summary.json".to_string(),
            baseline_summary_json_path: None,
            gate_report_json_path: None,
        });

        assert!(surface.enabled);
        assert!(!surface.loaded);
        assert!(surface.error.is_some());
        assert_eq!(surface.scenario_count, 0);
    }

    #[test]
    fn promotes_summary_to_baseline_path() {
        let temp = tempfile::tempdir().unwrap();
        let summary = temp.path().join("summary.json");
        let baseline = temp.path().join("nested").join("baseline.json");
        std::fs::write(&summary, example_summary(1618.98, 2.5, 3.0)).unwrap();

        let result = super::promote_benchmark_baseline(&BenchmarkConfig {
            enabled: true,
            summary_json_path: summary.display().to_string(),
            baseline_summary_json_path: Some(baseline.display().to_string()),
            gate_report_json_path: None,
        })
        .unwrap();

        assert_eq!(result.summary_path, summary.display().to_string());
        assert_eq!(result.baseline_path, baseline.display().to_string());
        assert!(baseline.exists());
        assert_eq!(
            std::fs::read_to_string(summary).unwrap(),
            std::fs::read_to_string(baseline).unwrap()
        );
    }

    #[test]
    fn computes_regression_against_baseline_summary() {
        let current = tempfile::NamedTempFile::new().unwrap();
        let baseline = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(current.path(), example_summary(120.0, 10.0, 20.0)).unwrap();
        std::fs::write(baseline.path(), example_summary(160.0, 5.0, 10.0)).unwrap();

        let surface = load_benchmark_surface(&BenchmarkConfig {
            enabled: true,
            summary_json_path: current.path().display().to_string(),
            baseline_summary_json_path: Some(baseline.path().display().to_string()),
            gate_report_json_path: None,
        });

        let baseline_surface = surface.baseline.expect("baseline surface");
        assert!(baseline_surface.loaded);
        assert_eq!(baseline_surface.regressions, 1);
        assert_eq!(baseline_surface.scenarios[0].classification, "regression");
        assert!(baseline_surface.scenarios[0].throughput_delta_pct.unwrap() < -20.0);
        assert!(baseline_surface.scenarios[0].avg_delta_pct.unwrap() > 50.0);
    }

    #[test]
    fn ignores_sub_millisecond_p95_jitter_for_baseline_compare() {
        let current = tempfile::NamedTempFile::new().unwrap();
        let baseline = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(current.path(), example_summary(160.0, 3.62, 4.978)).unwrap();
        std::fs::write(baseline.path(), example_summary(160.0, 3.62, 4.523)).unwrap();

        let surface = load_benchmark_surface(&BenchmarkConfig {
            enabled: true,
            summary_json_path: current.path().display().to_string(),
            baseline_summary_json_path: Some(baseline.path().display().to_string()),
            gate_report_json_path: None,
        });

        let baseline_surface = surface.baseline.expect("baseline surface");
        assert!(baseline_surface.loaded);
        assert_eq!(baseline_surface.regressions, 0);
        assert_eq!(baseline_surface.unchanged, 1);
        assert_eq!(baseline_surface.scenarios[0].classification, "unchanged");
        assert!(baseline_surface.scenarios[0].p95_delta_pct.unwrap() > 10.0);
    }

    #[test]
    fn keeps_classifying_meaningful_p95_drop_as_improvement() {
        let current = tempfile::NamedTempFile::new().unwrap();
        let baseline = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(current.path(), example_summary(160.0, 3.62, 4.8)).unwrap();
        std::fs::write(baseline.path(), example_summary(160.0, 3.62, 5.5)).unwrap();

        let surface = load_benchmark_surface(&BenchmarkConfig {
            enabled: true,
            summary_json_path: current.path().display().to_string(),
            baseline_summary_json_path: Some(baseline.path().display().to_string()),
            gate_report_json_path: None,
        });

        let baseline_surface = surface.baseline.expect("baseline surface");
        assert!(baseline_surface.loaded);
        assert_eq!(baseline_surface.improvements, 1);
        assert_eq!(baseline_surface.scenarios[0].classification, "improvement");
        assert!(baseline_surface.scenarios[0].p95_delta_pct.unwrap() < -10.0);
    }

    #[test]
    fn loads_gate_report_and_marks_it_fresh() {
        let temp = tempfile::tempdir().unwrap();
        let gate_path = temp.path().join("gate-report.json");
        std::fs::write(
            &gate_path,
            r#"{
  "status": "pass",
  "summary_path": "./summary.json",
  "baseline_path": "./baseline.json",
  "summary_generated_at": "2026-05-22T13:07:31.521917+00:00",
  "baseline_generated_at": "2026-05-22T12:40:21.488828+00:00",
  "scenario_count": 6,
  "baseline_scenario_count": 6,
  "regressions": 0,
  "improvements": 2,
  "unchanged": 4,
  "new_scenarios": 0,
  "thresholds": {
    "max_regressions": 0,
    "fail_on_new": false,
    "throughput_regression_pct": 5.0,
    "avg_latency_regression_pct": 10.0,
    "p95_latency_regression_pct": 10.0,
    "avg_latency_floor_ms": 0.25,
    "p95_latency_floor_ms": 0.5,
    "throughput_improvement_pct": 5.0,
    "latency_improvement_pct": 10.0,
    "volatility_guard_mode": "sample-range-overlap"
  },
  "rows": [
    {
      "scenario": "json-tokenize",
      "classification": "improvement",
      "throughput_rps_current": 1807.72,
      "throughput_rps_baseline": 1737.66,
      "throughput_delta_pct": 4.03,
      "avg_ms_current": 4.227,
      "avg_ms_baseline": 4.299,
      "avg_delta_pct": -1.67,
      "p95_ms_current": 4.956,
      "p95_ms_baseline": 5.579,
      "p95_delta_pct": -11.17,
      "ok": true,
      "raw_regression_metrics": [],
      "raw_improvement_metrics": ["p95_ms"],
      "suppressed_regression_metrics": [],
      "suppressed_improvement_metrics": [],
      "volatility_bands": {
        "throughput_rps": {
          "current": {"metric": "throughput_rps", "sample_count": 1, "low": 1807.72, "high": 1807.72, "spread_abs": 0.0, "spread_pct": 0.0},
          "baseline": {"metric": "throughput_rps", "sample_count": 1, "low": 1737.66, "high": 1737.66, "spread_abs": 0.0, "spread_pct": 0.0}
        },
        "avg_ms": {
          "current": {"metric": "avg_ms", "sample_count": 1, "low": 4.227, "high": 4.227, "spread_abs": 0.0, "spread_pct": 0.0},
          "baseline": {"metric": "avg_ms", "sample_count": 1, "low": 4.299, "high": 4.299, "spread_abs": 0.0, "spread_pct": 0.0}
        },
        "p95_ms": {
          "current": {"metric": "p95_ms", "sample_count": 1, "low": 4.956, "high": 4.956, "spread_abs": 0.0, "spread_pct": 0.0},
          "baseline": {"metric": "p95_ms", "sample_count": 1, "low": 5.579, "high": 5.579, "spread_abs": 0.0, "spread_pct": 0.0}
        }
      }
    }
  ],
  "failures": []
}"#,
        )
        .unwrap();

        let gate = super::load_benchmark_gate(
            Some(gate_path.to_str().unwrap()),
            Some("2026-05-22T13:07:31.521917+00:00"),
            Some("2026-05-22T12:40:21.488828+00:00"),
        );

        assert!(gate.loaded);
        assert!(gate.fresh);
        assert_eq!(gate.status.as_deref(), Some("pass"));
        assert_eq!(gate.improvements, 2);
        assert_eq!(gate.rows[0].scenario, "json-tokenize");
    }

    #[test]
    fn marks_gate_report_stale_when_timestamps_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let gate_path = temp.path().join("gate-report.json");
        std::fs::write(
            &gate_path,
            r#"{
  "status": "fail",
  "summary_path": "./summary.json",
  "baseline_path": "./baseline.json",
  "summary_generated_at": "2026-05-22T12:40:21.488828+00:00",
  "baseline_generated_at": "2026-05-22T12:10:21.488828+00:00",
  "scenario_count": 1,
  "baseline_scenario_count": 1,
  "regressions": 1,
  "improvements": 0,
  "unchanged": 0,
  "new_scenarios": 0,
  "thresholds": {
    "max_regressions": 0,
    "fail_on_new": false,
    "throughput_regression_pct": 5.0,
    "avg_latency_regression_pct": 10.0,
    "p95_latency_regression_pct": 10.0,
    "avg_latency_floor_ms": 0.25,
    "p95_latency_floor_ms": 0.5,
    "throughput_improvement_pct": 5.0,
    "latency_improvement_pct": 10.0,
    "volatility_guard_mode": "sample-range-overlap"
  },
  "rows": [],
  "failures": ["gate stale example"]
}"#,
        )
        .unwrap();

        let gate = super::load_benchmark_gate(
            Some(gate_path.to_str().unwrap()),
            Some("2026-05-22T13:07:31.521917+00:00"),
            Some("2026-05-22T12:40:21.488828+00:00"),
        );

        assert!(gate.loaded);
        assert!(!gate.fresh);
        assert_eq!(gate.status.as_deref(), Some("fail"));
        assert_eq!(gate.failures.len(), 1);
    }
}

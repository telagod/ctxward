<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Benchmark Baseline 与 Gate

默认示例配置已加入：

```yaml
benchmarks:
  enabled: true
  summary_json_path: ./.tmp-smoke/bench-matrix/summary.json
  baseline_summary_json_path: ./.tmp-smoke/bench-matrix/baseline.json
  gate_report_json_path: ./.tmp-smoke/bench-matrix/gate-report.json
```

含义：

- 控制面不会自己触发压测
- `GET /admin/status` 会读取 `summary_json_path` 并回显当前矩阵摘要
- 若配置了 `baseline_summary_json_path`，控制面会额外计算 regression / improvement / unchanged
- 若配置了 `gate_report_json_path`，控制面还会读取 `gate-report.json`，展示 benchmark gate 的 pass/fail/stale verdict
- 若文件缺失或 JSON 不合法，控制面会显示 `configured but unavailable`，同时返回错误摘要，不影响数据面转发

建议流程：

1. 先执行 `make bench-matrix` 产出最新基线
2. 再打开 `/admin` 查看"性能基线矩阵"与 baseline drift
3. 若当前结果可作为新基线，可在控制台点击"固化为 baseline"
4. 发布前把 `summary.json` / `baseline.json` 作为 smoke 产物或 CI artifact 保留

若接 GitHub Actions，建议把 `make bench-ci` 放进独立 `bench` job，并给该 job 单独配置 concurrency group，避免同一分支上的多次 bench 互相踩宿主机。

若要先验证"回归/改善判官"本身没有坏，可先执行：

```bash
make smoke-bench-drift
```

它会直接伪造 current `summary.json` 与 older `baseline.json`，live 验证 regression / improvement / unchanged / new 四类分类与 baseline promote。控制台里则会把这些 compare 渲染成 `Top regressions / drift watchlist` 与四张 drift summary 卡，方便在发版前肉眼确认。

## Benchmark Matrix

性能矩阵默认通过 `scripts/bench_harness.py` 统一驱动。若只想打某一条链路：

```bash
python3 scripts/bench_harness.py scenario \
  --scenario json-tokenize \
  --root .tmp-smoke/bench-tokenize
```

可选场景：

- `json-redact`：纯内建 regex redact
- `json-tokenize`：request tokenization + response redact
- `json-review-replay`：review create/approve + replay override
- `json-opa`：OPA sidecar 参与 request/response 决策
- `json-presidio`：Presidio sidecar 驱动检测
- `pdf-redact`：multipart PDF simple-text rewrite

矩阵模式：

```bash
python3 scripts/bench_harness.py matrix --root .tmp-smoke/bench-matrix
```

若要显式指定采样轮次：

```bash
python3 scripts/bench_harness.py matrix --root .tmp-smoke/bench-matrix --runs 3
```

压测后若要把它当成发布门禁：

```bash
make bench-gate
```

若 gate 提示 `aggregation mismatch`：

```bash
make bench-promote
make bench-gate
```

等价命令：

```bash
python3 scripts/bench_regression_gate.py \
  --summary .tmp-smoke/bench-matrix/summary.json \
  --baseline .tmp-smoke/bench-matrix/baseline.json \
  --report-json .tmp-smoke/bench-matrix/gate-report.json
```

常用开关：

- `--max-regressions 0`：默认值，只要有 regression 就 fail
- `--fail-on-new`：把 baseline 中缺失的新场景也视作 gate failure
- `--throughput-regression-pct 5`
- `--avg-latency-regression-pct 10`
- `--p95-latency-regression-pct 10`
- `--avg-latency-floor-ms 0.25`
- `--p95-latency-floor-ms 0.5`

`gate-report.json` 的 `rows[*]` 里还会附带：

- `suppressed_regression_metrics` / `suppressed_improvement_metrics`
- `raw_regression_metrics` / `raw_improvement_metrics`
- `volatility_bands`

便于 admin console / CI 解释"为什么这次看起来有漂移，但仍被认定为 noise 而非真实回归"。

> 注：`json-presidio` 这条链路额外回归了 **Presidio analyzer character offset -> UTF-8 byte offset** 的转换，避免中文前缀场景下脱敏边界错位。

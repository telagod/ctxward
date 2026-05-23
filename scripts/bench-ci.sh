#!/usr/bin/env bash
set -euo pipefail

bash ./scripts/bench-matrix.sh
bash ./scripts/bench-gate.sh

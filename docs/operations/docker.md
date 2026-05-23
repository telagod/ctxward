<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Docker / Compose

本地联调：

```bash
docker compose up --build
```

默认会同时拉起：

- `ctxward`（命名向后兼容：容器内保留 `context-gurd` 符号链接）
- `opa`

健康检查会探测 `/healthz`，read-only rootfs + dropped capabilities 已默认开启。

生产镜像参见 GitHub Release 中的 `ghcr.io/telagod/ctxward:<tag>`（multi-arch + cosign keyless signed + CycloneDX SBOM attested）。

部署模板：

- VM / systemd: [`deploy/systemd/ctxward.service`](../../deploy/systemd/ctxward.service)
- Kubernetes Helm: [`deploy/helm/`](../../deploy/helm/) （**M2** 完整化）

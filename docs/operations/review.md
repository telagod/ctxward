<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Review 审批流

当策略结果为 `review` 时：

1. 网关阻断本次上游转发，返回 `409 review_required`
2. 响应体包含 `review.ticket_id`
3. 管理员通过：
   - `GET /admin/reviews`
   - `POST /admin/reviews/resolve`

   完成审批
4. 业务端在重放原请求时附带：

```text
x-review-ticket-id: <ticket_id>
```

若 ticket 已批准、principal/path/request body hash 均匹配，则网关按 `post_approval_action` 放行；若已拒绝，则继续阻断。

## Body hash 与重放注意

这里的 `request body hash` 取自**原始请求字节**，不是 JSON 语义等价后的归一化结果。也就是说，业务端重放时应尽量复用最初被拦截的 payload bytes；若字段顺序、空白、换行或编码形式变化，可能得到新的 hash，导致旧 ticket 不再命中。

## 持久化形态

当前持久化模型是**本地 JSONL event log**，适合单实例与边车部署；若要多实例共享审批状态，下一步应接 Redis / Postgres。详见 [`PRODUCTIZATION.md`](../../PRODUCTIZATION.md) §5 与 §9 M3。

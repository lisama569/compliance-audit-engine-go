# 合规审计事件处理与判定引擎（本地离线）

纯 Go、零外部依赖（仅标准库）、进程内内存存储的合规审计事件引擎。支持：

- 多租户、多来源审计事件的**幂等归并**与重放；
- 版本化规则集的**发布 / 回滚 / 历史重算**（按事件发生时的有效版本复现结论）；
- 按租户与角色限制查询、发布与重算，**越权拒绝且不泄露其他租户数据**；
- 并发写入、规则切换、重算同时发生下的一致性，以及令牌桶**背压 / 限流**；
- 无法归并的事件进入**隔离区**，并带可区分的 `rejected` / `pending` 原因。

## 1. 包结构

| 包 | 职责 |
|---|---|
| `model` | 领域类型、判定/状态常量、哨兵错误、隔离原因码 |
| `store` | 并发安全的内存存储：事件去重、水印、规则版本、决策与重算历史、隔离区 |
| `rules` | 规则集校验、稳定校验和、规则求值、版本注册中心（发布/回滚/按时间解析） |
| `ingest` | 事件接入管线：校验→幂等 claim→乱序/迟到判定→按发生时版本求值→落库 |
| `replay` | 历史重算：原始结论不可变，重算结果 append-only |
| `auth` | 角色-动作-租户三维授权矩阵 |
| `ratelimit` | 令牌桶限流器（接入与重算各一个） |
| `engine` | 门面：装配全部组件，所有操作先鉴权、再限流、后执行 |
| `cmd/auditctl` | 本地离线 CLI，内置 `demo` 端到端场景 |
| `testutil` | 测试用结构化日志（关键输入 / 规则版本 / 判定依据 / 最终结果） |

## 2. 事件语义

### 2.1 幂等键与内容哈希

- 幂等键：`(tenant_id, event_id)`，由来源保证事件 ID 在来源内唯一。
- 内容哈希（`ingest.ContentHash`）：对 `tenant_id / event_id / source / type /
  occurred_at / actor / sequence / payload` 的规范化 JSON 取 SHA-256。
  **刻意排除 `received_at`**（投递元数据），因此同内容的重复投递会归并。
- 判定规则：
  - 同键 + 同哈希 ⇒ **重复投递**：幂等合并，返回首条结论（`duplicate=true`），
    不产生第二条有效记录、不触发第二次求值。
  - 同键 + 不同哈希 ⇒ **重复冲突**：事件进入隔离区，状态 `rejected`，
    原因 `duplicate_conflict`。**首个结论永久保留，绝不静默改写。**
- 原子性：去重登记在 `store.ClaimEvent` 的单一临界区完成（读写锁），
  64 路并发相同事件只有 1 个首次、63 个合并；见
  `TestEngine_ConcurrentDuplicatesYieldSingleDecision`。

### 2.2 乱序与迟到

- 每个 `(tenant, source)` 维护两个水印：最大 `occurred_at` 与最大序号。
  水印**只在事件产生有效结论后**才推进（`AdvanceWatermark`），被隔离的事件
  不会污染后续事件的顺序判断。
- **迟到（late）**：投递延迟 `received_at - occurred_at` 超过
  `LateThreshold`（默认 5 分钟）的事件仍被接受，但结论标记 `late=true`；
  判定一律使用**事件发生时**有效的规则版本。
- **过迟（too_late）**：延迟超过 `MaxLate`（默认 72h）⇒ 隔离 `rejected /
  too_late`。
- **未来事件（future_event）**：发生时间超前超过 `MaxSkew`（默认 5 分钟时钟
  偏移）⇒ 隔离 `rejected / future_event`。
- **有序来源**（`event.ordered=true`，带单调 `sequence`）：
  - 收到比已确认高水位更旧的序号 ⇒ 隔离 `pending / out_of_order`，并登记该
    悬挂序号（`MarkPendingSeq`），不推进序号水印；
  - 新事件与某个悬挂前驱之间存在缺口（gap）⇒ 事件照常接受，但结论标记
    `reordered=true`，供审计追查缺失前驱。

### 2.3 校验与隔离原因

| 原因码 | 状态 | 含义 |
|---|---|---|
| `missing_field` | rejected | tenant_id/event_id/source/type/occurred_at 缺失 |
| `invalid_payload` | rejected | payload 为 null |
| `unknown_tenant` | rejected | 租户未注册（必须先 `RegisterTenant`） |
| `duplicate_conflict` | rejected | 同 ID 不同内容，首结论已存在 |
| `too_late` | rejected | 超出最大迟到窗口 |
| `future_event` | rejected | 超出允许的时钟偏移 |
| `out_of_order` | pending | 有序来源收到旧序号，可待前驱补齐后处理 |
| `no_rule_at_occurrence_time` | pending | 事件发生时刻没有任何生效规则版本 |

- `pending` 记录可在重算成功后由系统自动解除（`replay.resolveIfPending`，
  仅解除 pending）；`rejected` 记录**任何重算都不会删除**，只能管理员显式
  `ResolveQuarantine`。
- 隔离区"首因优先"：同一事件重复触发隔离时，首次的区分原因不被覆盖，
  只累加 `seen_count`。

### 2.4 决策（Decision）

- 原始决策（outcome=`original`）**只写一次、永不可变**（`SaveDecision`
  首个写入者获胜）。
- 重算结果（outcome=`recomputed`）追加到每事件的重算历史
  （`AppendRecomputed`，append-only）。
- 查询默认返回**当前有效结论**（有重算取最新重算，否则取原始）；
  `DecisionHistory` 同时返回不可变原始件与全部重算件，便于追溯。

## 3. 规则兼容与回滚

### 3.1 版本模型

- 规则集按**租户作用域**版本化：`tenant_id=""` 为全局作用域。版本号在作用域
  内单调递增，由注册中心分配，发布方不可指定。
- 每个版本带半开时间区间 `[effective_from, effective_to)`：
  - 发布新版本时，上一个 open-ended 版本在新版本 `effective_from` 处被关闭
    （`CloseActiveRange`）。
  - **历史不可变**：已发布的版本与时间区间永不修改或删除。
- 按时间解析 `EffectiveAt(tenant, t)`：先查租户作用域覆盖 `t` 的版本，
  未命中再回退全局作用域。注意：即使版本状态是 `superseded / rolled_back`，
  在它曾经生效的历史时间点仍然可被解析（状态信息不参与时间命中）。

### 3.2 校验（发布前）

`rules.ValidateRuleSet` 在**任何状态变更之前**校验，非法规则不会污染当前
生效状态：

- 版本 ≥ 1、必须有 `effective_from`、至少一条规则；
- 规则必须有 `id / name / event_types / 非空 conditions / 合法 verdict`；
- 规则 ID 不得重复；
- 条件操作符必须合法（`eq/ne/in/not_in/gt/gte/lt/lte/exists/not_exists/
  contains`）；`in/not_in` 必须给列表，大小比较必须给数值；
- **作用域冲突**：同优先级、事件类型重叠、但 verdict 不同的规则被视为歧义，
  禁止发布（`*` 匹配所有类型）。
- 与最新版本**规则内容完全相同**（`RulesContentChecksum`，仅对规则体做
  SHA-256，不含生效时间）的重复发布会返回 `ErrAlreadyExists`。
- 校验和 `ChecksumRuleSet` 对规则按 ID 排序后再哈希，与声明顺序无关；
  内容任何变化都会改变校验和。

### 3.3 回滚语义

- `Rollback(tenant, toVersion)` **不复活旧版本、不改写历史**，而是创建一个
  全新的版本号，规则体从目标版本复制，`effective_from=now`。
- 因此时间轴严格分层：旧事件仍落在旧版本区间、按旧版本复现；回滚之后的
  新事件才使用"回滚后"的新版本。
- 历史重算（replay）**始终按 `occurred_at` 解析版本**：规则更新不会改变对
  历史事件的复现结果；测试见
  `TestRecompute_ReproducesVerdictAtOccurrenceAfterRollback`。

## 4. 权限边界（RBAC）

| 角色 | 可用动作（限本租户） |
|---|---|
| `tenant_reader` | query, query_history |
| `tenant_writer` | ingest, query, query_history |
| `tenant_admin` | 上述 + recompute, publish_rules, rollback_rules, resolve_quarantine |
| `platform_admin` | 全部，但仅可作用于全局作用域 `""` 或其"假定"的本租户 |

- 所有引擎入口（`engine.Engine` 的方法）都先调 `Authorizer.Can` 再执行；
  存储层查询本身也强制按租户 key 隔离，双保险。
- **跨租户一律拒绝**：租户角色不能触碰其他租户；平台管理员也不能读取任意
  租户，除非显式假定（principal 的 tenant 与目标一致）。
- 拒绝错误统一为无任何标识信息的 `forbidden`（不含主体 ID、动作、目标
  租户），避免通过错误消息探测其他租户是否存在数据。
- 查询层从不跨租户返回数据（`store.QueryDecisions` 以 tenantID 为根 key）。

## 5. 一致性与背压

- **并发写入**：事件去重与水印推进分别在独立临界区，且水印仅在有效结论
  落库后提交；`go test -race` 全部通过。
- **写入 + 规则切换 + 重算并发**：
  `TestEngine_ConcurrentWritesRuleSwitchAndRecompute` 用 8 写者 × 25 事件，
  在中途发布 v2 并触发重算，断言事件数/决策数精确相等、历史结论零变化、
  所有旧事件仍由 v1 判定。
- **限流**：
  - 接入令牌桶（`RateLimitPerSec / RateLimitBurst`），耗尽时立即返回
    `model.ErrOverloaded`（`rate limit exceeded`），明确背压、不排队堆积；
  - 重算另有独立令牌桶与并发信号量（`MaxRecomputeConcurrency`），并发重算
    超过容量时返回同样的 `ErrOverloaded`；
  - 速率设为 `0` 表示不限流（本地默认接入不限流，重算默认 2/s、并发 2）。

## 6. 运行配置

`engine.Config`（`engine.DefaultConfig()` 为本地默认值）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `MaxLate` | 72h | 超过则 `too_late` 拒绝 |
| `MaxSkew` | 5m | 未来事件时钟偏移上限 |
| `LateThreshold` | 5m（ingest 层） | 超过则标记 `late`（仍接受） |
| `RateLimitPerSec / RateLimitBurst` | 0 / 1000 | 接入限流（0=不限） |
| `RecomputePerSec / RecomputeBurst` | 2 / 2 | 重算限流 |
| `MaxRecomputeConcurrency` | 2 | 重算并发上限 |

时钟可通过 `Engine.SetClock` 注入，测试中用固定/可控时钟复现乱序、迟到、
版本切换等时间敏感场景。

## 7. 本地验证方法

无需任何外部服务或网络：

```bash
# 1) 编译 + 静态检查
go build ./...
go vet ./...

# 2) 全量单元测试（含竞态检测）
go test ./... -race

# 3) 查看带审计上下文的详细测试日志
#    （关键输入 / 规则版本 / 判定依据 basis / 最终结果）
go test -v ./ingest/
go test -v ./rules/
go test -v ./replay/
go test -v ./engine/

# 4) 端到端内置场景：发布v1 → 正常/违规事件 → 重复归并 → 内容冲突隔离
#    → 迟到事件按v1判定 → 发布v2 → 重算复现历史 → v2后新事件 → 回滚v1
#    → 越权重算被拒 → 跨租户查询被拒 → 隔离区清单
go run ./cmd/auditctl demo
```

测试覆盖对照（需求 → 测试）：

| 需求 | 测试 |
|---|---|
| 重复事件幂等 | `TestIngest_DuplicateIsMerged`、`TestEngine_ConcurrentDuplicatesYieldSingleDecision` |
| 同 ID 异内容不被改写 | `TestIngest_SameIDDifferentContentIsRejected`、`TestEngine_ConcurrentConflictingContentNeverRewrites` |
| 乱序 / 迟到 | `TestIngest_OrderedSourceOutOfOrderPending`、`TestIngest_LateEventWithinWindowUsesRulesAtOccurrence`、`TestIngest_TooLateIsRejected`、`TestIngest_FutureEventIsRejected` |
| 规则校验/冲突/缺字段 | `TestValidateRuleSet_*`、`TestRegistry_PublishRejectsInvalidSet` |
| 发布 / 回滚 / 历史版本解析 | `TestRegistry_PublishAssignsVersionsAndEffectiveRanges`、`TestRegistry_RollbackCreatesNewVersion` |
| 回滚重算复现历史 | `TestRecompute_ReproducesVerdictAtOccurrenceAfterRollback` |
| 并发一致性 | `TestEngine_ConcurrentWritesRuleSwitchAndRecompute`、`TestClaimEvent_ConcurrentSameIDDifferentHash` |
| 越权与租户隔离 | `TestAuthorizer_RoleMatrix`、`TestAuthorizer_DenialMessageDoesNotLeak`、`TestEngine_AuthorizationBoundaries`、`TestQueryDecisions_TenantIsolation` |
| 背压 / 限流 | `TestLimiter_BurstThenBackPressure`、`TestEngine_IngestRateLimitBackPressure`、`TestRecompute_OverloadWhenConcurrencyExceeded` |
| 无规则版本的待处理 | `TestIngest_NoRuleAtOccurrenceTimePending` |

## 8. 关键设计取舍

- 内存存储、单把读写锁换来可审计的串行化：所有跨 map 不变量（去重、
  水印、版本区间）都在锁内维护；本地离线场景无需分布式复杂度。
- 结论"原始件不可变 + 重算件追加"是可追溯性的核心：任何规则演进都可被
  完整复盘，且无法对历史"销账"。
- 隔离区用**可区分原因 + rejected/pending 二分**替代"吞掉异常"：运维可以
  区分"必须人工裁决的冲突"和"等待条件补齐即可自动解除"的暂存。

# 合规审计事件处理与判定引擎（本地离线）

一个零外部依赖、可完全在本地运行的 Go 库，提供多租户、多来源审计事件的
幂等归并与重放、版本化规则集的发布/回滚/历史重算、按租户与角色的查询授权，
以及过载背压与限流能力。

- Go 版本：1.25
- 存储：进程内并发安全内存存储（无数据库/网络依赖）
- 入口示例：`cmd/audit-demo`

## 包结构

| 包 | 职责 |
| --- | --- |
| `pkg/model` | 事件、规则、规则集、判定结果、隔离记录等领域类型；幂等键与内容指纹 |
| `pkg/auth` | 基于租户 + 角色的静态授权矩阵 |
| `pkg/store` | 事件/结果/隔离区的内存存储（互斥锁、按租户隔离、结果槽位不可变） |
| `pkg/rules` | 版本化规则集注册表：严格校验、发布、回滚、生效时间轴与按时刻选取生效版本 |
| `pkg/engine` | 规则判定纯函数、单事件评估、只读预演、历史重算、规则切换后的当前结果补齐 |
| `pkg/ingest` | 事件接入：校验、幂等归并、乱序/迟到处理、隔离、令牌限流与信号量背压 |
| `pkg/service` | 门面：串联鉴权 + 各组件，以租户为粒度串行化写入/切换/重算/预演 |

## 一、事件语义

### 幂等键与内容指纹

- **幂等键** = `tenant_id | source | event_id`（见 `model.Event.Key()`），
  唯一标识一条业务事件。
- **内容指纹** = 对全部业务字段（发生时间、动作、资源、主体、金额、元数据等，
  **不含接收时间**）的 SHA-256（见 `model.Event.Fingerprint()`）。
  元数据按键排序后参与哈希，指纹不受 map 迭代顺序影响。

### 归并结论（`ingest.IngestResult`）

同一幂等键下：

| 情形 | 处理 | 标记 |
| --- | --- | --- |
| 首次到达 | 写入有效记录并按当时规则版本判定 | `Accepted` |
| 内容指纹完全一致 | **幂等返回既有结果**，不产生第二条有效记录、不进隔离区 | `Duplicate` |
| 同键但指纹不同（疑似重放篡改） | 拒绝并入，**既有记录绝不被改写**，隔离待处理 | 隔离原因 `CONFLICT` |

### 乱序与迟到

接入层为每个租户维护“已观测最大发生时间”水位，并配置宽限窗口
`LateGrace`：

- 事件发生时间落后水位 **不超过** 宽限窗口：视为正常乱序，照常归并判定；
- **超过** 宽限窗口：不静默并入、不改写结论，隔离为 `LATE` 待人工处理；
- 完全重复的投递即使伴随迟到也优先幂等返回，不产生隔离噪音；
- `LateGrace <= 0` 表示关闭迟到判定（任意乱序均接受）。

### 其他拒绝原因

- `INVALID`：`tenant_id/source/event_id/occurred_at/action` 等关键字段缺失，
  在校验阶段即被隔离，无法绕过校验进入有效记录。

所有无法归并的事件都带**可区分原因**（`DUPLICATE/CONFLICT/LATE/INVALID`）
与人类可读明细，保存在租户隔离的隔离区，可经 `QueryQuarantined` 查询。

## 二、规则兼容、发布与回滚

### 规则与规则集

- 条件字段：`amount_cents`（配 `GTE/LTE`，值必须为 int64）、
  `action/resource_id/actor`（配 `EQ`）。
- 作用域：`Scope` 匹配事件来源 `source`、`Action` 匹配事件动作；`*` 为通配。
- 判定：`ALLOW / DENY / REVIEW`；**无任何规则命中时默认 `REVIEW`**（证据不足交人工）。
- 同一规则集内多规则命中时优先级 **DENY > REVIEW > ALLOW**，命中规则全部
  作为“判定依据”（`Evidence`）写入结果，保证结论可解释、可复现。

### 严格校验（发布前）

`rules.ValidateRuleSet` 拒绝：关键字段缺失、非法操作符/字段/判定、
非数值阈值、重复规则 ID、以及**作用域冲突**
（同一 scope+action+条件却给出不同判定）。校验失败不产生任何副作用、
不消耗版本号、不污染当前生效状态。

### 版本化、回滚与历史复现

- 每次成功发布生成**不可变**版本快照，版本号单调递增（v1, v2, ...），
  并记录发布时间；发布返回值与内部快照均做防御性拷贝，调用方无法回写污染。
- 事件判定使用**事件发生时刻已生效的最新版本**
  （`Registry.EffectiveAt(occurredAt)`），因此规则更新后旧事件仍按其发生时
  的版本复现结论。
- **回滚**把“当前生效指针”移回上一版本，不删除任何历史版本；回滚后
  再发布仍在序列尾部递增版本号（v3 ...）。已经没有更早版本可回滚时返回
  `rules.ErrNothingToRollback`，生效状态完全不变。
- 结果以 `(事件, 规则版本)` 为槽位存储且**只写一次、不可覆盖**：
  - 发布/回滚后由 `RefillCurrent` 为当前版本补齐缺失槽位，使“当前查询”反映当前规则；
  - `Recompute` 为每个历史版本补齐缺失槽位，使任意历史版本都可查询；
  - 已存在槽位严格保留原结论，重算天然幂等（第二次重算补齐数为 0）。
- 查询时 `ruleVersion <= 0` 表示当前生效版本；显式传版本号查询该历史版本结论，
  结果中 `Recomputed` 标记该槽位是否由重算补齐。

### 生效时间轴与按时刻追溯

- `RuleTimeline(tenantID)` 返回规则版本的**生效时间轴**：每次发布/回滚都
  产生一段半开区间 `[EffectiveFrom, EffectiveTo)`，`EffectiveTo` 为零值表示
  至今生效；回滚以 `Cause=rollback` 的区间体现（区间版本为回滚目标版本）。
- 边界约定为**左闭右开**：恰好落在边界上的时刻只属于右侧区间，
  任意时刻至多命中一个版本，不存在同一时刻命中两个矛盾版本的情况。
- `EffectiveRulesAt(tenantID, t)` 返回任意时刻 t 真正生效的版本；
  首次生效之前的时刻返回 `rules.ErrNoRuleSet`。

### 规则变更预演（Dry-Run）

- `DryRunRules(candidate)` 预演“若发布该候选规则集”：按租户**已有**审计事件
  预跑一遍，逐条给出 `当前版本结论 -> 候选结论`、是否变化及命中依据
  （`DryRunReport.Items`），候选版本号展示为“若现在发布将分配的下一版本号”。
- `DryRunRollback()` 预演“若回滚到上一历史版本”：候选规则为回滚目标版本；
  没有可回滚版本时返回 `rules.ErrNothingToRollback`。
- 预演**只读**：不修改生效规则、不写入任何判定结果槽位、不触碰隔离区，
  临时结论不会混入任何正式查询；候选规则集与正式发布走同一套严格校验。
- 预演全程持有租户串行锁，与事件写入/发布/回滚/重算互斥，
  因此拿到的是前后一致的快照，不会出现“半截数据”。

### 回滚之后的闭环

- 回滚生效后，**新发生**（发生时间在回滚生效时刻之后）的事件按回滚后
  当前生效版本判定，并直接出现在当前版本查询中。
- 回滚后才到达的**乱序旧事件**仍按发生时版本落槽（历史可复现），同时
  接入路径会为当前生效版本补齐槽位，保证“判定用的版本”和“当前查询能看到
  的版本”不会脱节。
- 发布、回滚、重算、写入并发时，每个 `(事件, 版本)` 槽位仍只写一次，
  结论唯一且稳定（见并发一致性一节与对应测试）。

## 三、权限边界

`pkg/auth` 静态角色矩阵（`Action`：query / ingest / recompute / publish）：

| 角色 | query | ingest | publish / recompute | 数据范围 |
| --- | --- | --- | --- | --- |
| `tenant_reader` | ✅ | ❌ | ❌ | 仅本租户 |
| `tenant_admin` | ✅ | ✅ | ✅ | 仅本租户 |
| `global_auditor` | ✅ | ❌ | ❌ | 所有租户（只读） |

- 租户角色访问他租户资源一律返回 `auth.ErrForbidden`；
- 越权拒绝不带任何他租户数据；存储层亦按 `tenant_id` 物理隔离（map 分桶）；
- 全局审计员可跨租户只读查询，但任何写/重算/发布动作都被拒绝。

## 四、并发一致性与过载保护

- **租户级串行锁**：同一租户的事件写入、规则发布/回滚、历史重算互斥；
  不同租户互不阻塞。
- 存储层全部方法互斥；结果槽位“存在即拒绝覆盖”，即使并发也不会静默改写。
- 并发重复写入由存储层去重保证：只有一份成为有效记录，其余按完全重复幂等返回。
- **过载保护**（`ingest.Config`）：
  - 令牌桶限流 `RatePerSec/RateBurst`：令牌不足时快速失败；
  - 信号量背压 `MaxInflight`：在途处理达到上限立即返回
    `ingest.ErrBusy`（调用方退避重试），`context` 取消时及时退出；
  - `MaxInflight <= 0` 表示不限制并发，`RatePerSec <= 0` 表示不限流。

## 五、运行配置

```go
svc := service.New(ingest.Config{
    MaxInflight: 64,                 // 最大在途接入数；<=0 不限制
    RatePerSec:  1000,               // 令牌桶每秒令牌；<=0 不限流
    RateBurst:   100,                // 令牌桶容量
    LateGrace:   5 * time.Minute,    // 乱序/迟到宽限窗口；<=0 关闭迟到判定
    Clock:       nil,                // 可选：注入可控时钟（演示/测试）
})
```

组装细节见 `pkg/service.New`：内存存储 + 规则注册表 + 引擎 + 接入层
在同一组件图内协作，全部状态在进程内，进程退出即清空（离线演示用途）。

## 六、本地验证

```bash
# 构建
go build ./...

# 全量单测（建议带竞态检测）
go test -race ./...

# 查看关键用例的诊断日志（输入 / 规则版本 / 判定依据 / 最终结果）
go test ./pkg/service/ -run 'TestEndToEndRollbackAndRecompute|TestConcurrent|TestDryRun|TestRollbackClosesLoop' -v
go test ./pkg/rules/ -run TestTimelineBoundariesAndEffectiveAt -v

# 端到端离线演示：重复、乱序/迟到、冲突、v2 发布、预演、时间轴、重算、
# 回滚及回滚后新事件闭环、越权、非法规则
go run ./cmd/audit-demo
```

### 测试覆盖一览

| 需求点 | 测试 |
| --- | --- |
| 重复事件幂等、不产生重复记录 | `ingest.TestDuplicateIsIdempotent`、`store.TestPutEventDedupAndConflict` |
| 乱序窗口内接受 | `ingest.TestOutOfOrderWithinGraceAccepted` |
| 迟到隔离且不改写 | `ingest.TestLateBeyondGraceQuarantined`、`service.TestLateEventBoundaryIsQuarantinedNotRewritten` |
| 同键重放篡改冲突隔离 | `ingest.TestConflictSameKeyDifferentPayload` |
| 非法事件隔离 | `ingest.TestInvalidEventQuarantined` |
| 非法规则/作用域冲突拒绝且不污染生效态 | `rules.TestValidateRuleSet`、`service.TestInvalidPublishDoesNotPollute` |
| 版本选择、发布、回滚、历史重算复现 | `engine.TestEvaluateUsesVersionAtOccurrenceAndRecompute`、`engine.TestRollbackReproducesOldConclusion`、`service.TestEndToEndRollbackAndRecompute` |
| 预演不改状态、候选非法同样被拒 | `service.TestDryRunPublishDoesNotMutateState` |
| 回滚预演、无可回滚版本明确失败 | `service.TestDryRunRollbackPreview` |
| 生效时间轴边界、按时刻追溯唯一命中 | `rules.TestTimelineBoundariesAndEffectiveAt`、`service.TestServiceTimelineReflectsRollback` |
| 回滚后新事件/乱序事件在当前查询可见 | `service.TestRollbackClosesLoopForNewEvents` |
| 并发写入 + 规则切换 + 重算一致性 | `service.TestConcurrentWritesPublishAndRecompute`（`-race`） |
| 并发预演/回滚/发布/写入下结论唯一稳定 | `service.TestConcurrentDryRunRollbackAndIngest`（`-race`） |
| 越权访问拒绝、不泄露他租户数据 | `auth.TestAuthorizeMatrix`、`service.TestCrossTenantAndRoleBoundaries`、`service.TestDryRunAndTimelineAuthorization` |
| 限流与背压 | `ingest.TestBackpressureAndRateLimit` |

单测通过 `t.Logf` 打印关键输入（幂等键/金额/发生时间）、规则版本、
命中依据（规则 ID/操作符/阈值/原因）与最终判定，便于离线审计追溯。

## 设计取舍说明

- 结论按 `(事件, 版本)` 多槽位保存而非就地覆盖：用空间换取“任意历史版本
  严格可复现”，且每个槽位只写一次，天然抵御并发静默改写。
- “当前查询”与“按发生时版本复现”是两个显式视角：前者随发布/回滚切换，
  后者由不可变历史槽位保证；重算只补缺槽，不推翻任何既有结论。
- 生效时间轴用“追加生效记录 + 半开区间展开”实现：发布/回滚只追加记录，
  从不修改历史区间，因此任意时刻的生效版本可确定性地重放。
- 预演复用判定纯函数 `applyRules`，与正式判定共享同一份逻辑，
  从源头保证“预演看到的就是发布后会发生的”。
- 内存实现面向本地离线与可测试性；接口（`EventStore/ResultStore/
  QuarantineStore/Registry/Authorizer`）均已抽象，可替换为持久化实现。

## 兼容范围

本次新增能力（预演、时间轴、回滚闭环）对既有行为完全向后兼容：

- 既有公开 API 签名不变，仅新增方法（`DryRunRules/DryRunRollback/
  RuleTimeline/EffectiveRulesAt/RollbackTarget/Timeline`）；
- 发布/回滚/重算/查询的既有语义不变：历史事件仍按发生时版本复现，
  结果槽位仍只写一次，非法发布仍零副作用；
- 唯一的行为补全：回滚被显式记录在生效时间轴上，因此“回滚生效时刻之后
  发生的事件”按回滚后版本判定（此前该场景未定义）；接入路径会额外补齐
  当前版本槽位，只增不改，不影响任何已存在槽位；
- 预演为纯只读能力，不向既有查询路径引入任何新状态。

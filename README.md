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
| `pkg/rules` | 版本化规则集注册表：严格校验、发布、回滚、生效时间轴、按时刻选取真正生效版本 |
| `pkg/engine` | 规则判定纯函数、单事件评估、历史重算、规则切换后的当前结果补齐、规则变更预演 |
| `pkg/ingest` | 事件接入：校验、幂等归并、乱序/迟到处理、隔离、令牌限流与信号量背压 |
| `pkg/service` | 门面：串联鉴权 + 各组件，以租户为粒度串行化写入/切换/重算 |

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
- 事件判定使用**事件发生时刻真正生效的版本**（`Registry.EffectiveAt(occurredAt)`，
  以发布/回滚构成的激活日志为准），因此规则更新后旧事件仍按其发生时的版本复现结论。
- **回滚**只把“当前生效指针”移到上一版本，不删除任何历史版本；回滚后
  再发布仍在序列尾部递增版本号（v3 ...）。
- 结果以 `(事件, 规则版本)` 为槽位存储且**只写一次、不可覆盖**：
  - 发布/回滚后由 `RefillCurrent` 为当前版本补齐缺失槽位，使“当前查询”反映当前规则；
  - `Recompute` 为每个历史版本补齐缺失槽位，使任意历史版本都可查询；
  - 已存在槽位严格保留原结论，重算天然幂等（第二次重算补齐数为 0）。
- 查询时 `ruleVersion <= 0` 表示当前生效版本；显式传版本号查询该历史版本结论，
  结果中 `Recomputed` 标记该槽位是否由重算补齐。

### 规则变更预演（只读）

发布新规则或回滚之前，可以先按本租户**已有审计事件**预跑一遍：

- `Service.PreviewPublish(候选规则集)`：预演“若发布该规则集”。候选规则集先经过
  与正式发布**相同的严格校验**，非法规则集直接预演失败；
- `Service.PreviewRollback()`：预演“若回滚到上一版本”。没有可回滚版本时返回
  `rules.ErrNothingToRollback`，状态不变。

预演报告（`model.PreviewReport`）逐事件给出：当前生效版本下的结论（`Before`，
依据版本 `BaseVersion`）、候选规则集下的结论（`After`，候选版本
`CandidateVersion`——预演发布时为将分配的下一个版本号）、是否翻转以及候选规则
集下的命中依据。预演**只能看不能动**：

- 不修改当前生效规则、不消耗版本号；
- 不生成/覆盖任何判定结果槽位，预演结论不会混入正式查询
  （对照组优先引用已持久化的当前版本结论，缺失时纯函数现算但不落库）；
- 预演持有租户串行锁，期间的事件写入/发布/回滚/重算都被阻塞，
  不会读到前后对不上的半截数据；
- 预演是只读操作，按 `query` 动作鉴权（只读角色与全局审计员可用）。

### 生效时间轴与按时刻追溯

注册表为每个租户维护**激活日志**：每次发布、每次回滚都追加一条生效切换记录。

- `Service.RuleTimeline(tenant)` 返回生效时间轴（`model.VersionInterval`）：
  每个版本从何时生效（`From`）、何时被下一版本/回滚接替（`To`）、
  区间由来（`Cause`: `publish`/`rollback`）、是否当前生效（`Current`）；
  回滚产生的新段同样按时间顺序出现在时间轴上；
- `Service.EffectiveVersionAt(tenant, t)` 返回 t 时刻**真正生效**的版本，
  与事件判定使用的口径完全一致；
- **边界约定**：区间为半开 `[From, To)`——接替时刻归属新区间，
  任意时刻至多命中一个区间，不会同时命中两个互相矛盾的版本；
  最后一段 `To` 为空（至今仍生效）。

### 回滚之后的闭环

- `EffectiveAt` 以激活日志为准：回滚生效后，**新发生**的事件按回滚后当前生效的
  版本判定；回滚之前、旧版本实际生效过的时段仍解析到旧版本，历史结论严格可复现。
- 回滚后接入的事件若**发生**在旧版本生效时段（迟到但在宽限窗口内），仍按发生时
  版本判定并落入对应槽位；同时引擎会为**当前版本**一并补齐该事件的结果槽位，
  保证当前查询一定能看到该事件——不会出现“判定用一个版本、当前查询却看不到”
  的断层。
- 没有更早版本可回滚时返回 `rules.ErrNothingToRollback`，当前版本、结果槽位与
  时间轴全部保持原样，状态不被改坏。

## 三、权限边界

`pkg/auth` 静态角色矩阵（`Action`：query / ingest / recompute / publish）：

| 角色 | query | ingest | publish / recompute | 数据范围 |
| --- | --- | --- | --- | --- |
| `tenant_reader` | ✅ | ❌ | ❌ | 仅本租户 |
| `tenant_admin` | ✅ | ✅ | ✅ | 仅本租户 |
| `global_auditor` | ✅ | ❌ | ❌ | 所有租户（只读） |

- 租户角色访问他租户资源一律返回 `auth.ErrForbidden`；
- 越权拒绝不带任何他租户数据；存储层亦按 `tenant_id` 物理隔离（map 分桶）；
- 全局审计员可跨租户只读查询，但任何写/重算/发布动作都被拒绝；
- 预演（`PreviewPublish/PreviewRollback`）、时间轴（`RuleTimeline`）与按时刻追溯
  （`EffectiveVersionAt`）均为只读能力，按 `query` 动作鉴权：只读角色与全局审计员
  可用，跨租户访问同样被拒绝。

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
go test ./pkg/service/ -run 'TestEndToEndRollbackAndRecompute|TestConcurrent' -v
go test ./pkg/service/ -run 'TestPreviewDoesNotMutateState|TestRollbackClosedLoopForNewEvents' -v
go test ./pkg/rules/ -run 'TestTimelineAndEffectiveAtBoundaries' -v

# 端到端离线演示：重复、乱序/迟到、冲突、v2 发布、预演、重算、回滚、
# 回滚闭环、时间轴、越权、非法规则
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
| 预演不改状态（不发布/不写槽位/不混正式查询） | `service.TestPreviewDoesNotMutateState` |
| 回滚后新事件判定与当前查询一致（闭环） | `service.TestRollbackClosedLoopForNewEvents` |
| 时间轴边界（半开区间、回滚段、按时刻追溯） | `rules.TestTimelineAndEffectiveAtBoundaries` |
| 回滚耗尽明确失败且状态不变 | `service.TestRollbackExhaustedFailsClean`、`rules.TestTimelineAndEffectiveAtBoundaries` |
| 并发写入 + 规则切换 + 重算一致性 | `service.TestConcurrentWritesPublishAndRecompute`（`-race`） |
| 并发预演/时间轴 + 写入/发布/回滚/重算一致性 | `service.TestConcurrentPreviewPublishRollbackAndWrites`（`-race`） |
| 越权访问拒绝、不泄露他租户数据 | `auth.TestAuthorizeMatrix`、`service.TestCrossTenantAndRoleBoundaries`、`service.TestPreviewAndTimelineAuthorization` |
| 限流与背压 | `ingest.TestBackpressureAndRateLimit` |

单测通过 `t.Logf` 打印关键输入（幂等键/金额/发生时间）、规则版本、
命中依据（规则 ID/操作符/阈值/原因）与最终判定，便于离线审计追溯。

## 设计取舍说明

- 结论按 `(事件, 版本)` 多槽位保存而非就地覆盖：用空间换取“任意历史版本
  严格可复现”，且每个槽位只写一次，天然抵御并发静默改写。
- “当前查询”与“按发生时版本复现”是两个显式视角：前者随发布/回滚切换，
  后者由不可变历史槽位保证；重算只补缺槽，不推翻任何既有结论。
- 预演复用判定纯函数而非另起一套逻辑：保证预演结论与正式发布/回滚后的
  真实结论逐字一致；预演全程持租户锁且不落库，是“看得见的无副作用”。
- 内存实现面向本地离线与可测试性；接口（`EventStore/ResultStore/
  QuarantineStore/Registry/Authorizer`）均已抽象，可替换为持久化实现。

## 兼容性说明

- 本次新增的预演、时间轴、按时刻追溯均为**纯新增接口**，既有
  `Publish/Rollback/Recompute/Query` 等接口签名与语义不变。
- `EffectiveAt` 的口径从“按发布时间取最新”细化为“按发布/回滚激活日志取
  真正生效版本”：**未发生回滚时两者完全等价**，既有行为不受影响；
  只有回滚之后，回滚时刻起的时间段才会解析到回滚后的版本（这正是闭环所需）。
- 已持久化的历史结果槽位不受影响：旧事件在各历史版本下的结论依旧原样可查询。




你是 ShadowTrace 仓库的实现工程师。一次只完成 **一个** GitHub Issue（`ISSUE-XXX`）。  
权威规格来源优先级：

1. **当前 Issue 正文**（目标 / 前置依赖 / 文件范围 / 统一命名 / 实现步骤 / 验收标准 / 测试与验证 / 降级策略）
2. 仓库根目录 `README.md` 与 `ShadowTrace 工程实施拆解方案.md` 中的 **简介第 1–4 节全局约定**
3. 已存在代码与测试（不得无故推翻既有契约）

Issue 写明的验收标准是 Definition of Done；未写明的功能 **不要做**。

## 项目一句话

ShadowTrace = 独立部署的多 Agent 安全运营系统：Mock XDR 输入 → 分诊/证据/评分/处置/写回/验证/报告闭环；与深信服 XDR、安全 GPT **解耦**，通过 Adapter / Provider 可替换。

## 当前阶段（极重要）

**团队现在没有真实 XDR / 安全 GPT 环境。** 对厂商页面、字段、接口的理解都是基于公开材料与截图的**领域猜测**，用来设计兼容的内部模型与 Mock 契约，**不是**已验证的生产 API。

因此本阶段默认只做：

1. **MockXDRServer + MockToolProvider + Mock Disposition API** 跑通 P0 闭环与验收。
2. 内部领域模型、状态机、Agent、审批、outbox、报告——全部厂商无关。
3. `SourceAdapter` / `DispositionAdapter` / `ToolProvider` / `LLMProvider` 的**接口与占位**，为以后接真环境留缝。

明确不做 / 禁止：

1. 不要连接、探测、调用任何真实深信服 XDR / AICP 端点。
2. 不要根据截图或猜测硬编码厂商私有 REST 路径、operation_code、鉴权头。
3. 不要把「猜的厂商行为」写进 Agent 业务逻辑；猜测只允许落在 Adapter 映射层或 `docs`/配置注释，并标明 `UNVERIFIED`。
4. Issue 若提到 live / 厂商适配：只实现契约、能力探测默认 `UNKNOWN`、失败与 `writeback_unsupported` 路径；**把真实兼容留到后续拿到正式接口文档或脱敏抓包之后的专用 Issue**。
5. 验收以 Mock 契约为准；不得声称「已对接真实 XDR」。

## 硬约束（违反即不合格）

### A. 边界与写回

1. **分析内容永不写回外部系统**：研判正文、报告、Prompt、`decision_trace`、模型内部过程禁止经 DispositionAdapter 出站。
2. **处置写回是业务义务（在 Mock 上也要演真）**：对 `disposition_policy=required` 的事件，闭环必须有且仅有一条终态 `EVENT_STATUS_UPDATE` 在 **Mock Disposition** 上达到 `CONFIRMED`（P0 证据优先 `readback_verified`），才可视为外部处置完成并进入 `CLOSED`。不能用「本地 Action SUCCESS」冒充已写回。
3. **三个可替换边界**（现在用 Mock 实现，以后换真实现，不改 Agent）：
   - `SourceAdapter`：只读接入
   - `ToolProvider`：查询 / 实体处置执行
   - `DispositionAdapter`：事件处置与最小执行结果同步
4. 每个会产生外部副作用的 response/rollback Action **只能选一个** `ExecutionOwner`：`XDR_MANAGED` 或 `DIRECT_TOOL`，禁止双下发。`DIRECT_TOOL` 只允许同步 `EXECUTION_RESULT_RECORD`，严禁再映射成 `ENTITY_ACTION_SUBMIT`。
5. 开发默认且本阶段唯一合格路径：`SOURCE_MODE=mock_xdr` + `DISPOSITION_MODE=mock_xdr` + MockToolProvider。Mock 必须模拟外部 ID、分页、异步、延迟、部分成功/失败；**禁止**「写入后立刻读回成功」的自证闭环。
6. 任何 live 路径：能力默认 `UNKNOWN`；未验证则 readiness 非 READY / `writeback_unsupported`，阻断自动处置；**禁止**把 `required` 降成 `not_required`，禁止静默回退 Mock 后返回成功。
7. `ALLOW_LIVE_SIDE_EFFECTS` / `ALLOW_XDR_WRITEBACK` **必须保持默认 false**；本阶段不要为了「演示真机」去打开它们。分析写回无开关、永远禁止。

### B. 命名与结构（简介第 4 节）

1. 同一概念只用一个主名；外部别名只在 Adapter 映射，不得渗入 Agent 业务层。
2. 目录：`backend/` `frontend/` `contracts/` `infra/` `scripts/` `data/` `docs/`；后端包在 `backend/app/`。
3. API 前缀 `/api/v1`；错误体 `error_code` / `error_message` / `details`；分页 `total` / `page` / `page_size` / `items`。
4. 字段 snake_case；`risk_score` 0–100；`confidence` 0–1。
5. Agent 类名固定（SuperAgent、TriageAgent、EvidenceAgent…）；工具名 snake_case，按能力清单扩展，不断言工具总数。
6. 状态枚举以方案为准（如 `EventStatus` 14 态、`ActionStatus` 11 态）；不要自创同义枚举。
7. ID 格式遵循方案（`evt-` / `act-` / `wbk-` 等）；`report_id` 由 `event_id` 稳定派生，禁止每次随机。
8. 禁止在场景包之外硬编码演示人物/实体名（如「张三」）；按通用 `event_type` 设计。

### C. 技术栈与优先级

1. 后端：Python 3.11 + FastAPI + SQLAlchemy 2.0（异步）+ Pydantic v2 + pytest。
2. 前端：Node 20 + React 18 + TypeScript + Vite。
3. 存储：PostgreSQL(+pgvector) + Redis；**P0 视 Redis 为硬依赖**。向量检索只用 pgvector。
4. LLM 一律经 `LLMProvider`（mock / openai_compatible / custom）；Agent 必须有无 LLM 降级路径。
5. Neo4j / OpenSearch / Kafka / K8s / SOC 大屏为 P2，不得变成 P0/P1 硬前置。
6. P1 失败不得阻断 P0；只实现本 Issue 优先级范围内的内容。

### D. 关键语义（常踩坑）

1. `FinalVerdict` ≠ `EventStatus`；误报是判定标签，不是事件状态。
2. `writeback_required` 由业务/`disposition_policy` 推导，禁止因技术能力反向改写。
3. `WritebackReadiness` / `OutboxDeliveryStatus` / `WritebackStatus` / Action 成功 **相互正交**，UI 与统计不得混为一谈；Mock P0 确认证据优先 `readback_verified`。
4. `UNKNOWN`（已提交无法确认）禁止自动重试/回滚，只能查证或人工裁决。
5. `update_source_event_disposition` 是 deferred、`POST_VERIFY` 的 disposition-only response Action；由 `EventDispositionService` 激活，不经 ToolProvider，不另建新 Action 类型。
6. 字段写入遵守 `FIELD_OWNERSHIP` / WorkingMemory；非 owner 不得写。

## 执行工作流（必须按序）

### 1. 读题与范围锁定

- 完整阅读 Issue 各节，列出：
  - 交付物文件清单（以「文件范围」为准，可增测试文件，勿扩大产品范围）
  - 统一命名中的类/方法/字段/API（照抄，不改名）
  - 验收标准 checklist
  - 前置依赖：若仓库中对应能力缺失，先最小补齐 **仅使本 Issue 可验收** 的缺口，或明确阻塞并停止；不要顺手做后续 Issue。
- 若 Issue 与简介第 4 节冲突：**以简介全局约定 + 更新后的 Issue 正文为准**，并在 PR/回复中注明冲突点。

### 2. 实现

- 严格按「实现步骤」推进；步骤未覆盖但验收需要的细节，以「统一命名」「输入上下文」补全。
- 优先复用现有模块；新增代码放在 Issue 指定路径。
- 保持小步提交逻辑清晰；不做与本 Issue 无关的重构、文档大改、依赖升级。
- 所有依赖 LLM 的路径实现规则/模板降级（若 Issue 要求）。
- 涉及 Mock：失败路径、异步回执、幂等键、CAS/乐观锁按 Issue 写明的契约实现。

### 3. 测试与验收

- 按「测试与验证」编写/更新自动化测试；命令能跑则跑，并把结果贴出。
- 逐条勾验收标准；任一条不满足则继续改，不得宣称完成。
- P0 涉及写回时：测试须证明分析内容未出站、处置写回路径被调用且幂等（不重复外呼）。

### 4. 交付说明

用简短结构输出：

1. **做了什么**（对应文件）
2. **验收对照**（逐条 ✅/❌）
3. **如何跑测试**
4. **未做 / 降级**（对照 Issue「降级策略」；P2 依赖未引入则说明）
5. **风险或需人工确认项**（例如 live Adapter 未证实的能力）

## 禁止清单

- 连接或实现未验证的真实 XDR/厂商 HTTP 客户端并当作完成
- 根据截图猜测并硬编码深信服私有 REST 路径 / operation_code / 鉴权细节
- 扩大 Issue 范围（顺手做 ISSUE-N+1 或提前做「真机兼容」）
- 用本地成功冒充外部（含 Mock）写回成功；或宣称已对接生产 XDR
- `TOOL_MODE=live` 失败时静默切 Mock 仍返回成功
- 引入方案未允许的新状态名、新写回字段、新 Agent 主名
- 把 Kafka/Neo4j 等做成 P0 必需
- 删除或弱化 Issue 要求的降级路径/人工门禁
- 在未要求时改 README / 大规模改无关 Issue 文档


```

## 最小自检（提交前默念）

- [ ] 文件路径 ⊆ Issue「文件范围」（+ 必要测试）
- [ ] 类名/API/枚举/字段 =「统一命名」
- [ ] 验收标准全部可演示或可自动验证
- [ ] 无分析内容写回；required 写回语义未被削弱
- [ ] 无范围蔓延；降级策略已实现或已声明不适用

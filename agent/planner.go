package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert       string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir           string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todos (preserved across wake-ups, written by you last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed from this: dispatch an intent only for the next step whose [prerequisite steps are complete / the fact it depends on already exists]; update the list with TodoWrite (mark steps already satisfied by a fact as completed). Don't re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = 摘要).
//	"goal"    — the human (via 主 agent 的 set_goals) added one OR MORE goals in a
//	            single call (Goals = 本次新增的目标文本，1+ 条；set_goals 支持批量).
//	"goal_deleted" — the human deleted a goal from 总览的目标管理 (Detail = 被删目标文本).
//	"goal_edited"  — the human edited a goal from 总览的目标管理 (OldGoal→NewGoal 文本).
//	"cancelled" — the human deleted intent IntentID (Detail = 删除原因). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" 专用：删除前捕获的意图摘要（真删除后节点已不存在，无法再查）
	Goals    []string // Kind=="goal" 专用：本次 set_goals 新增的目标文本（1 条或多条）
	OldGoal  string   // Kind=="goal_edited" 专用：修改前的目标文本
	NewGoal  string   // Kind=="goal_edited" 专用：修改后的目标文本
	Hints    []string // Kind=="hint" 专用：本次 add_hint 新增的提示文本（1 条或多条）
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[The actual change(s) that fired this round (look here first, then decide whether to add directions)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added a goal: %s —— a new goal to be met; add exploration directions for it accordingly (if there's no corresponding intent yet).", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d goals: %s —— all new goals to be met; add exploration directions one by one for each goal that has no corresponding intent yet.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added a strategic hint: %s —— it is attached to the exploration graph; adjust/add exploration directions accordingly (if there's no corresponding intent yet).", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d strategic hints: %s —— all attached to the exploration graph; adjust/add exploration directions one by one accordingly.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- The human deleted this goal: %s —— the goal has been removed; re-judge the remaining goals/directions accordingly (no need to dispatch intents for it anymore).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- The human edited a goal, from \"%s\" to \"%s\" —— adjust the exploration directions per the new goal (stop dispatching the old direction if it no longer applies).", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			// 意图内容优先用删除时捕获的 Summary（真删除后节点已不存在，intentSummary 查不到）。
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- Intent #%d was deleted by the user. Its content was: %s; the deletion reason was: %s. The intent has been deleted (will not run); re-plan accordingly.", ev.IntentID, sm, ev.Detail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) finished, with the conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; new fact ids produced by this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(Full details can be looked up again via node_detail / get_worker_output / list_findings.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12、#15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, ", ")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to fetch output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(this work has no output record yet)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " …(truncated; see get_worker_output for the full text)"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[This round's situation (graph_overview pre-fetched, identical to what calling that tool would return; call node_detail/list_facts etc. on demand for details)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间产物输出规约
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of an authorized penetration-testing system on a cybersecurity platform, woken frequently (woken whenever the graph changes). Your duties: read the situation → judge the goals → **only when there really is an uncovered new direction** add exploration intents. You are the planner, not the worker: everything you produce this round can only be [generating/clarifying intents] or [judging goals] — never do the actual work inside the plan.

Task goal: {{.Goal}}

**How many intents to produce this round (think this through first)**:
- **Hard floor (highest priority)**: as long as [the goal is not met] and [there is currently no open or running intent] (frontier_open=0 and running_intents empty), you [must] produce at least one intent that advances the goal this round —— when there is no running work to wait on and no queued direction, producing 0 intents = the task stalls; even if every known direction is only in recent_done, open a new one or re-dispatch one based on the done/exhausted/blocked judgment below.
- Beyond the hard floor, **producing 0 intents is a normal outcome, but it needs a legitimate reason** (not a default of "dispatching fewer is safer"): ① **Already covered** —— every direction you can think of is already handled by an intent still open/running (re-generating an existing intent in different words is a serious mistake); ② **Waiting on a dependency** —— the next step depends on the output of a currently-running work that hasn't come in yet (forcing a dispatch now would leave the downstream without its prerequisite and spinning idle; wait until the next wake-up with an updated graph before dispatching).
- Conversely: if there really is a new direction that is [uncovered and does not depend on running work], or the goal is unmet and there is still untested surface in scope, then dispatch —— don't treat 0 intents as a lazy default.

**Decision flow for each wake-up**:

1. **The full situation is already attached below this prompt** (it is the return of graph_overview; no need to call it again): task (original title + goal/root node), asset counts, goals + states, open/running/recent_done intents, sites_without_endpoints (sites with no endpoints, hinting at directions that may still need exploring), facts (count of exploration facts, a separate category from vulnerabilities), recent_facts ({id,summary,confidence?}).
   - **Scope**: exploration nodes (goals/intents/facts/findings) cover only this task; **the asset graph is globally shared** (one shared copy across tasks; asset counts are global within scope, not unique to this task) —— ignore assets unrelated to this task.
   - **Lineage**: every intent carries parents (upstream: the facts/intents it derived from) and yields (downstream: the facts/findings it produced); each recent_facts entry carries from_intent —— use these to understand "which facts came from which direction, and whether a new direction can be synthesized".
   - **Negative/doubtful observations** ("port closed / not injectable", etc. in recent_facts) are the worker's observations, not conclusions: before trusting one, call node_detail(id) to check the evidence —— only treat the direction as temporarily closed when the evidence is solid, confidence=observed, and the techniques are exhausted; when evidence is missing, it's just "looks like it / probed only once", or confidence=inferred, treat it as [not yet determined], and if it's in scope and no other intent covers it, by default dispatch a re-check intent to confirm or refute it (**re-check a given negative direction at most once**; if it's still negative after the re-check and the evidence is reasonable, respect that conclusion and dispatch no more).
   - **Only call these on demand when you need deeper detail**: list_facts (paginated, newest first, default 20, filterable by q, page with before, carries total/has_more), list_findings (all vulnerabilities), node_detail(id) (full evidence/details; the lists/recent_facts give only summaries), list_assets (pull: search by q, filter by type/company_id/task_id, paginated, or fetch directly by id/ids), asset_neighbors. The asset graph is global and shared —— don't pull it all by default.

2. **Judge the goals (core duty)**: the goals field already contains the goals and their states; for an unmet goal that some finding/fact has proven, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When the one you mark is exactly the last unfinished goal, the system automatically judges the whole task complete** —— closing out is driven solely by marking goals one by one with prove_goal; there is no other "one-click complete" mechanism.
   - ⚠️ **Quantitative acceptance check (never stamp approval early)**: when a goal contains a quantifiable condition (coverage reaches X%, capture N flags, obtain some privilege), before prove_goal you [must] verify the measured values in the graph_overview above (coverage.pct, the findings_total count, etc.): if the bar isn't met, prove_goal is [forbidden] —— dispatch intents to close the gap instead; do not mark it met early on the grounds that it's "basically achieved / the core is already taken". Example: required coverage 100% but measured coverage.pct=40% → not met, keep dispatching gap-filling intents.

3. **(Optional, opening only, extremely lightweight) probing to understand**: only when the graph has almost no fact yet (recent_facts essentially empty, the task just started) and the situation alone doesn't let you make the initial intent concrete, use Bash etc. to do a very small, read-only probe of the target (e.g. 1–2 curls to look at the home page/fingerprint). **The only legitimate output is a more precise one-sentence intent description** —— never the discovery/verification/exploitation of a vulnerability, nor the enumeration of endpoints/directories/parameters (those are the worker's job —— write them up as intents and dispatch them). Three hard boundaries:
   - If the graph already has facts produced by a worker (facts>0 / recent_facts non-empty) → [forbidden] to probe yourself again; base every judgment on existing facts, and this round's output can only be "dispatch new intents" or "finish"; to dig into a lead → dispatch an intent for a worker to investigate, not curl it yourself.
   - Even at the opening, probe ≤3 times at most and then stop, only to make the initial intent clear; the moment you notice you're "digging in to verify" rather than "quickly fixing a direction" (enumerating endpoints/directories one by one, trying ids one by one, decode chains, probing the same interface repeatedly, any injection/privilege-escalation/vulnerability testing or verification —— all the worker's heavy lifting), stop immediately and write it up as an intent.
   - Anything you can judge from existing facts/situation needs no probing at all.

4. **Decide which new directions to add**: **the "restraint" here means only [don't duplicate an existing intent], not "dispatch as few as possible"** —— while the goal is unmet, the default question is "to close in on the goal, what deeper, harder, still-uncovered approaches are there", not "can we wrap up". An intent is an [open exploration direction] (not a fixed type/menu); judge directions yourself from known facts, assets, and goals, and compare each against open + running + recent_done:
   - Already covered by open/running → don't generate it (it's being handled).
   - Appeared in recent_done → **first look at that intent's state (every entry carries it) to tell how it stopped, then decide**:
     · **done (ran to completion normally)**: already covered → don't re-dispatch it as-is; whether it's a dead end is judged by the fact conclusions it yielded, not by state; re-dispatch only when a [materially new mechanism] appears (new fact/asset/parameter/clearly different approach), and spell out in the summary how it differs from last time; rewording or "maybe it'll work if I try again" doesn't count —— retrying is forbidden.
     · **exhausted (budget spent, cut off halfway, only partial write-back) / blocked (model or network failure, essentially didn't explore)**: both ended badly midway with incomplete information —— first use get_worker_trace / get_worker_output to see how far it actually got and where it stuck, then pick from: close to a breakthrough but cut off by budget → dispatch "continue from where it left off"; a pure external failure that never ran (blocked often is) → re-dispatch the same direction directly; stuck at the same place every time → change the approach/direction. The basis is always the real progress in the trace, not state itself.
   - A brand-new direction with no intent coverage at all → generate it.
   - All known directions are covered by intents still open/running → don't generate, just finish (there is running/queued work; let it progress); but if only recent_done coverage remains, there is no open/running, and the goal is unmet → per the hard floor at the top you must open a new one or re-dispatch.
   - **Depth over coverage**: coverage is a lower bound / acceptance item, not the exploration goal itself; after finding a high-value entry point (one that may lead to RCE/privilege escalation/data exfiltration), prioritize dispatching intents to [drive that path all the way through], rather than spreading wide and shallowly probing asset by asset just to level up coverage.
   - **Keep the routes diverse, don't converge too early**: while the goal is unmet, if the existing intents all cluster on the same route/entry point and an [essentially different] uncovered direction exists (another entry surface / another asset class / another exploit chain), prioritize filling that divergent direction rather than adding synonymous intents on the same line (look at substantive difference, not wording); if that divergent direction is already covered by an existing intent, still don't generate. The ideal is 2–3 mechanistically different routes running in parallel (e.g. "attack via the upload chain" and "attack via auth bypass"), and only after one hands over [goal-approaching] evidence do you concentrate resources on it. **But diversity is always subordinate to the [operation constraints] at the top**: for an entry surface / port / host / operation excluded by the constraints, never generate an intent, even if it is essentially different.

   **Serial exploit chain: dispatch step by step, don't split it into parallel.** For a strongly-dependent serial chain (①→②→③, where each step depends on the actual output of the previous one): don't dispatch them all in parallel at once (a downstream step that can't get a not-yet-existing prerequisite will only duplicate/spin idle); use TodoWrite to record the whole chain as todos (one per step), and this round dispatch only the step whose "prerequisites are already met" (usually the first), then after it produces a fact, dispatch the next step at the next wake-up (the prompt will carry the todo list) and mark the satisfied ones completed. Don't split "the same thing" into two ("confirm the trigger point" and "trigger the trigger point" are the same step); only use multiple parallel intents for [parallel, mutually independent] dimensions (e.g. enumerating several unrelated endpoints).

5. **Submit**: use [one] add_intent call to batch-submit the new directions you filtered out (the intents array, at most the 4 highest-value ones; don't call it repeatedly one at a time):
   - **summary**: a one-sentence natural-language description of the direction (the full address of the test target + what to do + why), without forcing a fixed category; dedup relies mainly on comparing it against existing intents.
   - **asset_ids**: the ids of the target assets this direction will test/attack (pass them whenever you can, 0/1/many, from list_assets) —— whenever the direction centers on concrete assets (site/interface/parameter/host), be sure to pass them, for coverage dedup and to wire into the asset chain; pass them all when it spans multiple assets; leave empty only for pure global recon with no concrete asset.
   - **parent_ids**: which upstream nodes this direction was synthesized from (optional, 0/1/many) —— pass them all when several facts combine into one intent, pass the id when it derives from some upstream intent/finding, and leave empty for a brand-new top-level direction.

Don't duplicate, don't pad; but when the goal is unmet and there's an uncovered, deeper approach, dispatch it. Be concise, focused, efficient.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	// 资产覆盖度功能关闭时剔除 add_task_scope/list_untested_assets（不入 prompt）。
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）改放【本轮 user 输入】(见下方 input)，system
	// 只留静态规划正文。move-out 让 system 每轮稳定、更利于缓存；代价是若单轮变长，态势可能
	// 被 compaction 压缩（planner 单轮通常短，风险低）。situational 会拼进下方 input。
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】拼进本轮 user 输入(随 situational),让它只做最后
	// 目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task endgame wrap-up (special instruction for this round, overriding the normal planning flow above)]:" + resolveTaskTimeoutWrapup("planner")
	}
	// 本任务的工作目录 <workDir>/tasks/<taskID>，先建好。
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // 操作约束(若有)注入系统提示,框定探索边界
	}
	system, boundary := deferredSystem(sysBody, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert), // Bash 子命令默认走代理+信任 CA
		WorkingDir:            taskDir,                              // 本任务工作目录 <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:            compactionConfig(p.compactionWindow()),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// 态势（刚完成的意图 + 完整图）现在拼进本轮 user 输入（见下方 input）。user 里还有
	// 指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	// 开场白按「本轮有无具体变动」分两种：有变动 → 指向下方【实际变动】块；无变动
	// (心跳定时巡检 / hint / 恢复等) → 别谎称"图发生了变化",转而提示顺带复查在跑意图。
	lead := "There was just a concrete change (see [The actual change(s) that fired this round] below); plan the next step accordingly: "
	if len(triggers) == 0 {
		lead = "This round is a wake-up from a **scheduled sweep (heartbeat tick) / no concrete change signal** —— the graph may not have changed. While you're at it, re-check the running intents: use steer_work to correct one that has made no progress for a long time or has drifted, and kill_work to cut losses on one whose direction is entirely wrong; then judge the goals and decide whether to add directions: "
		// 心跳/无变动唤醒时,若全图已无任何 open 或 running 意图 → 探索已停摆(没 worker 在跑、
		// 也没排队方向)。明确告知 planner 并强制其本轮补出新方向,别只复查在跑意图后空转一轮。
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This round is a wake-up from a **scheduled sweep (heartbeat tick)**, and there is currently **no open or running intent at all** —— no worker is running and there is no queued direction, so exploration has stalled. You **must** produce one or more new intents this round that advance the goal and are **not duplicates** of existing intents in the graph (producing 0 intents is not allowed); first judge from the situation below whether the goal is met, and if not, add directions immediately: "
		}
	}
	input := lead + situational + "\n\nBased on the situation above, judge the goals. When a goal is [truly met] (the goal deliverable is in hand / the goal vulnerability is confirmed), mark them one by one with prove_goal. **Hard floor: as long as the goal is not yet met and there is currently no open or running intent (frontier_open=0 and running_intents empty), you must produce at least one intent that advances the goal this round —— there is no running work to wait on and no queued direction, so producing 0 intents = the task stalls. Only when there are already open/running intents making progress, or the goal is met, may you produce no new intent this round.**" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration 现在会在墙钟到点打断在跑工具并就地进收尾(在活 ctx 上),单轮卡死不再
	// 绕过收尾,无需外部硬 ctx 兜底。ctx 只承载 pause / kill / shutdown。
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}

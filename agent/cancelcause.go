package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "user paused the task",
		"The user paused the task via the task-control API (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was actively cancelled; in-flight intents return to the frontier(open) and are re-claimed and re-run from the start after the task resumes")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "orchestrator Agent paused the task",
		"The orchestrator Agent called the pause_task tool to pause this task. This Planner/Worker run was actively cancelled; in-flight intents return to the frontier(open) and are re-run after resume")
	AbortTaskDeleted = cause("task_deleted", "task was deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the delete barrier cancelled this task's running Planner, Worker and main Agent; this run's result will no longer be used")
	AbortPausedOnReload = cause("paused_on_reload", "backend restored the task's paused state",
		"On startup the backend restored the task's paused state from the persisted database state. This run was cancelled; normally no Agent is running during the recovery phase")
	AbortGoalMet = cause("goal_met", "planner judged the task goal met",
		"The planner judged the task goal met and set the task to done, then cancelled the still-running Workers; those intents are marked stopped rather than failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "the wait for timeout settlement has run out",
		"After the task hit its timeout it waited for running Workers to settle gracefully, but the 90-second drain grace period was still not enough, so a hard cancel was performed; intents are marked exhausted, and facts and assets already written during the settlement phase are kept")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "planner terminated this intent",
		"The planner called kill_work to actively terminate this intent, usually meaning the direction went off track or has no further value; the intent is marked stopped and will not be re-claimed automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "user paused this Worker intent",
		"The user paused the running Worker. This call was cancelled and the intent turns to paused; all registered intents, facts, findings and activity records are kept, and it is re-run from the start after resume")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "user deleted this Worker intent",
		"The user deleted the running Worker. This call was cancelled; after the Worker exits the write region, the server handles the intent per the user's chosen delete mode — a soft delete only marks it deleted and keeps all output, while a hard delete cascades and removes the intent and the downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker finished normally and released its context",
		"The Worker finished normally and the engine released its context resources in detachWork. This is not a run interruption; if it appears in an interruption message, it means the cancel and the wrap-up events raced")
	AbortPausedRaceGuard = cause("paused_race_guard", "refused to start a new run while the task is paused",
		"While the task is paused, the engine refuses to issue a new execution context, to prevent a race between claim and pause from letting a Worker keep starting; claimed intents return to the frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "user stopped this conversation turn",
		"The user clicked stop, actively aborting this main Agent or conversation Agent run. Activity records already produced are kept, and you can continue sending the next message")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "task paused and aborted the main Agent conversation",
		"When the user paused the task, the running main Agent conversation was cancelled along with it. Activity records already produced are kept; this turn's message is not replayed automatically after the task resumes")
	AbortChatTurnFinished = cause("chat_turn_finished", "this conversation turn finished normally and released its context",
		"This conversation turn finished normally and the server is releasing the turn's context resources. This is not a run interruption; if it appears in an interruption message, it means the cancel and the wrap-up events raced")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating or shutting down. All running Agents are cancelled; after restart, leftover running intents are reset to open and re-run")
	AbortRunHardTimeout = cause("run_hard_timeout", "the single-run hard-timeout backstop fired",
		"A single run exceeded its soft wall-clock budget plus the extra grace period, meaning a model request or some tool has not returned for a long time, so normal turn-boundary settlement could not run. Focus on the last tool call that had not returned before the interruption")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "upstream context reached its deadline",
			"The upstream context reached its deadline, but the setter did not attach a named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "canceller attached no named cause",
			"The upstream context was cancelled, but the canceller did not attach a named cause via context.WithCancelCause; please register the cause in agent/cancelcause.go and wire it into that cancellation point", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}

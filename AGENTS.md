<!-- naveax-ci-execution-policy:v1 -->
# Agent Execution and CI Policy

This policy is mandatory for every AI agent, automation, and coding assistant working in this repository.

## CI dispatch invariant
One logical validation target may have at most one active GitHub Actions run. Before every workflow dispatch, rerun, retry, or CI-triggering change, inspect existing runs and build a logical key from repository + workflow + ref/branch + HEAD commit SHA + normalized workflow inputs. If an equivalent run is queued, waiting, pending, requested, or in progress, do not create another run. Track the existing run ID instead. Never use reruns or repeated dispatches as a polling mechanism. If the same logical target already completed successfully, do not rerun it unless the code, inputs, environment requirement, or validation objective materially changed.

## Retry budget
For the same commit + workflow + normalized inputs, the automatic dispatch budget is 1. A second execution is allowed only for a concrete infrastructure failure, runner failure, or demonstrated flaky external dependency, and the reason must be recorded. Prefer rerunning only the failed job when possible. Never create empty/no-op commits or meaningless file changes merely to retrigger CI. If dispatch frequency rises unexpectedly, stop all new dispatches and diagnose the scheduler, trigger configuration, or agent loop before continuing.

## Work scheduler
CI is an asynchronous dependency, not the main work loop. Maintain RUNNING, READY, BLOCKED, and DONE work states. When a CI-dependent task becomes BLOCKED, immediately switch to another independent READY task. Normal target: up to 10 active independent workstreams and up to 50 queued READY work items, subject to repository safety and dependency constraints. Do not duplicate work merely to fill the queue. Useful work while CI runs includes source inspection, static analysis, tests, documentation, review, dependency analysis, security review, benchmark preparation, log analysis, and preparing the next patch without dispatching another equivalent run.

## CI broker rule
Only the coordinating agent/workstream may authorize GitHub Actions dispatches. Parallel workers must report validation needs to the coordinator instead of independently starting Actions runs. Before creating a new CI run after a failure: collect the complete relevant failure evidence, determine the root cause, make one coherent patch, then dispatch at most one validation run for the new commit.

## Workflow authoring
When adding or editing GitHub Actions workflows, preserve existing semantics and add an appropriate top-level concurrency policy when one is absent. For ordinary branch-scoped validation, prefer a group derived from workflow + ref and keep `cancel-in-progress: false` unless the workflow is explicitly safe and intended to replace older runs.

The objective is bounded CI concurrency, zero duplicate validation for the same logical target, and continuous useful progress while external jobs are running.

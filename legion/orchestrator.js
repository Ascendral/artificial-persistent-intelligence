/**
 * LEGION Orchestrator — Core Engine
 *
 * The central brain. Receives a goal, decomposes into tasks, delegates to models,
 * runs every action through CORD before execution, and delivers the final product.
 *
 * Phase 1 model squad:
 *   Claude   — Lead Architect (decompose, spec, review)
 *   Executor — Local Builder  (write files, run commands)
 *
 * All outputs are validated by CORD before any file is written or command is run.
 */

const path = require("path");
const {
  evaluateProposal,
  validatePlan: cordValidatePlan,
} = require("../cord/cord");
const {
  startSession,
  recordTask,
  summarizeSession,
  REPO_ROOT,
} = require("./session");
const claude = require("./models/claude");
const executor = require("./models/executor");

const MAX_REVISIONS = 2; // Max times to retry a rejected task

class Orchestrator {
  constructor(options = {}) {
    this.options = options;
    this.session = null;
    this.completedOutputs = [];
  }

  // ─── Session Management ────────────────────────────────────────────────────

  /**
   * Initialize session and set CORD intent lock.
   */
  async startSession(goal) {
    this.session = startSession(goal, this.options.scope || {});
    return this.session;
  }

  // ─── CORD Enforcement ──────────────────────────────────────────────────────

  /**
   * Run a proposal through CORD before execution.
   * Logs the result. Returns decision.
   *
   * @param {object} proposal   - { text, path, networkTarget, grants }
   * @param {string} taskId     - For logging context
   * @returns {object}          - { decision, score, reasons, log_id }
   */
  validate(proposal, taskId = "unknown") {
    const result = evaluateProposal({
      proposal: proposal.text || "",
      text: proposal.text || "",
      path: proposal.path || null,
      networkTarget: proposal.networkTarget || null,
      grants: proposal.grants || [],
      // Orchestrator handles intent alignment via decomposition.
      // Pass empty sessionIntent so CORD doesn't double-score drift
      // on internal bookkeeping proposals — it checks injection/exfil/privilege instead.
      sessionIntent: "",
    });

    const icon =
      result.decision === "ALLOW"
        ? "✅"
        : result.decision === "CONTAIN"
          ? "🟡"
          : result.decision === "CHALLENGE"
            ? "🟠"
            : "🚫";

    console.log(
      `   ${icon} CORD [${taskId}]: ${result.decision} ` +
        `(score: ${result.score.toFixed(2)}) ` +
        `${result.reasons.length ? `— ${result.reasons.join(", ")}` : ""}`,
    );

    return result;
  }

  // ─── Goal Decomposition ────────────────────────────────────────────────────

  /**
   * Use Claude to decompose the goal into atomic tasks.
   */
  async decompose(goal) {
    // Get brief repo context for Claude
    const repoContext = this._getRepoContext();
    const tasks = await claude.decompose(goal, repoContext);
    this.session.tasks = tasks;
    return tasks;
  }

  _getRepoContext() {
    try {
      const { execSync } = require("child_process");
      const files = execSync(
        "git ls-files --others --cached --exclude-standard",
        {
          cwd: REPO_ROOT,
          encoding: "utf8",
          timeout: 5000,
        },
      );
      const lines = files.trim().split("\n").slice(0, 30).join("\n");
      return `Repository files (sample):\n${lines}`;
    } catch {
      return "";
    }
  }

  // ─── Task Execution ────────────────────────────────────────────────────────

  /**
   * Execute a single task through the full LEGION pipeline:
   * Brief → (if executor) CORD validate file writes → Execute → CORD validate output → Review → Approve/Revise
   *
   * CORD only fires on real execution (file writes, shell commands).
   * Claude analysis/review/spec tasks are thinking-only — no CORD gate needed.
   */
  async executeTask(task, revisionCount = 0) {
    console.log(`\n─────────────────────────────────────`);
    console.log(`📋 Task [${task.id}]: ${task.description}`);
    console.log(`   Model: ${task.assignedModel} | Type: ${task.type}`);
    console.log(`─────────────────────────────────────`);

    // Step 1: Generate task brief (Claude writes spec + code)
    const brief = await claude.generateBrief(task, this.session.goal);

    const filePaths = task.filePaths || [];

    // Step 2: CORD gates only executor tasks with actual file writes
    if (task.assignedModel === "executor" && filePaths.length > 0) {
      for (const fp of filePaths) {
        const cordResult = this.validate(
          {
            text: `git commit -m "legion: write ${fp}"`,
            path: path.join(REPO_ROOT, fp),
          },
          task.id,
        );
        if (cordResult.decision === "BLOCK") {
          console.log(`\n🚫 CORD BLOCK on "${task.id}" — halting task.`);
          recordTask(this.session, task, { decision: "BLOCK", cordResult });
          return { taskId: task.id, status: "BLOCKED", cordResult };
        }
        if (cordResult.decision === "CHALLENGE") {
          const proceed = await this._challengeUser(task, cordResult);
          if (!proceed) {
            recordTask(this.session, task, {
              decision: "CHALLENGE_REJECTED",
              cordResult,
            });
            return {
              taskId: task.id,
              status: "CHALLENGE_REJECTED",
              cordResult,
            };
          }
        }
      }
    }

    // Step 3: Execute — write files / run commands (executor tasks only)
    let writeResults = [];
    if (task.assignedModel === "executor" && filePaths.length > 0) {
      console.log(`\n⚙️  Executor: Writing files...`);
      writeResults = executor.executeBrief(brief, task);
    }

    // Step 4: CORD validates the written output
    if (writeResults.length > 0) {
      for (const wr of writeResults) {
        const outCord = this.validate(
          { text: `git add ${wr.filePath}`, path: wr.filePath },
          `${task.id}:output`,
        );
        if (outCord.decision === "BLOCK") {
          console.log(`\n🚫 CORD BLOCK on output — reverting "${task.id}"`);
          try {
            require("fs").unlinkSync(wr.filePath);
          } catch {}
          return { taskId: task.id, status: "OUTPUT_BLOCKED", outCord };
        }
      }
    }

    // Step 5: Claude reviews the output
    const codeContent = brief;
    const review = await claude.reviewCode(
      codeContent,
      task,
      this.session.goal,
    );

    if (review.approved) {
      console.log(`\n✅ Review passed: ${review.feedback}`);
      const output = {
        taskId: task.id,
        status: "COMPLETE",
        brief,
        writeResults,
        review,
        summary: review.feedback,
      };
      this.completedOutputs.push(output);
      recordTask(this.session, task, {
        decision: "ALLOW",
        review,
        writeResults,
      });
      return output;
    } else {
      console.log(`\n🔄 Review rejected: ${review.feedback}`);
      console.log(`   Issues: ${review.issues.join("; ")}`);

      if (revisionCount < MAX_REVISIONS) {
        console.log(`   Retrying (${revisionCount + 1}/${MAX_REVISIONS})...`);
        // Inject revision request back into task description for next attempt
        const revisedTask = {
          ...task,
          description: `${task.description}\n\nREVISION REQUIRED: ${review.revisionRequest || review.issues.join("; ")}`,
        };
        return this.executeTask(revisedTask, revisionCount + 1);
      } else {
        console.log(`   Max revisions reached — marking as incomplete.`);
        recordTask(this.session, task, { decision: "CONTAIN", review });
        return { taskId: task.id, status: "REVISION_LIMIT", review };
      }
    }
  }

  // ─── Human-in-the-Loop ────────────────────────────────────────────────────

  /**
   * CHALLENGE mode — pause and request human confirmation.
   * In CLI mode, prompts the user. Returns true to proceed, false to abort.
   */
  async _challengeUser(task, cordResult) {
    console.log(`\n🟠 CORD CHALLENGE — Human confirmation required`);
    console.log(`   Task: ${task.id}`);
    console.log(`   Score: ${cordResult.score.toFixed(2)}`);
    console.log(`   Reasons: ${cordResult.reasons.join(", ")}`);

    if (this.options.autoApproveChallenge) {
      console.log(`   Auto-approving (autoApproveChallenge=true)`);
      return true;
    }

    // In non-interactive mode, block by default
    if (!process.stdin.isTTY) {
      console.log(`   Non-interactive mode — blocking challenged action`);
      return false;
    }

    const readline = require("readline");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    return new Promise((resolve) => {
      rl.question(`   Proceed? (y/N): `, (answer) => {
        rl.close();
        resolve(answer.toLowerCase() === "y");
      });
    });
  }

  // ─── Main Orchestration Loop ───────────────────────────────────────────────

  /**
   * Full LEGION run: start session → decompose → execute all tasks → summarize.
   *
   * @param {string} goal   - Human-provided goal
   * @returns {object}      - Session summary
   */
  async run(goal) {
    console.log("\n╔═══════════════════════════════════════╗");
    console.log("║        LEGION AI — STARTING           ║");
    console.log("╚═══════════════════════════════════════╝");

    // 1. Initialize session + CORD intent lock
    await this.startSession(goal);

    // 2. Decompose goal into tasks
    console.log("\n📐 Phase 1: Goal Decomposition");
    const tasks = await this.decompose(goal);

    console.log(`\n📋 Task Plan:`);
    tasks.forEach((t, i) => {
      console.log(
        `   ${i + 1}. [${t.assignedModel.toUpperCase()}] ${t.description}`,
      );
    });

    // 2b. Plan-level validation — check aggregate task list for cross-task threats
    console.log("\n🔍 Phase 1b: Plan-Level Validation");
    const planCheck = cordValidatePlan(tasks, goal);
    const planIcon =
      planCheck.decision === "ALLOW"
        ? "✅"
        : planCheck.decision === "CONTAIN"
          ? "🟡"
          : planCheck.decision === "CHALLENGE"
            ? "🟠"
            : "🚫";
    console.log(
      `   ${planIcon} CORD PLAN: ${planCheck.decision} ` +
        `(score: ${planCheck.score.toFixed(2)}, tasks: ${planCheck.taskCount}) ` +
        `${planCheck.reasons.length ? `— ${planCheck.reasons.join(", ")}` : ""}`,
    );

    if (planCheck.decision === "BLOCK") {
      console.log(`\n🚫 CORD PLAN BLOCK — aggregate plan rejected`);
      const summary = summarizeSession(this.session);
      return {
        summary: { ...summary, blocked: true },
        results: [],
        narrative: planCheck.reasons.join("; "),
      };
    }
    if (planCheck.decision === "CHALLENGE") {
      const proceed = await this._challengeUser(
        {
          id: "PLAN_AGGREGATE",
          description: `Aggregate plan (${tasks.length} tasks)`,
        },
        planCheck,
      );
      if (!proceed) {
        const summary = summarizeSession(this.session);
        return {
          summary: { ...summary, blocked: true },
          results: [],
          narrative: "Plan challenge rejected by user",
        };
      }
    }

    // 3. Execute tasks in order (respecting dependencies)
    console.log("\n🚀 Phase 2: Task Execution");
    const results = [];
    for (const task of tasks) {
      // Check dependencies
      const depsComplete = (task.dependencies || []).every((depId) =>
        this.completedOutputs.some(
          (o) => o.taskId === depId && o.status === "COMPLETE",
        ),
      );

      if (!depsComplete) {
        console.log(`\n⏭️  Skipping "${task.id}" — dependencies not met`);
        results.push({ taskId: task.id, status: "SKIPPED_DEPS" });
        continue;
      }

      const result = await this.executeTask(task);
      results.push(result);

      // Hard stop on BLOCK
      if (result.status === "BLOCKED") {
        console.log(`\n🚫 Session halted — CORD BLOCK on task "${task.id}"`);
        break;
      }
    }

    // 4. Final summary
    console.log("\n📊 Phase 3: Session Summary");
    const summary = summarizeSession(this.session);

    let narrative = "";
    if (this.completedOutputs.length > 0) {
      narrative = await claude.generateSummary(
        this.session,
        this.completedOutputs,
      );
    }

    console.log("\n╔═══════════════════════════════════════╗");
    console.log("║        LEGION AI — COMPLETE           ║");
    console.log("╚═══════════════════════════════════════╝");
    console.log(`\n   Session:   ${summary.sessionId}`);
    console.log(`   Duration:  ${summary.durationSeconds}s`);
    console.log(
      `   Completed: ${summary.tasksCompleted}/${summary.tasksTotal} tasks`,
    );
    console.log(`   Blocked:   ${summary.tasksBlocked} tasks`);
    if (narrative) {
      console.log(`\n${narrative}`);
    }

    return { summary, results, narrative };
  }
}

module.exports = { Orchestrator };

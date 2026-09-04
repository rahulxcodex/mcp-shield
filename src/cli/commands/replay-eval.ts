import * as fs from 'fs';
import { SecurityReplayEngine, ReplayInputEvent } from '../../security/replay/security-replay-engine';

export class ReplayEvalCommand {
  public static async run(logPath?: string): Promise<void> {
    if (!logPath) {
      console.error('Usage: mcp-shield replay-eval <path-to-events.jsonl>');
      process.exit(1);
    }

    if (!fs.existsSync(logPath)) {
      console.error(`Error: File not found: ${logPath}`);
      process.exit(1);
    }

    console.log(`\n▶️  EXECUTING SECURITY REPLAY EVALUATION: ${logPath}\n`);

    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter((l) => l.trim().length > 0);
    const events: ReplayInputEvent[] = [];

    for (let i = 0; i < lines.length; i++) {
      try {
        const raw = JSON.parse(lines[i]);
        events.push({
          eventId: raw.eventId || `evt-${i + 1}`,
          timestamp: raw.timestamp || Date.now(),
          toolName: raw.toolName || raw.tool || 'generic_tool',
          rawArgs: raw.rawArgs || raw.arguments || raw.args || {},
          originalDecision: {
            action: raw.originalDecision?.action || raw.action || 'ALLOW',
            riskScore: raw.originalDecision?.riskScore ?? raw.riskScore ?? 0.1
          },
          originalLatencyUs: raw.originalLatencyUs || raw.latencyUs || 200,
          groundTruthLabel: raw.groundTruthLabel || raw.label
        });
      } catch (err: any) {
        console.warn(`[WARN] Skipping malformed line ${i + 1}: ${err.message}`);
      }
    }

    const engine = new SecurityReplayEngine();
    const report = await engine.replayEvents(events);

    console.log('========================================================');
    console.log('🛡️  SECURITY REPLAY EVALUATION REPORT (v2.0.0 ENGINE)');
    console.log('========================================================');
    console.log(`Total Replayed Events:       ${report.totalEvents}`);
    console.log(`Decisions Changed:           ${report.decisionsChanged}`);
    console.log(`Decisions Unchanged:         ${report.decisionsUnchanged}`);
    console.log(`New Blocks Triggered:        ${report.newBlocksCount}`);
    console.log(`New Allows Granted:          ${report.newAllowsCount}`);
    console.log(`False Positive Delta:        ${report.falsePositiveDelta}`);
    console.log(`Average Risk Score Delta:    ${report.averageRiskDelta >= 0 ? '+' : ''}${report.averageRiskDelta}`);
    console.log(`Average Latency Delta:       ${report.averageLatencyDeltaUs >= 0 ? '+' : ''}${report.averageLatencyDeltaUs} µs`);
    console.log('========================================================\n');

    if (report.decisionsChanged > 0) {
      console.log('Top Changed Decisions:');
      for (const diff of report.comparisons.filter((c) => c.actionChanged).slice(0, 5)) {
        console.log(`- [${diff.toolName}] ${diff.oldAction} -> ${diff.newAction} (risk: ${diff.oldRiskScore} -> ${diff.newRiskScore})`);
      }
      console.log('');
    }
  }
}

import { SecuritySession } from '../session';
import { COWFileSystem } from '../../sandbox/cow-fs';
import { PromptBridge } from '../../tui/prompt-bridge';
import { RegisteredTool } from '../../security/capabilities';

export interface SecretRestorationResult {
  restoredParams: any;
  restored: boolean;
  scope?: string;
}

export class ExecutionBroker {
  constructor(
    private session: SecuritySession,
    private cowFs: COWFileSystem
  ) {}

  public getCowFs(): COWFileSystem {
    return this.cowFs;
  }

  public async handleSandboxExecution(
    toolName: string,
    rawArgs: Record<string, any>,
    requestId: any,
    onLog: (event: any) => void
  ): Promise<{ handled: boolean; success?: boolean; error?: string }> {
    const targetPath = rawArgs.path || rawArgs.file || rawArgs.filename || rawArgs.filepath || rawArgs.target;
    const content = rawArgs.content || rawArgs.text || rawArgs.data;

    if (targetPath && typeof content === 'string') {
      const staged = this.cowFs.stageWrite(targetPath, content);
      onLog({ type: 'cow_staged', toolName, payload: staged });

      const result = await PromptBridge.ask(
        `Sandbox Write: ${toolName}`,
        `Tool: ${toolName}\nTarget: ${targetPath}`,
        'HIGH',
        staged.diff
      );

      if (result.action === 'approve') {
        this.cowFs.commit(staged.stagingPath, staged.absoluteOriginalPath, staged.originalIdentity);
        onLog({ type: 'cow_committed', toolName, payload: { path: staged.absoluteOriginalPath } });
        return { handled: true, success: true };
      } else {
        this.cowFs.discard(staged.stagingPath);
        onLog({ type: 'cow_discarded', toolName });
        return { handled: true, success: false, error: 'USER DENIED: Staged file changes rejected.' };
      }
    } else {
      onLog({
        type: 'sandbox_pass_through',
        toolName,
        reason: 'Tool has no filesystem write parameters (path/content); allowing non-mutating execution.'
      });
      return { handled: false };
    }
  }

  public restoreSecretsForTool(
    toolName: string,
    params: any,
    registeredTool?: RegisteredTool
  ): SecretRestorationResult {
    const isTrusted = registeredTool?.trustLevel === 'TRUSTED';
    const hasDeclaredSecretAccess = !!registeredTool?.declaredCapabilities?.secretAccess;

    if (isTrusted && hasDeclaredSecretAccess) {
      const secretScope = `${this.session.serverIdentity}:${toolName}`;
      const restorationContext = {
        serverIdentity: this.session.serverIdentity,
        toolName,
        sessionId: this.session.sessionId,
        scope: secretScope
      };

      const payloadStr = JSON.stringify(params);
      let restoredStr = this.session.sanitizer.restore(payloadStr, restorationContext);
      if (restoredStr === payloadStr) {
        restoredStr = this.session.sanitizer.restore(payloadStr, {
          serverIdentity: this.session.serverIdentity,
          sessionId: this.session.sessionId
        });
      }

      return {
        restoredParams: JSON.parse(restoredStr),
        restored: true,
        scope: secretScope
      };
    }

    return {
      restoredParams: params,
      restored: false
    };
  }
}

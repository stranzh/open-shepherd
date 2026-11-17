import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface ShepherdEvent {
  timestamp: string;
  source: 'vscode' | 'neovim' | 'agent-hook';
  event_type: string;
  severity: 'info' | 'warn' | 'high' | 'critical';
  details: Record<string, unknown>;
}

const DEFAULT_LOG_PATH = path.join(os.homedir(), '.open-shepherd', 'events.jsonl');

export function emitEvent(
  event: Omit<ShepherdEvent, 'timestamp'>,
  options?: { logPath?: string; webhookUrl?: string }
): void {
  const payload: ShepherdEvent = {
    timestamp: new Date().toISOString(),
    ...event,
  };

  const logPath = options?.logPath || process.env.OPEN_SHEPHERD_LOG || DEFAULT_LOG_PATH;
  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.appendFileSync(logPath, JSON.stringify(payload) + '\n', 'utf8');
  } catch {
    // Best-effort local logging; never crash the IDE host.
  }

  const webhookUrl = options?.webhookUrl || process.env.OPEN_SHEPHERD_WEBHOOK;
  if (webhookUrl) {
    fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).catch(() => {});
  }
}

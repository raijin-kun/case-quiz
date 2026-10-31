// Claude Code hook: runs scripts/check-html.mjs
//  - PreToolUse(Bash): before any `git commit`, over all tracked HTML. Blocks the commit on findings.
//  - PostToolUse(Edit|Write): on the edited .html file. Reports findings back so they get fixed in the same turn.
import { spawnSync } from 'node:child_process';
const root = process.env.CLAUDE_PROJECT_DIR || process.cwd();
let raw = '';
process.stdin.on('data', d => raw += d).on('end', () => {
  let ev = {}; try { ev = JSON.parse(raw); } catch {}
  const input = ev.tool_input || {};
  let args;
  if (ev.hook_event_name === 'PreToolUse' && /\bgit\b[^|;&]*\bcommit\b/.test(input.command || '')) args = [];
  else if (ev.hook_event_name === 'PostToolUse' && /\.html$/i.test(input.file_path || '')) args = [input.file_path];
  else process.exit(0);
  const r = spawnSync('node', [`${root}/scripts/check-html.mjs`, ...args], { cwd: root, encoding: 'utf8' });
  if (r.status === 0) process.exit(0);
  process.stderr.write((args.length ? 'Security check failed for the file you just edited. Fix before continuing:\n' : 'Blocked git commit: security checks failed.\n') + r.stderr + r.stdout);
  process.exit(2);
});

# case-quiz

Static HTML pages, no build step: `index.html` (legal cases quiz) and `survival-guides.html` (React + Three.js survival build guides, also published as a claude.ai artifact).

## Security rules (enforced by `scripts/check-html.mjs`)

- External scripts only from cdnjs, jsDelivr `/npm/` or unpkg, pinned to an exact version, with `integrity="sha384-…"` and `crossorigin="anonymous"`. Import maps carry an `integrity` map for every module the page imports.
- Bumping a library version means recomputing its hash: `scripts/sri.sh <url>`.
- Stylesheets only from Google Fonts; everything else inline. No `http://`, no `javascript:` hrefs.
- No `eval`, `new Function`, `document.write`, or string timers. `innerHTML` only for hardcoded templates, marked `/* static */` on the same line; anything touching user input uses `textContent` or DOM APIs.
- No secrets in the repo. CI runs gitleaks.

## Where the checks run

- `node scripts/check-html.mjs` locally; run it before committing.
- Git pre-commit hook: enable once per clone with `git config core.hooksPath .githooks`.
- Claude Code hooks (`.claude/settings.json`): block `git commit` on findings and report findings after any HTML edit.
- GitHub Actions `security` workflow on every push and pull request. After the first run, require it on `main`:
  `gh api -X PUT repos/raijin-kun/case-quiz/branches/main/protection --input - <<< '{"required_status_checks":{"strict":true,"contexts":["security"]},"enforce_admins":false,"required_pull_request_reviews":null,"restrictions":null}'`
- Run `/security-review` before opening a pull request.

After editing `survival-guides.html`, republish the artifact with the same file path so the public URL updates.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import http from 'http';

// ── Dockerfile parser ────────────────────────────────────────────────────
// Dockerfile syntax is simple enough (one instruction per logical line,
// backslash continuations, # comments) that a hand-written line-based parser
// is the right tool, same philosophy as the rest of this portfolio
// (regex-safety-audit-mcp hand-writes its own AST rather than pulling in a
// library). Builds a flat list of { instruction, args, raw, line, stage }
// entries -- `stage` is the 0-based index of the FROM block this instruction
// belongs to, since multi-stage builds reset most safety assumptions (a
// USER in stage 0 says nothing about stage 1).

function parseDockerfile(src) {
  const rawLines = src.split(/\r?\n/);
  const logical = [];
  let buf = '';
  let bufStartLine = null;
  for (let i = 0; i < rawLines.length; i++) {
    const lineNo = i + 1;
    let line = rawLines[i];
    if (buf === '' && /^\s*#/.test(line)) continue; // pure comment line
    if (buf === '' && line.trim() === '') continue;
    if (bufStartLine === null) bufStartLine = lineNo;
    if (/\\\s*$/.test(line)) {
      buf += line.replace(/\\\s*$/, ' ');
    } else {
      buf += line;
      logical.push({ text: buf.trim(), line: bufStartLine });
      buf = '';
      bufStartLine = null;
    }
  }
  if (buf.trim()) logical.push({ text: buf.trim(), line: bufStartLine });

  const instructions = [];
  let stage = -1;
  for (const { text, line } of logical) {
    const m = /^(\w+)\s+(.*)$/s.exec(text);
    if (!m) continue;
    const instruction = m[1].toUpperCase();
    const args = m[2];
    if (instruction === 'FROM') stage++;
    instructions.push({ instruction, args, raw: text, line, stage: Math.max(stage, 0) });
  }
  return instructions;
}

// ── Checks ───────────────────────────────────────────────────────────────

function findMissingUser(instructions, findings) {
  // Matches real Dockerfile linter convention (hadolint's DL3002 checks only
  // the LAST USER instruction, not every stage): a `docker build` with no
  // --target produces the LAST stage as the final image, and multi-stage
  // builds exist specifically so earlier stages' root-run build steps never
  // ship -- only what the final stage's runtime user is matters for the
  // container that actually gets deployed. Checking every intermediate
  // builder stage would flag the exact pattern Docker's own docs recommend.
  const stages = [...new Set(instructions.filter((i) => i.instruction === 'FROM').map((i) => i.stage))];
  const finalStage = Math.max(...stages);
  const stageInstrs = instructions.filter((i) => i.stage === finalStage);
  const fromInstr = stageInstrs.find((i) => i.instruction === 'FROM');
  const userInstrs = stageInstrs.filter((i) => i.instruction === 'USER');
  const lastUser = userInstrs[userInstrs.length - 1];
  if (!lastUser) {
    findings.push({
      severity: 'warning', kind: 'missing_user', location: `final stage (FROM at line ${fromInstr?.line})`,
      why: 'No USER instruction in the final build stage -- every RUN/CMD/ENTRYPOINT in the image that actually ships runs as root (image default) by design, not by explicit choice. A container escape or compromised dependency in the running container has full root privileges inside it.',
      fix: 'Add `USER <non-root-name>` after creating the user (e.g. `RUN adduser -D appuser` then `USER appuser`), placed after any step that genuinely needs root (installing packages, chown-ing files) and before the app actually runs.',
    });
  } else if (/^root$/i.test(lastUser.args.trim())) {
    findings.push({
      severity: 'warning', kind: 'explicit_root_user', location: `line ${lastUser.line}`,
      why: 'The final USER instruction in the shipped stage is root -- same effective risk as no USER instruction at all, just stated on purpose instead of by omission.',
      fix: 'Switch to a non-root user for the steps that run the actual application.',
    });
  }
}

// Common secret-shaped env/build-arg names. A value baked in via ENV or ARG
// (without --secret mount) lands permanently in an image layer and is
// readable via `docker history --no-trunc` or by anyone who pulls the image,
// even if a LATER layer overwrites or unsets it.
const SECRET_NAME_RE = /^(.*_)?(API_KEY|APIKEY|SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|AUTH_TOKEN|DATABASE_URL|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|STRIPE_.*_KEY)(_.*)?$/i;
const PLACEHOLDER_VALUE_RE = /^(<.*>|\$\{.*\}|changeme|change_me|your[-_].*|xxx+|placeholder|example|todo|none|null|""|'')$/i;

function findBakedSecrets(instructions, findings) {
  for (const instr of instructions) {
    if (instr.instruction !== 'ENV' && instr.instruction !== 'ARG') continue;
    // ENV/ARG can declare multiple KEY=VALUE pairs on one line, or the legacy
    // "ENV KEY value" single-pair form.
    const pairs = [];
    const kvMulti = instr.args.match(/([A-Za-z_][A-Za-z0-9_]*)=(\S+|"[^"]*"|'[^']*')/g);
    if (kvMulti) {
      for (const p of kvMulti) {
        const eq = p.indexOf('=');
        pairs.push([p.slice(0, eq), p.slice(eq + 1)]);
      }
    } else {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$/.exec(instr.args);
      if (m) pairs.push([m[1], m[2]]);
    }
    for (const [key, rawVal] of pairs) {
      if (!SECRET_NAME_RE.test(key)) continue;
      const val = rawVal.replace(/^["']|["']$/g, '');
      if (PLACEHOLDER_VALUE_RE.test(val)) continue;
      if (instr.instruction === 'ARG' && val === '') continue; // ARG with no default -- value supplied at build time, not baked into the Dockerfile itself
      findings.push({
        severity: 'critical', kind: 'baked_secret', location: `line ${instr.line}`,
        variable: key, instruction: instr.instruction,
        why: `${instr.instruction} ${key}=... bakes what looks like a real credential into the image layer history permanently -- visible via \`docker history --no-trunc <image>\` or to anyone who pulls the image, even if a later layer unsets it. This is true even for private registries and even after the image is deleted from the registry if it was ever pulled/cached anywhere.`,
        fix: 'Use a build secret instead: `RUN --mount=type=secret,id=' + key.toLowerCase() + ' ...` (BuildKit) reads it into the build environment without persisting it in any layer, or pass it at container runtime via `docker run -e` / an orchestrator secret instead of baking it at build time.',
      });
    }
  }
}

function findCurlPipeShell(instructions, findings) {
  for (const instr of instructions) {
    if (instr.instruction !== 'RUN') continue;
    const cmd = instr.args;
    // curl/wget piped into a shell -- runs whatever that URL currently
    // serves, unpinned and unverified, at build time.
    const re = /(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b/i;
    if (re.test(cmd)) {
      findings.push({
        severity: 'critical', kind: 'curl_pipe_shell', location: `line ${instr.line}`,
        why: 'Piping curl/wget directly into a shell executes whatever that remote script contains at the moment the image builds, with no integrity check -- if the remote host is compromised, rate-limited into serving something else, or the script itself gets a malicious update, every future build silently pulls it in.',
        fix: 'Download to a file first, verify its checksum/signature against a value pinned in the Dockerfile, then execute: `curl -fsSL -o install.sh https://...\\n&& echo "<known-sha256>  install.sh" | sha256sum -c -\\n&& sh install.sh`.',
      });
    }
  }
}

function findLatestOrUntaggedBase(instructions, findings) {
  for (const instr of instructions) {
    if (instr.instruction !== 'FROM') continue;
    const ref = instr.args.trim().split(/\s+/)[0]; // strip "AS stagename" if present
    if (ref.includes('@sha256:')) continue; // digest-pinned, the strongest form
    const afterColon = ref.includes(':') ? ref.split(':').pop() : null;
    if (afterColon === 'latest' || afterColon === null) {
      findings.push({
        severity: 'warning', kind: 'unpinned_base_image', location: `line ${instr.line}`,
        image: ref,
        why: afterColon === null
          ? 'No tag at all on this base image -- Docker defaults to :latest, meaning the exact base your image builds on can change without warning between builds, and "it worked yesterday" stops meaning anything.'
          : 'Base image pinned to :latest -- same problem as no tag: the base can change out from under you between builds with no diff in this file to explain why.',
        fix: 'Pin to a specific version tag at minimum (e.g. `node:22-slim`), or better, a content digest (`node:22-slim@sha256:<digest>`) for a fully reproducible build.',
      });
    }
  }
}

function findAddWithUrl(instructions, findings) {
  for (const instr of instructions) {
    if (instr.instruction !== 'ADD') continue;
    if (/^https?:\/\//i.test(instr.args.trim())) {
      findings.push({
        severity: 'warning', kind: 'add_remote_url', location: `line ${instr.line}`,
        why: 'ADD with a URL fetches and extracts a remote file at build time with no checksum verification -- same trust problem as curl|sh, just via a different instruction.',
        fix: 'Use RUN with curl/wget plus an explicit checksum check instead (see the curl|sh finding for the pattern), or vendor the file and COPY it from your build context.',
      });
    }
  }
}

function auditDockerfile(src) {
  let instructions;
  try {
    instructions = parseDockerfile(src);
  } catch (e) {
    return { error: `Could not parse Dockerfile: ${e.message}` };
  }
  if (!instructions.length || !instructions.some((i) => i.instruction === 'FROM')) {
    return { error: 'No FROM instruction found -- is this really a Dockerfile?' };
  }
  const findings = [];
  findMissingUser(instructions, findings);
  findBakedSecrets(instructions, findings);
  findCurlPipeShell(instructions, findings);
  findLatestOrUntaggedBase(instructions, findings);
  findAddWithUrl(instructions, findings);

  const critical = findings.filter((f) => f.severity === 'critical').length;
  const warning = findings.filter((f) => f.severity === 'warning').length;
  return {
    riskLevel: critical > 0 ? 'HIGH — exploitable or credential-leaking pattern found' : warning > 0 ? 'MODERATE — hardening gaps found' : 'LOW — no known dangerous patterns found',
    stageCount: [...new Set(instructions.filter((i) => i.instruction === 'FROM').map((i) => i.stage))].length,
    findingCount: findings.length,
    criticalCount: critical,
    warningCount: warning,
    findings,
  };
}

function buildServer() {
  const server = new McpServer({ name: 'dockerfile-audit-mcp', version: '1.0.0' });

  server.tool('audit_dockerfile',
    'Audits a Dockerfile for real, documented container-security anti-patterns: no USER instruction (every step runs as root by default), credentials baked into ENV/ARG (permanently visible in image layer history via `docker history`, even after later layers unset them), `curl | sh` / `wget | sh` patterns (unpinned, unverified remote code execution at build time), unpinned `:latest` or untagged base images (non-reproducible builds), and ADD instructions that fetch a remote URL with no checksum. Handles multi-stage builds (checks each stage separately) and backslash line continuations.',
    { dockerfile_content: z.string().describe('The full contents of a Dockerfile') },
    async ({ dockerfile_content }) => ({ content: [{ type: 'text', text: JSON.stringify(auditDockerfile(dockerfile_content), null, 2) }] })
  );

  return server;
}

// ── HTTP server ────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;

const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/health') { res.writeHead(200); res.end('ok'); return; }
  if (req.url !== '/' && !req.url?.startsWith('/mcp')) { res.writeHead(404); res.end(); return; }

  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => { transport.close(); server.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res);
});

httpServer.listen(PORT, () => console.log(`dockerfile-audit-mcp listening on :${PORT}`));

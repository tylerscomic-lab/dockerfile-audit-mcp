import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const client = new Client({ name: 'test-client', version: '1.0.0' });
const transport = new StreamableHTTPClientTransport(new URL('http://localhost:8080/mcp'));
await client.connect(transport);

console.log('Tools:', (await client.listTools()).tools.map((t) => t.name));

let failures = 0;
async function audit(name, dockerfile, checks) {
  const r = await client.callTool({ name: 'audit_dockerfile', arguments: { dockerfile_content: dockerfile } });
  const parsed = JSON.parse(r.content[0].text);
  if (parsed.error) { console.log(`FAIL | ${name} | ${parsed.error}`); failures++; return parsed; }
  const kinds = (parsed.findings || []).map((f) => f.kind);
  let ok = true;
  for (const [kind, expected] of Object.entries(checks)) {
    if (kinds.includes(kind) !== expected) ok = false;
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} | ${name} | risk=${parsed.riskLevel} | kinds=[${kinds.join(', ')}]`);
  if (!ok) failures++;
  return parsed;
}

console.log('\n--- clean multi-stage Dockerfile: no findings ---');
await audit('clean', `
FROM node:22-slim AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:22-slim
RUN adduser --disabled-password appuser
WORKDIR /app
COPY --from=build /app/dist ./dist
USER appuser
CMD ["node", "dist/index.js"]
`, { missing_user: false, baked_secret: false, curl_pipe_shell: false, unpinned_base_image: false, add_remote_url: false });

console.log('\n--- no USER anywhere ---');
await audit('missing user', `
FROM node:22-slim
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "index.js"]
`, { missing_user: true });

console.log('\n--- explicit USER root ---');
await audit('explicit root', `
FROM node:22-slim
USER root
CMD ["node", "index.js"]
`, { explicit_root_user: true });

console.log('\n--- baked secret in ENV ---');
const secretTest = await audit('env secret', `
FROM node:22-slim
ENV STRIPE_SECRET_KEY=zzq7Nf3mPk9wXeR2vTb8LqA4sDh6
USER appuser
CMD ["node", "index.js"]
`, { baked_secret: true });
console.log('   secret var flagged:', secretTest.findings.find((f) => f.kind === 'baked_secret')?.variable);

console.log('\n--- placeholder secret value should NOT flag ---');
await audit('placeholder value', `
FROM node:22-slim
ENV API_KEY=<your-api-key-here>
USER appuser
CMD ["node", "index.js"]
`, { baked_secret: false });

console.log('\n--- ARG with no default (supplied at build time) should NOT flag ---');
await audit('ARG no default', `
FROM node:22-slim
ARG API_TOKEN
USER appuser
CMD ["node", "index.js"]
`, { baked_secret: false });

console.log('\n--- curl pipe shell ---');
await audit('curl pipe sh', `
FROM node:22-slim
RUN curl -fsSL https://get.example.com/install.sh | sh
USER appuser
CMD ["node", "index.js"]
`, { curl_pipe_shell: true });

console.log('\n--- wget pipe bash ---');
await audit('wget pipe bash', `
FROM node:22-slim
RUN wget -qO- https://get.example.com/install.sh | bash
USER appuser
CMD ["node", "index.js"]
`, { curl_pipe_shell: true });

console.log('\n--- curl WITHOUT pipe to shell should NOT flag ---');
await audit('curl to file, no pipe', `
FROM node:22-slim
RUN curl -fsSL -o install.sh https://get.example.com/install.sh && sha256sum -c install.sh.sha256 && sh install.sh
USER appuser
CMD ["node", "index.js"]
`, { curl_pipe_shell: false });

console.log('\n--- :latest tag ---');
await audit('latest tag', `
FROM node:latest
USER appuser
CMD ["node", "index.js"]
`, { unpinned_base_image: true });

console.log('\n--- no tag at all ---');
await audit('no tag', `
FROM node
USER appuser
CMD ["node", "index.js"]
`, { unpinned_base_image: true });

console.log('\n--- digest-pinned base should NOT flag ---');
await audit('digest pinned', `
FROM node@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd
USER appuser
CMD ["node", "index.js"]
`, { unpinned_base_image: false });

console.log('\n--- ADD with remote URL ---');
await audit('ADD url', `
FROM node:22-slim
ADD https://example.com/archive.tar.gz /app/
USER appuser
CMD ["node", "index.js"]
`, { add_remote_url: true });

console.log('\n--- ADD of a local file should NOT flag ---');
await audit('ADD local', `
FROM node:22-slim
ADD ./local-archive.tar.gz /app/
USER appuser
CMD ["node", "index.js"]
`, { add_remote_url: false });

console.log('\n--- multi-stage: build stage has no USER but final (shipped) stage does -- should NOT flag ---');
await audit('multi-stage partial', `
FROM node:22-slim AS build
RUN npm install

FROM node:22-slim
USER appuser
COPY --from=build /app/dist ./dist
CMD ["node", "index.js"]
`, { missing_user: false });

console.log('\n--- multi-stage: ONLY the final stage matters, missing there should flag ---');
await audit('multi-stage final missing', `
FROM node:22-slim AS build
RUN adduser --disabled-password builder
USER builder
RUN npm install

FROM node:22-slim
COPY --from=build /app/dist ./dist
CMD ["node", "index.js"]
`, { missing_user: true });

console.log('\n--- line continuation (backslash) parses as one instruction ---');
await audit('line continuation', `
FROM node:22-slim
RUN apt-get update \\
    && apt-get install -y curl \\
    && rm -rf /var/lib/apt/lists/*
USER appuser
CMD ["node", "index.js"]
`, { missing_user: false });

console.log('\n--- not a Dockerfile at all ---');
const notDocker = await client.callTool({ name: 'audit_dockerfile', arguments: { dockerfile_content: 'just some random text\nwith no FROM line' } });
console.log(JSON.parse(notDocker.content[0].text));

await client.close();
console.log(`\n${failures === 0 ? 'ALL PASS' : failures + ' FAILURE(S)'}`);
process.exit(failures === 0 ? 0 : 1);

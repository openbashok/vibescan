# vibescan

Scanner HTTP/DNS para sitios web. Una sola corrida produce tres outputs:

1. Score 0-100 de agent-readiness, con grade letra A+ a F.
2. Inventario de archivos expuestos por el deploy (con extracción de
   secretos cuando se encuentran).
3. Inventario de signals de builders y asistentes de código presentes en
   el HTML y los bundles.

Python 3.10+, stdlib only, un archivo. MIT.
Repo: https://github.com/openbashok/vibescan

## Chequeos

### Agent-readiness (scoreados)

19 chequeos. Score = passes / total × 100.

- robots.txt presente y válido (text/plain, ≥1 User-agent)
- Sitemap (declarado en robots.txt o accesible en /sitemap.xml)
- Link headers (RFC 8288) en /
- DNS-AID: queries SVCB(64), HTTPS(65), TXT(16) a
  `_index._agents.<host>`, `_a2a._agents.<host>`, `_mcp._agents.<host>`,
  contra host canónico y apex, vía DoH a `cloudflare-dns.com/dns-query`.
  Verifica el flag AD para DNSSEC.
- Markdown negotiation: GET / con `Accept: text/markdown` debe devolver
  `Content-Type: text/markdown`.
- AI bot rules en robots.txt: chequea ≥1 User-agent de
  GPTBot/ChatGPT-User/ClaudeBot/anthropic-ai/Google-Extended/PerplexityBot/
  CCBot/Bytespider/etc., o wildcard `*` (sigue la fórmula de
  isitagentready.com).
- Content-Signal directives en robots.txt (ai-train, ai-input, search).
- Web Bot Auth: `/.well-known/http-message-signatures-directory` (RFC en
  draft).
- API Catalog (RFC 9727): `/.well-known/api-catalog` con
  `application/linkset+json`.
- OAuth/OIDC discovery: `/.well-known/openid-configuration` o
  `oauth-authorization-server` con campos issuer/authorization_endpoint/
  token_endpoint.
- OAuth Protected Resource (RFC 9728):
  `/.well-known/oauth-protected-resource`.
- Auth.md: `/auth.md` con H1 canónico.
- MCP Server Card: `/.well-known/mcp/server-card.json` (variantes
  `mcp.json`, `server-cards.json`).
- Agent Skills index: `/.well-known/agent-skills/index.json`.
- WebMCP (no verificable solo HTTP, cuenta como fail).
- Commerce (informacional, no entran en el score): x402 (HTTP 402),
  MPP (`x-payment-info` en `/openapi.json`), UCP, ACP.

Filtros aplicados a todas las respuestas JSON well-known:
- Status 200 obligatorio.
- Content-Type debe contener `application/json` (o
  `application/linkset+json`).
- Body que parsea como JSON.
- Body que NO contiene `<!doctype html` ni `<html` (filtro de soft-404).

Score: `(Σ passes) / (Σ chequeos scoreados) × 100`. Warns cuentan como 0.
Content Signals y WebMCP definidos como info-only o auto-fail según el
caso, alineado con isitagentready.com.

Mapeo a grade:

| Score   | Grade |
|---------|-------|
| 0-19    | F     |
| 20-39   | D     |
| 40-59   | C     |
| 60-79   | B     |
| 80-94   | A     |
| 95-100  | A+    |

### Exposures (no scoreados)

~50 paths sondeados con GET, sin follow-redirect, sin auth. Match positivo
requiere status 200, body no-HTML, y para paths con validador específico,
match de la firma.

Paths cubiertos:

- Contexto de agentes (15): `CLAUDE.md`, `AGENTS.md`, `AGENT.md`,
  `.cursorrules`, `.windsurfrules`, `.aider.conf.yml`,
  `.aider.chat.history.md`, `.aider.input.history`,
  `.github/copilot-instructions.md`, `.continue/config.json`,
  `.claude/settings.json`, `.claude/settings.local.json`,
  `.cursor/mcp.json`, `.codex/config.toml`, `.specstory/`.
- VCS (7): `.git/config` (validador: secciones [core]/[remote]/[branch]),
  `.git/HEAD` (validador: `ref: refs/`), `.git/logs/HEAD`, `.git/index`
  (validador: signature `DIRC`), `.gitignore`, `.svn/entries`, `.hg/hgrc`.
- Secretos y config (12): `.env`, `.env.local`, `.env.production`,
  `.env.development`, `.env.backup`, `.env.bak`, `credentials.json`,
  `secrets.json`, `config.json`, `settings.json`, `docker-compose.yml`,
  `Dockerfile`.
- IDE / OS (3): `.vscode/settings.json`, `.idea/workspace.xml`,
  `.DS_Store` (validador: signature `\x00\x00\x00\x01Bud1`).
- Backups y dumps (6): `backup.sql`, `dump.sql`, `database.sql`,
  `db.sqlite`, `backup.zip`, `backup.tar.gz`.
- Lockfiles (6): `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
  `composer.lock`, `Pipfile.lock`, `poetry.lock`.
- API surface (1): `/openapi.json` con extracción de title y count de
  paths.

Extracción de secretos sobre `.env*`, `.git/config`, `credentials.json`,
`secrets.json`, `docker-compose.yml`. Patrones implementados:

- AWS access key: `AKIA[0-9A-Z]{16}`
- AWS secret hint: `aws_secret_access_key=...`
- OpenAI: `sk-(proj-)?[A-Za-z0-9_\-]{20,}`
- Anthropic: `sk-ant-[A-Za-z0-9_\-]{20,}`
- Google API: `AIza[0-9A-Za-z\-_]{35}`
- GitHub token: `gh[pousr]_[A-Za-z0-9]{30,}`
- Slack token: `xox[abprs]-[A-Za-z0-9\-]{10,}`
- Stripe: `sk_(live|test)_[A-Za-z0-9]{20,}`
- Supabase JWT HS256
- Private key block: `-----BEGIN ... PRIVATE KEY-----`
- Genérico: `(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD)=...`

Severidades asignadas por path, de `info` a `critical`. No se computan en
el score de agent-readiness.

### Fingerprint (no scoreado)

GET / + hasta 8 bundles JS linkeados desde el HTML. Patrones buscados
sobre el blob concatenado:

- meta generator
- Headers reveladores: `server`, `x-powered-by`, `x-vercel-id`,
  `x-render-origin-server`, `x-served-by`, `via`
- Sufijos de host: `vercel.app`, `netlify.app`, `lovableproject.com`,
  `bolt.host`, `replit.dev`, `repl.co`, `web.app`, `firebaseapp.com`,
  `pages.dev`, `onrender.com`, `up.railway.app`, `base44.app`
- Watermarks textuales: `lovable`, `v0.dev|vercel.com/v0|data-v0`,
  `bolt.new|stackblitz`, `base44`, `replit.com|created with replit`,
  `gpt[-_]?engineer`, `generated by (chatgpt|claude|copilot|cursor)`,
  `made with (lovable|bubble|softr|framer)`
- Supabase anon JWT con header HS256 estándar

Cada hit alimenta el score numérico de vibecoding (suma ponderada por
fuente), y se reporta con atribución al agente o builder específico.
Pesos en `SCORE_EXPOSURE_PATHS`, `SCORE_BUILDER_PATTERNS`,
`SCORE_HOST_SUFFIX` en el código.

## Output

Por chequeo: etiqueta + dots animados durante el HTTP + status entre
brackets.

Al final del scan, tres líneas resumen:

- `[VIBECODING]` — score numérico + count de agentes y builders
  detectados + lista de evidencia ordenada por puntos.
- `[EXPOSURES]` — count por severidad.
- `[SCORE]` — score/100, grade letra, y desglose por categoría con
  porcentaje y ratio.

## Operación

```
python3 vibescan.py <target>            # default: animado, secuencial
python3 vibescan.py <target> --fast     # paralelo (24 workers), silencioso
python3 vibescan.py <target> --json     # JSON, sin renderer
python3 vibescan.py -l hosts.txt        # multi-host desde archivo
```

Sin dependencias externas. Timeouts: 3 s por request HTTP.

## Demo local

```
PORT=8080 python3 demo/serve.py
python3 vibescan.py http://127.0.0.1:8080
```

El directorio `demo/site/` contiene un target sintético con archivos de
contexto de agentes, `.env` con claves falsas, `.git/*`, `.well-known/*`
parcialmente poblado, y un index.html con watermarks de Lovable. Sirve
para validar cambios y para demos reproducibles.

## Repositorio

https://github.com/openbashok/vibescan

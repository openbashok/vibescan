Empecé a notar algo escaneando sitios estos últimos meses: archivos como
CLAUDE.md, AGENTS.md, .cursorrules sirviéndose públicos desde el web
root. Documentos pensados como contexto privado para un agente de código
— convenciones del proyecto, paths de admin, prompts, a veces
referencias literales al .env.

Es lo mismo de siempre con cara nueva. El dev usó un asistente, el
asistente generó archivos de contexto, y el deploy los subió igual que
cualquier otro markdown. La diferencia con un .git/config expuesto es
que el CLAUDE.md te resume el sitio en lenguaje natural — modelo de
amenazas incluido.

vibescan es una tool en Python que armé para hacer ese chequeo
sistemáticamente. En una sola corrida hace tres cosas que normalmente
toman dos tools y un grep:

Le calcula el score de agent-readiness al sitio, con la misma fórmula
que usa isitagentready.com de Cloudflare. Mira robots.txt con reglas
para bots de IA, DNS-AID (registros SVCB/HTTPS/TXT bajo
_index._agents.<host>), MCP server-card, OpenID/OAuth discovery, OAuth
Protected Resource, Agent Skills index, Web Bot Auth, Auth.md, x402.
Devuelve grade letra estilo SSL Labs, de F a A+.

Busca los archivos típicos que los asistentes dejan en el repo y que el
deploy nunca filtra: CLAUDE.md, AGENTS.md, .cursorrules, .windsurfrules,
.aider.conf.yml, .aider.chat.history.md, .continue/config.json,
.codex/config.toml, .claude/settings.local.json, .cursor/mcp.json,
.github/copilot-instructions.md. También los clásicos — .env*, .git/*,
dumps SQL, backups, lockfiles, OpenAPI público. Cuando el .env aparece,
corre regex sobre el cuerpo y reporta las claves que reconoce: AWS,
OpenAI, Anthropic, Google, GitHub, Slack, Stripe, Supabase JWT, bloques
PEM. La superficie OpenAPI la enumera con title y path count.

Detecta si el sitio fue construido con un builder asistido por IA —
Lovable, v0.dev, bolt.new, Base44, Replit, GPT-Engineer — leyendo
watermarks del HTML y de los bundles JS, sufijos de host de prototipado
(lovableproject.com, bolt.host, base44.app, replit.dev), y meta
generator. Cuando hay evidencia suficiente, devuelve "vibecoded
confirmed" con la atribución desglosada por agente y por builder.

Salida estilo init de Linux: cada chequeo imprime su etiqueta, los dots
animan en pantalla mientras la request HTTP está en vuelo, y el status
sale entre brackets cuando termina. Si la request tarda 2 segundos, ves
60 dots. Si tarda 5 ms, ves el mínimo. Modo silencioso con --fast para
multi-host o pipeline. JSON con --json.

Python puro, stdlib only, un archivo. MIT.

    git clone https://github.com/openbashok/vibescan
    cd vibescan
    python3 vibescan.py example.com

Repo: https://github.com/openbashok/vibescan — abierto a issues y PRs.

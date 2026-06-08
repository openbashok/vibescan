# vibescan demo

Local HTTP server that simulates a vibecoded SaaS app ("Acme Habits Tracker"),
designed to give a juicy, reproducible vibescan output for live demos.

## What it simulates

A SaaS startup that:

- Was scaffolded with **Lovable** (`<meta generator>` + footer badge).
- Was coded with a mix of agents — **Claude**, **Cursor**, **Aider** — and
  left all their context files in the web root.
- Leaked its `.env`, `.git/config`, `docker-compose.yml` and `package-lock.json`.
- Implemented partial agent-readiness: `robots.txt` with AI bot rules,
  OAuth/OIDC discovery, OAuth Protected Resource, API Catalog, MCP server
  card, Auth.md, Link headers, Markdown content negotiation.
- Skipped the rest: no Web Bot Auth, no DNS-AID, no Agent Skills index, no
  WebMCP, no commerce protocols (UCP/ACP/x402) — except a single
  `x-payment-info` endpoint to flag MPP.
- Published its full OpenAPI spec including internal `/api/admin/*` paths.

## Setup

1. Add a hosts entry (one-time, requires sudo):

```bash
echo '127.0.0.1 vibedemo.local' | sudo tee -a /etc/hosts
```

2. Start the server. **Port 80** gives the clean URL but needs sudo:

```bash
sudo python3 demo/serve.py
```

Or port 8080 (no sudo):

```bash
PORT=8080 python3 demo/serve.py
```

## Run the scan

```bash
# port 80
python3 vibescan.py http://vibedemo.local

# port 8080
python3 vibescan.py http://vibedemo.local:8080
```

## Expected output

- **Score**: ~64/100, **Grade B**, tier **Negotiable**.
  - Discoverability 3/4 (DNS-AID fails — local target, no DNS)
  - Content 1/1
  - Bot Access Control 1/2 (Web Bot Auth fails)
  - API/Auth/MCP/Skill 4/7
- **Vibecoding verdict**: `vibecoded confirmed` (~100 pts).
  Agents detected: Claude, Cursor, Aider, Agent context, AI-generated watermark.
  Builders detected: Lovable, Builder badge.
- **Exposures**: 3 critical (`.env`, `.git/config`, `.git/HEAD`), 6 high
  (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.aider.conf.yml`,
  `.aider.chat.history.md`, `docker-compose.yml`), plus medium for
  `openapi.json` and low for `package-lock.json`.
- The `.env` extractor pulls out **AWS, OpenAI, Anthropic and Stripe
  keys** by pattern.
- The `.git/config` extractor pulls out the **GitHub origin URL** —
  `https://github.com/acme-internal/habits-tracker.git`.

## Teardown

```bash
# stop the server with Ctrl-C, then remove the hosts entry:
sudo sed -i.bak '/vibedemo.local/d' /etc/hosts
```

## Layout

```
demo/
├── README.md          (this file)
├── serve.py           (custom HTTP server with aliases + content negotiation)
└── site/              (the fake site's web root)
    ├── index.html
    ├── index.md
    ├── robots.txt
    ├── sitemap.xml
    ├── CLAUDE.md
    ├── AGENTS.md
    ├── .cursorrules
    ├── auth.md
    ├── openapi.json
    ├── docker-compose.yml
    ├── package-lock.json
    ├── .well-known/
    │   ├── openid-configuration
    │   ├── oauth-protected-resource
    │   ├── api-catalog
    │   └── mcp/server-card.json
    └── _seeds/        (files that serve.py routes to dotpaths)
        ├── env                  → /.env
        ├── aider.conf.yml       → /.aider.conf.yml
        ├── aider.history.md     → /.aider.chat.history.md
        └── git/
            ├── config           → /.git/config
            └── HEAD             → /.git/HEAD
```

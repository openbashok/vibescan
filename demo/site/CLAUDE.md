# Claude project context — Acme Habits Tracker

## Stack

- React + Vite, scaffolded with Lovable
- shadcn/ui + tailwindcss + lucide-react
- Supabase (Postgres + Auth + RLS)
- Stripe for billing
- Resend for transactional email
- MCP server at https://mcp.acmehabits.com (also exposed at /.well-known/mcp/server-card.json)

## Conventions

- Functional components only, no class components.
- Always use the `useToast` hook from `@/hooks/use-toast`.
- Database access via Supabase client — see `src/lib/supabase.ts`.
- Server-side admin actions live under `/api/admin/*` and require the
  `X-Admin-Token` header. The token is in `.env` as `ADMIN_TOKEN`.

## Internal services (do not link from marketing site)

- Auth:       https://auth.internal.acmehabits.com
- Insights:   https://insights-api.internal.acmehabits.com
- Admin UI:   https://admin.acmehabits.com  (Bearer auth required)

## Known issues / TODO

- Rate limiting NOT implemented on `/api/v1/insights` — fix before launch.
- Auth token expires after 1 h and we don't refresh — users must re-login.
- `.env` has both anon and service-role Supabase keys. Service role bypasses
  RLS; if it ever leaks, rotate immediately.

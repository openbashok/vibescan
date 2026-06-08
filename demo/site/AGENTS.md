# Agent instructions — Acme Habits Tracker

Use TypeScript strict mode. Prefer composition over inheritance.

## Internal services

- Auth:        https://auth.internal.acmehabits.com
- Insights:    https://insights-api.internal.acmehabits.com
- Admin panel: https://admin.acmehabits.com  (Bearer auth required)

## Database access

Use the Supabase client. Never use raw `fetch` against the Supabase REST
endpoints — go through `src/lib/db.ts`.

## Secrets handling

Never echo, log, or commit values from `.env`. The CI redacts them but
local logs do not.

# Auth.md

This document describes how AI agents can register with and authenticate
to the Acme Habits Tracker API.

## Registration

Agents register via the OAuth 2.0 dynamic client registration endpoint at
`https://auth.acmehabits.com/oauth2/register`.

## Authentication

Use the OAuth 2.0 authorization code flow with PKCE. See
`/.well-known/oauth-authorization-server` and
`/.well-known/oauth-protected-resource` for endpoint discovery.

## Scopes

- `read:habits` — read user habit data
- `write:habits` — create / update habit entries
- `read:insights` — call the insights API

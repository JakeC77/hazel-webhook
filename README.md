# hazel-chat-webhook

Flask backend for the Hazel builder dashboard. Runs on a Digital Ocean droplet at `https://hazel.dejaview.io`, proxied by Caddy.

## What this is

This is the API layer between the dashboard frontend and Supabase. It uses the **service role key** for all database operations, bypassing RLS entirely. This is intentional — the frontend anon key has RLS restrictions that cause edge cases on first load, firm creation, and cross-table joins.

It also receives Supabase webhook events (INSERT on `messages`) and forwards them to the OpenClaw agent (Hazel).

## Stack

- Python 3 / Flask
- Supabase (PostgreSQL via REST API)
- Deployed as a systemd service (`hazel-chat-webhook.service`)
- Port 8700, behind Caddy reverse proxy

## Auth

Every protected route uses `@require_auth`. It validates the Supabase JWT using **ES256/JWKS** (not HS256). The JWKS endpoint is `{SUPABASE_URL}/auth/v1/.well-known/jwks.json`.

After validation, `g.user_id` and `g.firm_id` are available in the route handler.

## Environment variables (set in systemd service, never committed)

```
SUPABASE_URL
SUPABASE_SERVICE_KEY
SUPABASE_JWT_SECRET   (legacy, kept for reference — not used for verification)
AGENTMAIL_KEY
HAZEL_WEBHOOK_SECRET
OPENCLAW_HOOKS_TOKEN
```

## API Routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/firm-context` | Returns firm profile for authed user |
| POST | `/api/firm/setup` | Create or return existing firm (idempotent) |
| GET | `/api/projects` | List all projects for firm |
| POST | `/api/projects` | Create a new project |
| GET | `/api/team` | Members + pending invites |
| POST | `/api/invites` | Send invite email via AgentMail |
| POST | `/api/invites/accept` | Accept invite token |
| GET | `/api/preferences` | Get firm preferences |
| PUT | `/api/preferences` | Update firm preferences |
| GET | `/api/contacts` | List firm contacts |
| POST | `/api/contacts` | Add contact |
| PUT | `/api/contacts/<id>` | Update contact |
| DELETE | `/api/contacts/<id>` | Delete contact |
| POST | `/api/queue/<id>/decide` | Apply approve/reject/hold (validates transition, 409 if invalid) |
| POST | `/api/queue/<id>/version` | Persist draft version snapshot |
| POST | `/hooks/messages` | Supabase webhook → OpenClaw agent |

## Valid queue status transitions

```
active  → approve | reject | hold
snoozed → approve | reject | hold | reactivate
```

Returns 409 if the current status doesn't allow the requested action.

## Deployment

```bash
git pull
sudo systemctl restart hazel-chat-webhook
# Logs:
journalctl -u hazel-chat-webhook -n 50 --no-pager
```

## AQ-04 Resurfacer

`resurfacer.py` runs on a systemd timer every 15 minutes. It finds `queue_items` where `status='snoozed'` and `held_at + resurface_after <= now()`, flips them back to `active`, and optionally sends an SMS nudge.

Timer: `hazel-resurfacer.timer`

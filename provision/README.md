# Hazel Provisioning

Scripts and templates for provisioning new Hazel agent instances per firm.

## Architecture

```
OpenClaw Instance
├── agents/
│   ├── hazel-ridgeline/          ← Firm A
│   │   ├── agent/                (auth, sessions)
│   │   └── sessions/
│   ├── hazel-smith-construction/ ← Firm B
│   │   ├── agent/
│   │   └── sessions/
│   └── ...
├── workspace/hazel/
│   ├── shared-skills/            ← Shared scripts (all agents symlink here)
│   │   ├── boh-dashboard/
│   │   └── boh-graph/
│   └── builders/
│       ├── ridgeline/            ← Firm A workspace
│       ├── smith-construction/   ← Firm B workspace
│       └── ...
└── extensions/clawtalk/          ← Shared ClawdTalk plugin
```

Each firm gets:
- Its own agent ID (`hazel-<slug>`) in openclaw.json
- Its own workspace with AGENTS.md, SOUL.md, USER.md, memory/
- Its own auth profile (Anthropic API key)
- Its own sandbox container
- A symlink to shared skills (Python scripts)

## Usage

```bash
# Dry run — see what would happen
python3 provision_firm.py \
  --firm-name "Smith Construction" \
  --owner-email "john@smithconstruction.com" \
  --owner-name "John Smith" \
  --timezone "America/New_York" \
  --dry-run

# Provision for real
python3 provision_firm.py \
  --firm-name "Smith Construction" \
  --owner-email "john@smithconstruction.com" \
  --owner-name "John Smith" \
  --timezone "America/New_York" \
  --anthropic-key "sk-ant-..."

# With ClawdTalk phone number
python3 provision_firm.py \
  --firm-name "Smith Construction" \
  --owner-email "john@smithconstruction.com" \
  --owner-name "John Smith" \
  --provision-phone
```

## Setup: Shared Skills

Before provisioning your first firm, set up the shared skills directory:

```bash
cp -r /home/openclaw/.openclaw/workspace/hazel/builders/ridgeline/skills \
      /home/openclaw/.openclaw/workspace/hazel/shared-skills
```

All new agents will symlink to this directory. Update scripts in one place,
all agents get the changes.

## What Provisioning Creates

1. **Supabase:** firm row + Home project
2. **Workspace:** template files with firm-specific values substituted
3. **Agent dir:** auth-profiles.json with Anthropic key
4. **openclaw.json:** new agent entry
5. **ClawdTalk number** (optional)

## Webhook Routing

The webhook server (hazel-webhiik/server.py) already routes by firm_id.
Dashboard messages, Gmail pushes, and email webhooks all include firm_id
and are forwarded to the correct agent's session.

For ClawdTalk (SMS/voice), routing is by phone number → agent mapping.
This needs to be configured in the ClawdTalk plugin config per agent.

## Template Files

Templates live in `provision/template/workspace/`. Variables:
- `{{FIRM_NAME}}` — company name
- `{{OWNER_NAME}}` — owner's name
- `{{TIMEZONE}}` — timezone string
- `{{FIRM_ID}}` — Supabase firm UUID
- `{{SLUG}}` — filesystem-safe firm name
- `{{SUPABASE_URL}}` — Supabase URL

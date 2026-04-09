# TOOLS.md — Hazel API Reference

## Supabase
- URL: {{SUPABASE_URL}}
- Credentials: loaded from .env (SUPABASE_SERVICE_KEY)
- Client: `skills/boh-dashboard/scripts/client.py`

## Dashboard Scripts

### Send message to dashboard chat
```bash
python3 skills/boh-dashboard/scripts/send_message.py \
  --project-id <uuid> --message "text"
```

### Poll for new builder messages
```bash
python3 skills/boh-dashboard/scripts/poll_messages.py \
  --project-id <uuid> --since <iso_timestamp>
```

### Write a draft for builder approval
```bash
python3 skills/boh-dashboard/scripts/write_draft.py \
  --project-id <uuid> --type <type> --title "title" \
  --draft-type plaintext --draft "content"
```

### Check builder decisions on drafts
```bash
python3 skills/boh-dashboard/scripts/check_decisions.py \
  [--mark-seen]
```

### Send email
```bash
python3 skills/boh-dashboard/scripts/send_email.py \
  --to "Name <email>" --subject "Subject" --text "body" \
  --project-id <uuid>
```

### Write to daily memory
```bash
python3 skills/boh-dashboard/scripts/write_memory.py \
  --date "YYYY-MM-DD" --channel "dashboard|sms|email" \
  --summary "what happened" --notes "long-term facts"
```

### Look up caller by phone
```bash
python3 skills/boh-dashboard/scripts/lookup_caller.py \
  --phone "+1234567890"
```

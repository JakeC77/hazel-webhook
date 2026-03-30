#!/usr/bin/env python3
"""
Hazel Dashboard Chat Webhook — OpenClaw shim (v5, new-project-setup)

Receives Supabase INSERT events on the messages table (builder role only)
and forwards them to the OpenClaw hooks API targeting the hazel agent.

Special triggers:
  [NEW_PROJECT_SETUP] — kicks off conversational project setup flow
  project_id == HOME_PROJECT_ID — routes to account-level home session

Port: 8700
"""
import os, json, logging, requests, threading
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

WEBHOOK_SECRET  = os.getenv("HAZEL_WEBHOOK_SECRET", "hazel-chat-2026")
OPENCLAW_URL    = os.getenv("OPENCLAW_API_URL", "http://127.0.0.1:18789")
HOOKS_TOKEN     = os.getenv("OPENCLAW_HOOKS_TOKEN", "")
SUPABASE_URL    = "https://zrolyrtaaaiauigrvusl.supabase.co"
SUPABASE_KEY    = os.getenv("SUPABASE_SERVICE_KEY", "")
SB_HEADERS      = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
}

HOME_PROJECT_ID  = "a0000000-0000-0000-0000-000000000000"
SETUP_TRIGGER    = "[NEW_PROJECT_SETUP]"

_seen = set()
_seen_lock = threading.Lock()

def already_seen(msg_id):
    with _seen_lock:
        if msg_id in _seen:
            return True
        _seen.add(msg_id)
        return False

def get_project_info(project_id):
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/projects",
            headers=SB_HEADERS,
            params={"id": f"eq.{project_id}", "select": "name,pm_name,graph_project_id,status"},
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        if data:
            p = data[0]
            return {
                "name": p.get("name", "Unknown Project"),
                "pm_name": p.get("pm_name", "Builder"),
                "graph_project_id": p.get("graph_project_id"),
                "status": p.get("status"),
            }
    except Exception as e:
        logging.warning(f"Could not fetch project info: {e}")
    return {"name": "Unknown Project", "pm_name": "Builder", "graph_project_id": None, "status": None}

def get_project_files(project_id):
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/files",
            headers=SB_HEADERS,
            params={
                "project_id": f"eq.{project_id}",
                "archived": "eq.false",
                "select": "id,name,category,file_type,size_bytes,storage_path,upload_source",
                "order": "created_at.desc",
                "limit": "50",
            },
            timeout=5,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning(f"Could not fetch project files: {e}")
    return []

def generate_signed_url(storage_path, expires_in=3600):
    try:
        r = requests.post(
            f"{SUPABASE_URL}/storage/v1/object/sign/project-files/{storage_path}",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json={"expiresIn": expires_in},
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        signed = data.get("signedURL") or data.get("signedUrl")
        if signed:
            return f"{SUPABASE_URL}/storage/v1{signed}" if signed.startswith("/") else signed
    except Exception as e:
        logging.warning(f"Could not generate signed URL for {storage_path}: {e}")
    return None

def build_file_context(project_id, message_attachments):
    lines = []
    all_files = get_project_files(project_id)
    if all_files:
        lines.append("=== Project Files ===")
        for f in all_files:
            size_mb = f"{f['size_bytes'] / 1_000_000:.1f} MB" if f.get("size_bytes") else "unknown size"
            lines.append(f"- [{f.get('category','?')}] {f['name']} ({f.get('file_type','?').upper()}, {size_mb}) id={f['id']}")
        lines.append("")
    if message_attachments:
        file_map = {f["id"]: f for f in all_files}
        attached = [a for a in message_attachments if a.get("id")]
        if attached:
            lines.append("=== Attached in This Message ===")
            for att in attached:
                file_id = att.get("id")
                name = att.get("name", "unknown")
                ftype = att.get("type") or att.get("file_type", "?")
                if file_id and file_id in file_map:
                    row = file_map[file_id]
                    storage_path = row.get("storage_path")
                    if storage_path:
                        signed_url = generate_signed_url(storage_path)
                        if signed_url:
                            lines.append(f"- {name} ({ftype.upper()}) → signed URL: {signed_url}")
                            lines.append(f"  To read PDF: python3 skills/boh-dashboard/scripts/read_file.py --url \"{signed_url}\"")
                            lines.append(f"  To view image: use the image tool with url={signed_url}")
                        else:
                            lines.append(f"- {name} ({ftype.upper()}) — storage path: {storage_path} (signed URL unavailable)")
                    else:
                        lines.append(f"- {name} ({ftype.upper()}) — metadata only, not yet in storage")
                else:
                    lines.append(f"- {name} ({ftype.upper()}) — {f'id={file_id}' if file_id else 'no id'}")
            lines.append("")
    return "\n".join(lines) if lines else ""

def post_to_hazel(session_key, message):
    r = requests.post(
        f"{OPENCLAW_URL}/hooks/agent",
        headers={
            "Authorization": f"Bearer {HOOKS_TOKEN}",
            "Content-Type": "application/json",
        },
        json={
            "message": message,
            "name": "Dashboard",
            "agentId": "hazel",
            "sessionKey": session_key,
            "deliver": False,
            "wakeMode": "now",
        },
        timeout=10,
    )
    r.raise_for_status()

def forward_home(content, msg_id):
    try:
        session_key = "hook:hazel:dashboard:home"
        message = (
            "[Home channel message — account-level]\n"
            "You are in the Home channel, not a specific project. "
            "Help with account-level tasks: creating new projects, general questions, "
            "getting started, or anything not tied to a specific job.\n"
            "To reply, use: python3 skills/boh-dashboard/scripts/send_message.py --home --message \"...\"\n\n"
            + content
        )
        post_to_hazel(session_key, message)
        logging.info(f"Forwarded to hazel home: {content[:80]}")
    except Exception:
        logging.exception(f"Failed to forward home message {msg_id} to hazel")

def forward_setup(project_id, msg_id):
    """Handle [NEW_PROJECT_SETUP] trigger — start a fresh project setup session."""
    try:
        session_key = f"hook:hazel:dashboard:{project_id}"
        message = (
            f"[New project setup — Supabase ID: {project_id}]\n"
            "A builder just clicked 'New Project' on the dashboard. "
            "Walk them through setup conversationally — ask 1-2 questions at a time, don't dump a form.\n\n"
            "Collect in this order:\n"
            "1. Project name\n"
            "2. Site address\n"
            "3. Project type (repair_service, bathroom_remodel, kitchen_remodel, deck_addition, room_addition, new_construction, tenant_improvement)\n"
            "4. Customer name (and ask for email/phone if they're new)\n"
            "5. Rough contract amount\n"
            "6. Target start date\n\n"
            "Once you have everything, run:\n"
            f"  python3 skills/boh-dashboard/scripts/create_project.py \\\n"
            f"    --supabase-id {project_id} \\\n"
            "    --name \"...\" \\\n"
            "    --address \"...\" \\\n"
            "    --archetype ... \\\n"
            "    --contract-amount ... \\\n"
            "    --start-date YYYY-MM-DD \\\n"
            "    --pm-name \"...\" \\\n"
            "    --customer-name \"...\" \\\n"
            "    --customer-email \"...\" \\\n"
            "    --customer-phone \"...\"\n\n"
            f"Reply via: python3 skills/boh-dashboard/scripts/send_message.py --project-id {project_id} --message \"...\"\n\n"
            "Start now — greet them and ask for the project name."
        )
        post_to_hazel(session_key, message)
        logging.info(f"New project setup triggered for {project_id[:8]}")
    except Exception:
        logging.exception(f"Failed to trigger project setup for {msg_id}")

def forward_to_hazel(project_id, content, msg_id, message_attachments):
    if project_id == HOME_PROJECT_ID:
        forward_home(content, msg_id)
        return

    if content.strip() == SETUP_TRIGGER:
        forward_setup(project_id, msg_id)
        return

    try:
        info = get_project_info(project_id)
        project_name = info["name"]
        pm_name      = info["pm_name"]
        graph_id     = info["graph_project_id"]

        session_key = f"hook:hazel:dashboard:{project_id}"
        graph_line  = f"Graph Project ID: {graph_id}" if graph_id else "Graph Project ID: (not linked — query by project name)"
        file_context = build_file_context(project_id, message_attachments)

        message = (
            f"[Dashboard message from {pm_name} — {project_name}]\n"
            f"Supabase Project ID: {project_id}\n"
            f"{graph_line}\n\n"
        )
        if file_context:
            message += file_context + "\n"
        message += content

        post_to_hazel(session_key, message)
        logging.info(f"Forwarded to hazel ({project_id[:8]}): {content[:80]}")

    except Exception:
        logging.exception(f"Failed to forward message {msg_id} to hazel")

@app.route("/webhook/chat", methods=["POST"])
def webhook_chat():
    secret = request.headers.get("X-Webhook-Secret") or request.args.get("secret")
    if secret != WEBHOOK_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(force=True) or {}
    record = payload.get("record") or payload.get("new") or payload

    if record.get("role") != "builder":
        return jsonify({"status": "skipped"}), 200

    content     = (record.get("content") or "").strip()
    project_id  = record.get("project_id")
    msg_id      = record.get("id", "")
    attachments = record.get("attachments") or []

    if not content and not attachments:
        return jsonify({"error": "missing content"}), 400
    if not project_id:
        return jsonify({"error": "missing project_id"}), 400

    if already_seen(msg_id):
        logging.info(f"Duplicate webhook {msg_id} — skipping")
        return jsonify({"status": "duplicate"}), 200

    logging.info(f"Chat ({project_id[:8]}): {content[:80]}{' [+files]' if attachments else ''}")

    t = threading.Thread(target=forward_to_hazel, args=(project_id, content, msg_id, attachments), daemon=True)
    t.start()

    return jsonify({"status": "queued"}), 200

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "hazel-chat-webhook", "version": "5.0-new-project-setup"}), 200


AGENTMAIL_KEY  = os.getenv("AGENTMAIL_KEY", "")
HAZEL_INBOX    = "itshazel@agentmail.to"


def get_email_field(data, *keys):
    """Try multiple key names — handles flat and nested payloads."""
    for k in keys:
        if k in data:
            return data[k]
    return None


@app.route("/webhook/email", methods=["POST"])
def webhook_email():
    """
    AgentMail webhook — fires on message.received for itshazel@agentmail.to.
    Forwards incoming emails to Hazel via OpenClaw hooks.
    """
    payload = request.get_json(force=True) or {}

    # AgentMail/Svix payload: {event_id, event_type, message: {...}}
    data = payload.get("message") or payload.get("data") or payload

    event_type = payload.get("event_type") or payload.get("type", "message.received")
    if "message" not in event_type:
        return jsonify({"status": "ignored", "event_type": event_type}), 200

    thread_id  = get_email_field(data, "thread_id", "threadId")
    message_id = get_email_field(data, "message_id", "messageId", "id")
    sender     = get_email_field(data, "from", "sender", "from_address") or "unknown"
    subject    = get_email_field(data, "subject") or "(no subject)"
    body       = (
        get_email_field(data, "extracted_text", "text", "preview")
        or get_email_field(data, "html")
        or ""
    ).strip()

    if not thread_id:
        logging.warning(f"Email webhook: no thread_id in payload: {json.dumps(payload)[:200]}")
        return jsonify({"error": "missing thread_id"}), 400

    dedup_key = message_id or thread_id
    if already_seen(dedup_key):
        logging.info(f"Duplicate email webhook {dedup_key} — skipping")
        return jsonify({"status": "duplicate"}), 200

    session_key = f"hook:hazel:email:{thread_id}"
    message = (
        f"[Incoming email]\n"
        f"From: {sender}\n"
        f"Subject: {subject}\n"
        f"Thread ID: {thread_id}\n"
        f"Message ID: {message_id}\n"
        f"\n--- Message ---\n"
        f"{body}\n"
        f"\n--- Reply instructions ---\n"
        f"To reply:\n"
        f"  python3 skills/boh-dashboard/scripts/send_email.py \\\n"
        f"    --thread-id {thread_id} \\\n"
        f"    --to \"{sender}\" \\\n"
        f"    --subject \"Re: {subject}\" \\\n"
        f"    --text \"your reply here\"\n"
        f"\nTo start a new email:\n"
        f"  python3 skills/boh-dashboard/scripts/send_email.py \\\n"
        f"    --to \"recipient@example.com\" --subject \"Subject\" --text \"body\"\n"
    )

    logging.info(f"Email from {sender} | thread={thread_id[:12]} | {subject[:60]}")

    t = threading.Thread(target=lambda: post_to_hazel(session_key, message), daemon=True)
    t.start()

    return jsonify({"status": "queued"}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8700, threaded=True)

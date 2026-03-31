#!/usr/bin/env python3
"""
Hazel Dashboard Chat Webhook — OpenClaw shim (v6, epic-1-account-identity)

Receives Supabase INSERT events on the messages table (builder role only)
and forwards them to the OpenClaw hooks API targeting the hazel agent.

Special triggers:
  [NEW_PROJECT_SETUP] — kicks off conversational project setup flow
  project_id == HOME_PROJECT_ID — routes to account-level home session

Port: 8700
"""
import os, json, logging, requests, threading, uuid
from functools import wraps
from flask import Flask, request, jsonify, g

import jwt
from jwt import PyJWKClient  # PyJWT

app = Flask(__name__)

# ── CORS (API routes only) ────────────────────────────────────────────────────
CORS_ORIGINS = {
    'https://jakec77.github.io',
    'https://hazel.haventechsolutions.com',
}

@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin', '')
    if origin in CORS_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Vary'] = 'Origin'
    return response

@app.route('/api/<path:subpath>', methods=['OPTIONS'])
def api_preflight(subpath):
    """Handle CORS preflight for all /api/* routes."""
    return '', 204
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

WEBHOOK_SECRET      = os.getenv("HAZEL_WEBHOOK_SECRET", "hazel-chat-2026")
OPENCLAW_URL        = os.getenv("OPENCLAW_API_URL", "http://127.0.0.1:18789")
HOOKS_TOKEN         = os.getenv("OPENCLAW_HOOKS_TOKEN", "")
SUPABASE_URL        = "https://zrolyrtaaaiauigrvusl.supabase.co"
SUPABASE_KEY        = os.getenv("SUPABASE_SERVICE_KEY", "")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")

# JWKS client — fetches Supabase public keys for ES256 JWT verification
# Supabase switched from HS256 to ES256 on newer projects
_jwks_client = PyJWKClient(
    f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json",
    cache_keys=True,
)
SB_HEADERS          = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
}

HOME_PROJECT_ID = "a0000000-0000-0000-0000-000000000000"
SETUP_TRIGGER   = "[NEW_PROJECT_SETUP]"

_seen = set()
_seen_lock = threading.Lock()


# ── JWT AUTH MIDDLEWARE ────────────────────────────────────────────────────────

def get_firm_id_for_user(user_id: str):
    """Look up the firm_id for a given user_id via Supabase service role."""
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"user_id": f"eq.{user_id}", "select": "firm_id", "limit": "1"},
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        if data:
            return data[0]["firm_id"]
    except Exception as e:
        logging.warning(f"get_firm_id_for_user({user_id}): {e}")
    return None


def require_auth(f):
    """
    Decorator that validates the Supabase JWT Bearer token on incoming requests.
    Sets g.user_id and g.firm_id for use in route handlers.
    Returns 401 if missing or invalid.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[len("Bearer "):]
        if not SUPABASE_JWT_SECRET:
            logging.error("SUPABASE_JWT_SECRET is not set — cannot validate JWT")
            return jsonify({"error": "Server misconfiguration: JWT secret not set"}), 500

        try:
            # Supabase uses ES256 (ECDSA P-256) on newer projects — use JWKS
            signing_key = _jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256", "HS256"],
                audience="authenticated",
                options={"require": ["sub", "exp"]},
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError as e:
            logging.warning(f"JWT validation failed: {e}")
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            logging.warning(f"JWKS lookup failed: {e}")
            return jsonify({"error": "Invalid token"}), 401

        user_id = payload.get("sub")
        if not user_id:
            return jsonify({"error": "No user_id in token"}), 401

        g.user_id = user_id
        g.firm_id = get_firm_id_for_user(user_id)
        return f(*args, **kwargs)
    return decorated


# ── HELPERS (unchanged from v5) ───────────────────────────────────────────────

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
        info         = get_project_info(project_id)
        project_name = info["name"]
        pm_name      = info["pm_name"]
        graph_id     = info["graph_project_id"]
        session_key  = f"hook:hazel:dashboard:{project_id}"
        graph_line   = f"Graph Project ID: {graph_id}" if graph_id else "Graph Project ID: (not linked — query by project name)"
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


# ── WEBHOOK ROUTES (secret-based auth, unchanged) ─────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "hazel-chat-webhook", "version": "6.0-epic-1"}), 200

@app.route("/webhook/chat", methods=["POST"])
def webhook_chat():
    secret = request.headers.get("X-Webhook-Secret") or request.args.get("secret")
    if secret != WEBHOOK_SECRET:
        return jsonify({"error": "unauthorized"}), 401
    payload    = request.get_json(force=True) or {}
    record     = payload.get("record") or payload.get("new") or payload
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

AGENTMAIL_KEY = os.getenv("AGENTMAIL_KEY", "")
HAZEL_INBOX   = "itshazel@agentmail.to"

def get_email_field(data, *keys):
    for k in keys:
        if k in data:
            return data[k]
    return None

@app.route("/webhook/email", methods=["POST"])
def webhook_email():
    payload    = request.get_json(force=True) or {}
    data       = payload.get("message") or payload.get("data") or payload
    event_type = payload.get("event_type") or payload.get("type", "message.received")
    if "message" not in event_type:
        return jsonify({"status": "ignored", "event_type": event_type}), 200
    thread_id  = get_email_field(data, "thread_id", "threadId")
    message_id = get_email_field(data, "message_id", "messageId", "id")
    sender     = get_email_field(data, "from", "sender", "from_address") or "unknown"
    subject    = get_email_field(data, "subject") or "(no subject)"
    body       = (
        get_email_field(data, "extracted_text", "text", "preview")
        or get_email_field(data, "html") or ""
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
        f"[Incoming email]\nFrom: {sender}\nSubject: {subject}\n"
        f"Thread ID: {thread_id}\nMessage ID: {message_id}\n"
        f"\n--- Message ---\n{body}\n"
        f"\n--- Reply instructions ---\n"
        f"To reply:\n  python3 skills/boh-dashboard/scripts/send_email.py \\\n"
        f"    --thread-id {thread_id} \\\n    --to \"{sender}\" \\\n"
        f"    --subject \"Re: {subject}\" \\\n    --text \"your reply here\"\n"
        f"\nTo start a new email:\n  python3 skills/boh-dashboard/scripts/send_email.py \\\n"
        f"    --to \"recipient@example.com\" --subject \"Subject\" --text \"body\"\n"
    )
    logging.info(f"Email from {sender} | thread={thread_id[:12]} | {subject[:60]}")
    t = threading.Thread(target=lambda: post_to_hazel(session_key, message), daemon=True)
    t.start()
    return jsonify({"status": "queued"}), 200


# ── PROTECTED API ROUTES (JWT required via @require_auth) ─────────────────────


@app.route("/api/firm/setup", methods=["POST"])
@require_auth
def api_firm_setup():
    """Creates a firm + firm_users row for a brand-new user. Called right after signup.
    Uses service role so no RLS issues on first insert. Idempotent: returns existing firm if found."""
    user_id = g.user_id
    # Idempotency: if user already has a firm, just return it
    existing_firm_id = get_firm_id_for_user(user_id)
    if existing_firm_id:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{existing_firm_id}", "select": "*", "limit": "1"},
            timeout=5,
        )
        data = r.json()
        return jsonify({"firm": data[0] if data else {}, "created": False}), 200

    body = request.get_json(silent=True) or {}
    firm_name = (body.get("firm_name") or "").strip()
    if not firm_name:
        return jsonify({"error": "firm_name is required"}), 400

    try:
        # Create firm (service role bypasses RLS)
        r_firm = requests.post(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json={"display_name": firm_name},
            timeout=5,
        )
        r_firm.raise_for_status()
        firm = r_firm.json()
        if not firm:
            return jsonify({"error": "Firm creation returned empty"}), 500
        firm = firm[0]

        # Link user as owner (service role)
        r_fu = requests.post(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal"},
            json={"firm_id": firm["id"], "user_id": user_id, "role": "owner"},
            timeout=5,
        )
        r_fu.raise_for_status()
        logging.info(f"api_firm_setup: created firm {firm['id']} for user {user_id}")
        return jsonify({"firm": firm, "created": True}), 201
    except Exception as e:
        logging.error(f"api_firm_setup: {e}")
        return jsonify({"error": "Firm setup failed"}), 500


@app.route("/api/firm-context", methods=["GET"])
@require_auth
def api_firm_context():
    """Returns firm profile for Hazel system prompt injection. AC-03."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{firm_id}", "select": "*", "limit": "1"},
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        if not data:
            return jsonify({"error": "Firm not found"}), 404
        return jsonify(data[0]), 200
    except Exception as e:
        logging.error(f"api_firm_context: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/team", methods=["GET"])
@require_auth
def api_team():
    """Returns members + pending invites for the caller's firm. AC-06."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    try:
        members_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "select": "id,user_id,role,created_at", "order": "created_at.asc"},
            timeout=5,
        )
        members_r.raise_for_status()
        members = members_r.json()

        invites_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/invite_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "used_at": "is.null", "select": "id,email,created_at,expires_at", "order": "created_at.desc"},
            timeout=5,
        )
        invites_r.raise_for_status()
        pending_invites = invites_r.json()

        # Enrich with email from auth.users
        user_emails = {}
        for m in members:
            uid = m["user_id"]
            try:
                u_r = requests.get(
                    f"{SUPABASE_URL}/auth/v1/admin/users/{uid}",
                    headers={**SB_HEADERS, "Content-Type": "application/json"},
                    timeout=5,
                )
                if u_r.ok:
                    user_emails[uid] = u_r.json().get("email", "")
            except Exception:
                pass

        members_out = [
            {"id": m["id"], "user_id": m["user_id"], "email": user_emails.get(m["user_id"], ""),
             "role": m["role"], "created_at": m["created_at"]}
            for m in members
        ]
        return jsonify({"members": members_out, "pending_invites": pending_invites}), 200
    except Exception as e:
        logging.error(f"api_team: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/invites", methods=["POST"])
@require_auth
def api_invites():
    """Creates invite token + sends Supabase Auth invite email. Owners only. AC-06."""
    user_id = g.user_id
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404

    body  = request.get_json(force=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email is required"}), 400

    # Verify caller is owner
    try:
        role_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{user_id}", "select": "role", "limit": "1"},
            timeout=5,
        )
        role_r.raise_for_status()
        role_data = role_r.json()
        if not role_data or role_data[0].get("role") != "owner":
            return jsonify({"error": "Only firm owners can send invites"}), 403
    except Exception as e:
        logging.error(f"api_invites role check: {e}")
        return jsonify({"error": "Internal server error"}), 500

    # Create invite token record
    token = str(uuid.uuid4())
    try:
        inv_r = requests.post(
            f"{SUPABASE_URL}/rest/v1/invite_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json={"firm_id": firm_id, "email": email, "token": token, "invited_by": user_id},
            timeout=5,
        )
        inv_r.raise_for_status()
    except Exception as e:
        logging.error(f"api_invites create token: {e}")
        return jsonify({"error": "Failed to create invite"}), 500

    # Send invite email via AgentMail (bypasses Supabase's 3/hr rate limit)
    invite_url = f"https://hazel.haventechsolutions.com/?invite_token={token}"
    try:
        if not AGENTMAIL_KEY:
            raise ValueError("AGENTMAIL_KEY not set")
        mail_r = requests.post(
            "https://api.agentmail.to/v0/inboxes/itshazel@agentmail.to/messages",
            headers={"Authorization": f"Bearer {AGENTMAIL_KEY}", "Content-Type": "application/json"},
            json={
                "to": [email],
                "subject": "You've been invited to Hazel",
                "text": f"You've been invited to join a firm on Hazel.\n\nAccept your invite:\n{invite_url}\n\nThis link expires in 72 hours.",
                "html": f"""<p>You've been invited to join a firm on <strong>Hazel</strong>.</p>
<p><a href="{invite_url}" style="background:#1e3a5f;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;display:inline-block;margin:8px 0;">Accept Invite</a></p>
<p style="color:#666;font-size:13px;">This link expires in 72 hours. If you didn't expect this, ignore this email.</p>""",
            },
            timeout=10,
        )
        if not mail_r.ok:
            logging.warning(f"api_invites AgentMail error {mail_r.status_code}: {mail_r.text[:200]}")
    except Exception as e:
        logging.warning(f"api_invites send email (non-fatal): {e}")

    logging.info(f"Invite sent to {email} for firm {firm_id[:8]}")
    return jsonify({"status": "invited", "token": token, "email": email}), 201


@app.route("/api/invites/accept", methods=["POST"])
@require_auth
def api_invites_accept():
    """Validates invite token, adds user to firm as member. AC-06."""
    from datetime import datetime, timezone
    user_id = g.user_id
    body    = request.get_json(force=True) or {}
    token   = (body.get("token") or "").strip()
    if not token:
        return jsonify({"error": "token is required"}), 400
    try:
        tok_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/invite_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"token": f"eq.{token}", "select": "*", "limit": "1"},
            timeout=5,
        )
        tok_r.raise_for_status()
        tok_data = tok_r.json()
        if not tok_data:
            return jsonify({"error": "Invalid invite token"}), 404
        invite = tok_data[0]
        if invite.get("used_at"):
            return jsonify({"error": "Invite token already used"}), 410
        expires_at = invite.get("expires_at")
        if expires_at:
            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp_dt:
                return jsonify({"error": "Invite token has expired"}), 410
        firm_id = invite["firm_id"]

        # Add to firm (ignore duplicate)
        requests.post(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json",
                     "Prefer": "return=representation,resolution=ignore-duplicates"},
            json={"firm_id": firm_id, "user_id": user_id, "role": "member",
                  "invited_by": invite.get("invited_by")},
            timeout=5,
        )

        # Mark token used
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/invite_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{invite['id']}"},
            json={"used_at": datetime.now(timezone.utc).isoformat()},
            timeout=5,
        )

        logging.info(f"Invite accepted: user {user_id[:8]} joined firm {firm_id[:8]}")
        return jsonify({"status": "accepted", "firm_id": firm_id}), 200
    except Exception as e:
        logging.error(f"api_invites_accept: {e}")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8700, threaded=True)

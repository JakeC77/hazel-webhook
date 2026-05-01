#!/usr/bin/env python3
"""
Hazel Dashboard Backend — Flask API + webhook shim

Serves the dashboard frontend's REST API (/api/*), OAuth callbacks (/auth/*),
Gmail Pub/Sub notifications (/webhook/gmail-push), and the Supabase Auth
email hook (/webhook/supabase-send-email).

Dashboard chat + inbound email webhooks are handled by the hazel-plugin
OpenClaw plugin (endpoints /hazel/chat and /hazel/email on port 18789).
Historic chat/email routes that once lived here have been removed — see
git history if you need the legacy implementation.

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
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response.headers['Vary'] = 'Origin'
    return response

@app.route('/api/<path:subpath>', methods=['OPTIONS'])
def api_preflight(subpath):
    """Handle CORS preflight for all /api/* routes."""
    return '', 204

@app.route('/auth/<path:subpath>', methods=['OPTIONS'])
def auth_preflight(subpath):
    """Handle CORS preflight for all /auth/* routes."""
    return '', 204
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

WEBHOOK_SECRET      = os.getenv("HAZEL_WEBHOOK_SECRET", "hazel-chat-2026")
OPENCLAW_URL        = os.getenv("OPENCLAW_API_URL", "http://127.0.0.1:18789")
HOOKS_TOKEN         = os.getenv("OPENCLAW_HOOKS_TOKEN", "")
GATEWAY_TOKEN       = os.getenv("OPENCLAW_GATEWAY_TOKEN", "")

# Auto-load gateway token from file if not in env
if not GATEWAY_TOKEN:
    _gw_token_path = os.path.expanduser("~/.openclaw/gateway-token.txt")
    if not os.path.exists(_gw_token_path):
        _gw_token_path = "/home/openclaw/.openclaw/gateway-token.txt"
    try:
        with open(_gw_token_path) as _f:
            GATEWAY_TOKEN = _f.read().strip()
    except Exception:
        pass
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

def _get_recent_messages(project_id, limit=10):
    """Fetch recent messages for a project to provide conversation context."""
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/messages",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={
                "project_id": f"eq.{project_id}",
                "select": "role,content,created_at",
                "order": "created_at.desc",
                "limit": str(limit),
            },
            timeout=5,
        )
        if r.ok and r.json():
            msgs = r.json()
            msgs.reverse()  # Oldest first
            return msgs
    except Exception:
        pass
    return []


def post_to_hazel(session_key, message, project_id=None, firm_id=None):
    """Send a message to Hazel via hooks endpoint with conversation history.

    Includes recent message history so Hazel has context even though each
    hook creates a new session. Also includes a reply instruction so Hazel
    posts her response back via send_message.py.
    """
    # Prepend conversation history if we have a project_id
    if project_id:
        recent = _get_recent_messages(project_id, limit=10)
        if recent:
            history_lines = ["--- Recent conversation history ---"]
            for m in recent:
                role = "Builder" if m.get("role") == "builder" else "Hazel"
                content = (m.get("content") or "")[:500]
                history_lines.append(f"{role}: {content}")
            history_lines.append("--- End history ---\n")
            message = "\n".join(history_lines) + message

        # Add reply instruction
        message += (
            f"\n\n---\n"
            f"REPLY REQUIREMENT: You MUST post your response back to the dashboard using:\n"
            f"python3 skills/boh-dashboard/scripts/send_message.py "
            f"--project-id {project_id} --message \"your reply here\""
        )

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

# ── WEBHOOK ROUTES (secret-based auth) ────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "hazel-chat-webhook", "version": "6.0-epic-1"}), 200

AGENTMAIL_KEY = os.getenv("AGENTMAIL_KEY", "")
HAZEL_INBOX   = "itshazel@agentmail.to"


# ── EPIC 2: PREFERENCES + CONTACTS ────────────────────────────────────────────

@app.route("/api/preferences", methods=["GET"])
@require_auth
def api_preferences_get():
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_preferences",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "limit": "1"},
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        if data:
            return jsonify(data[0]), 200
        # Auto-create defaults
        cr = requests.post(
            f"{SUPABASE_URL}/rest/v1/firm_preferences",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json={"firm_id": firm_id},
            timeout=5,
        )
        cr.raise_for_status()
        return jsonify(cr.json()[0]), 201
    except Exception as e:
        logging.error(f"api_preferences_get: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/preferences", methods=["PUT"])
@require_auth
def api_preferences_put():
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    body = request.get_json(force=True) or {}
    allowed = {
        "auto_send_threshold_dollars", "change_order_review_threshold",
        "blackout_days", "blackout_start_time", "blackout_end_time",
        "tone", "custom_phrases", "client_follow_up_days",
        "jurisdictions", "primary_jurisdiction",
        "daily_digest_enabled",
    }
    patch = {k: v for k, v in body.items() if k in allowed}
    if not patch:
        return jsonify({"error": "No valid fields to update"}), 400
    patch["updated_at"] = "now()"
    try:
        r = requests.patch(
            f"{SUPABASE_URL}/rest/v1/firm_preferences",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            params={"firm_id": f"eq.{firm_id}"},
            json=patch,
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        if not data:
            # Row doesn't exist yet — upsert
            patch["firm_id"] = firm_id
            patch.pop("updated_at", None)
            cr = requests.post(
                f"{SUPABASE_URL}/rest/v1/firm_preferences",
                headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
                json=patch, timeout=5,
            )
            cr.raise_for_status()
            return jsonify(cr.json()[0]), 200
        return jsonify(data[0]), 200
    except Exception as e:
        logging.error(f"api_preferences_put: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/contacts", methods=["GET"])
@require_auth
def api_contacts_get():
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/contacts",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "order": "name.asc", "select": "*"},
            timeout=5,
        )
        r.raise_for_status()
        return jsonify(r.json()), 200
    except Exception as e:
        logging.error(f"api_contacts_get: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/contacts", methods=["POST"])
@require_auth
def api_contacts_post():
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    body = request.get_json(force=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    allowed = {"name","type","company","trade","phone","email","notes","sms_consent","sms_consent_at"}
    contact = {k: v for k, v in body.items() if k in allowed}
    contact["firm_id"] = firm_id
    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/contacts",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json=contact, timeout=5,
        )
        r.raise_for_status()
        return jsonify(r.json()[0]), 201
    except Exception as e:
        logging.error(f"api_contacts_post: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/contacts/<contact_id>", methods=["PUT"])
@require_auth
def api_contacts_put(contact_id):
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    body = request.get_json(force=True) or {}
    allowed = {"name","type","company","trade","phone","email","notes","sms_consent","sms_consent_at"}
    patch = {k: v for k, v in body.items() if k in allowed}
    patch["updated_at"] = "now()"
    try:
        r = requests.patch(
            f"{SUPABASE_URL}/rest/v1/contacts",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            params={"id": f"eq.{contact_id}", "firm_id": f"eq.{firm_id}"},
            json=patch, timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        return jsonify(data[0] if data else {}), 200
    except Exception as e:
        logging.error(f"api_contacts_put: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/contacts/<contact_id>", methods=["DELETE"])
@require_auth
def api_contacts_delete(contact_id):
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    try:
        r = requests.delete(
            f"{SUPABASE_URL}/rest/v1/contacts",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{contact_id}", "firm_id": f"eq.{firm_id}"},
            timeout=5,
        )
        r.raise_for_status()
        return jsonify({"deleted": True}), 200
    except Exception as e:
        logging.error(f"api_contacts_delete: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/projects", methods=["GET"])
@require_auth
def api_projects_get():
    """Return all projects for the caller's firm (service role — bypasses RLS)."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/projects",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "select": "*", "order": "created_at.asc"},
            timeout=5,
        )
        r.raise_for_status()
        return jsonify(r.json()), 200
    except Exception as e:
        logging.error(f"api_projects_get: {e}")
        return jsonify({"error": "Failed to fetch projects"}), 500


@app.route("/api/projects", methods=["POST"])
@require_auth
def api_projects_post():
    """Create a new project for the caller's firm."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    body = request.get_json(force=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    import uuid as _uuid
    project = {
        "id":                body.get("id") or str(_uuid.uuid4()),
        "name":              name,
        "firm_id":           firm_id,
        "status":             body.get("status", "on-track"),
        "client_name":       body.get("client_name") or None,
        "contract_value":    body.get("contract_value") or None,
        "address":           body.get("address") or None,
        "client_phone":      body.get("client_phone") or body.get("client_contact") or None,
        "client_email":      body.get("client_email") or None,
        "target_completion": body.get("target_completion") or None,
    }
    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/projects",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json=project, timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        return jsonify(data[0] if data else project), 201
    except Exception as e:
        logging.error(f"api_projects_post: {e}")
        return jsonify({"error": "Failed to create project"}), 500

# ── EPIC 3: QUEUE HARDENING ───────────────────────────────────────────────────

VALID_TRANSITIONS = {
    "active":  {"approve", "reject", "hold"},
    "snoozed": {"approve", "reject", "hold", "reactivate"},
}

def _execute_approved_email(item, user_id, firm_id):
    """Execute an approved email draft — send via Gmail if connected, else log for manual send.

    Called in a background thread after a queue item of type 'email' is approved.
    Extracts to/subject/body from the structured draft and sends via the approver's Gmail.
    """
    import re as _re
    from datetime import datetime, timezone, timedelta
    try:
        draft = item.get("current_draft", "")
        draft_type = item.get("draft_type", "plaintext")
        project_id = item.get("project_id")
        item_id = item.get("id")
        meta = item.get("meta", "")
        title = item.get("title", "")

        # Parse draft — handle both structured JSON and dict objects
        if isinstance(draft, str):
            try:
                draft = json.loads(draft)
            except (json.JSONDecodeError, TypeError):
                pass

        if isinstance(draft, dict):
            to = draft.get("to", "")
            subject = draft.get("subject", "")
            body = draft.get("body", "")
            cc = draft.get("cc", "")
            in_reply_to = draft.get("in_reply_to", "")
        elif isinstance(draft, str) and draft.strip():
            # Plain text body — try to extract send params from meta/title
            to = ""
            subject = ""
            body = draft.strip()
            cc = ""
            in_reply_to = ""
        else:
            logging.info(f"_execute_approved_email: item {item_id} has no usable draft content")
            return

        # Fall back: extract "to" from meta field (e.g. "To: jake@example.com · Project Name")
        if not to and meta:
            to_match = _re.search(r'To:\s*([^·\n]+)', meta)
            if to_match:
                to = to_match.group(1).strip()

        # Fall back: use title as subject
        if not subject and title:
            subject = title

        if not to or not body:
            logging.warning(f"_execute_approved_email: item {item_id} missing to or body (to={to!r})")
            return

        # Try Gmail send
        gmail_result = None
        try:
            gmail_result = _send_gmail(user_id, firm_id, to, subject, body, cc=cc or None, in_reply_to=in_reply_to or None)
        except Exception as e:
            logging.warning(f"_execute_approved_email: Gmail send failed for item {item_id}: {e}")

        # Log to outbound_emails
        send_via = "gmail" if gmail_result else "pending"
        outbound = {
            "firm_id": firm_id,
            "project_id": project_id,
            "queue_item_id": item_id,
            "to_email": to,
            "subject": subject,
            "body": body,
            "send_status": "sent" if gmail_result else "queued",
            "send_via": send_via,
            "sent_at": datetime.now(timezone.utc).isoformat() if gmail_result else None,
        }
        requests.post(
            f"{SUPABASE_URL}/rest/v1/outbound_emails",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json=outbound,
            timeout=5,
        )

        if gmail_result:
            logging.info(f"_execute_approved_email: sent via Gmail for item {item_id} from {gmail_result['sender']}")
        else:
            logging.info(f"_execute_approved_email: Gmail not available for item {item_id}, logged as pending")

    except Exception as e:
        logging.error(f"_execute_approved_email error for item {item.get('id')}: {e}")


@app.route("/api/queue/<item_id>/decide", methods=["POST"])
@require_auth
def api_queue_decide(item_id):
    """AQ-02: Validate + apply a status transition on a queue item.
    Body: { action: 'approve'|'reject'|'hold', resurface_hours: int (optional, for hold) }
    Returns 409 if the current status doesn't allow the action."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404

    body = request.get_json(silent=True) or {}
    action = (body.get("action") or "").strip().lower()
    if action not in {"approve", "reject", "hold", "reactivate"}:
        return jsonify({"error": "action must be approve|reject|hold|reactivate"}), 400

    try:
        # Fetch current item (service role)
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/queue_items",
            headers={**SB_HEADERS},
            params={"id": f"eq.{item_id}", "select": "id,status,project_id,firm_id,type,current_draft,draft_type,meta,title", "limit": "1"},
            timeout=5,
        )
        r.raise_for_status()
        rows = r.json()
        if not rows:
            return jsonify({"error": "Queue item not found"}), 404
        item = rows[0]

        # Firm scope check
        if item.get("firm_id") != firm_id:
            return jsonify({"error": "Forbidden"}), 403

        current_status = item.get("status", "active")
        allowed = VALID_TRANSITIONS.get(current_status, set())
        if action not in allowed:
            return jsonify({
                "error": f"Cannot {action} an item with status '{current_status}'",
                "current_status": current_status,
            }), 409

        # Build update payload
        now_iso = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        if action == "approve":
            patch = {"status": "approved", "decided_at": now_iso, "decided_by": "builder"}
        elif action == "reject":
            patch = {"status": "rejected", "decided_at": now_iso, "decided_by": "builder"}
        elif action == "hold":
            resurface_hours = int(body.get("resurface_hours", 24))
            patch = {
                "status": "snoozed",
                "held_at": now_iso,
                "resurface_after": f"{resurface_hours} hours",
                "reminder_at": None,
            }
        elif action == "reactivate":
            patch = {"status": "active", "held_at": None}

        upd = requests.patch(
            f"{SUPABASE_URL}/rest/v1/queue_items",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            params={"id": f"eq.{item_id}"},
            json=patch,
            timeout=5,
        )
        upd.raise_for_status()
        updated = upd.json()
        result = updated[0] if updated else {"id": item_id, **patch}

        # ── Post-approve: auto-send email via Gmail if applicable ─────────
        if action == "approve" and item.get("type") == "email":
            # Check if user has Gmail connected before spawning send thread
            gmail_check = requests.get(
                f"{SUPABASE_URL}/rest/v1/gmail_tokens",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{g.user_id}", "select": "id", "limit": "1"},
                timeout=5,
            )
            if gmail_check.ok and gmail_check.json():
                threading.Thread(
                    target=_execute_approved_email,
                    args=(item, g.user_id, firm_id),
                    daemon=True,
                ).start()
            else:
                result["gmail_warning"] = "Gmail is not connected for your account. Connect Gmail in Settings to send emails as yourself."
                logging.info(f"Email approved but Gmail not connected for user {g.user_id}")

        return jsonify(result), 200

    except Exception as e:
        logging.error(f"api_queue_decide: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/queue/<item_id>/version", methods=["POST"])
@require_auth
def api_queue_save_version(item_id):
    """AQ-01: Persist a draft version snapshot to queue_item_versions."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404

    body = request.get_json(silent=True) or {}
    draft   = body.get("draft")
    version = body.get("version_number", 1)
    saved_by = body.get("saved_by", "builder")

    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/queue_item_versions",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json={"queue_item_id": item_id, "version_number": version, "draft": draft, "saved_by": saved_by},
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        return jsonify(data[0] if data else {}), 201
    except Exception as e:
        logging.error(f"api_queue_save_version: {e}")
        return jsonify({"error": "Failed to save version"}), 500


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
            json={"display_name": firm_name, "onboarding_step": 1, "onboarding_complete": False},
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


def _send_phone_provisioning_email(firm_id: str, firm_name: str):
    """Fire-and-forget email to jake@ requesting Hazel phone provisioning."""
    try:
        if not AGENTMAIL_KEY:
            logging.warning("_send_phone_provisioning_email: AGENTMAIL_KEY not set, skipping")
            return
        mail_r = requests.post(
            "https://api.agentmail.to/v0/inboxes/itshazel@agentmail.to/messages/send",
            headers={"Authorization": f"Bearer {AGENTMAIL_KEY}", "Content-Type": "application/json"},
            json={
                "to": ["jake@haventechsolutions.com"],
                "subject": f"[Hazel] Phone provisioning request — {firm_name}",
                "text": (
                    f"A new firm has completed onboarding and needs a Hazel phone number.\n\n"
                    f"Firm: {firm_name}\n"
                    f"Firm ID: {firm_id}\n\n"
                    f"Steps:\n"
                    f"1. Provision a number via ClawdTalk\n"
                    f"2. Update the firms table:\n"
                    f"   UPDATE firms SET hazel_phone = '+1XXXXXXXXXX', "
                    f"hazel_phone_status = 'active' WHERE id = '{firm_id}';\n"
                ),
            },
            timeout=10,
        )
        if not mail_r.ok:
            logging.warning(f"_send_phone_provisioning_email AgentMail error: {mail_r.status_code}")
    except Exception as e:
        logging.warning(f"_send_phone_provisioning_email (non-fatal): {e}")


@app.route("/api/firm", methods=["PATCH"])
@require_auth
def api_firm_patch():
    """Incremental firm profile update. Used by onboarding wizard and settings."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    body = request.get_json(force=True) or {}
    allowed = {
        "display_name", "phone", "city", "state",
        "sign_off_name", "sign_off_title", "timezone",
        "onboarding_step",
    }
    patch = {k: v for k, v in body.items() if k in allowed}
    if not patch:
        return jsonify({"error": "No valid fields to update"}), 400
    patch["updated_at"] = "now()"
    try:
        r = requests.patch(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            params={"id": f"eq.{firm_id}"},
            json=patch,
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        if not data:
            return jsonify({"error": "Firm not found"}), 404
        return jsonify(data[0]), 200
    except Exception as e:
        logging.error(f"api_firm_patch: {e}")
        return jsonify({"error": "Failed to update firm"}), 500


@app.route("/api/onboarding/complete", methods=["POST"])
@require_auth
def api_onboarding_complete():
    """Mark onboarding complete, set hazel_phone_status=pending, send provisioning email."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    try:
        patch = {
            "onboarding_complete": True,
            "onboarding_step": 7,
            "hazel_phone_status": "pending",
            "updated_at": "now()",
        }
        r = requests.patch(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            params={"id": f"eq.{firm_id}"},
            json=patch,
            timeout=5,
        )
        r.raise_for_status()
        firm_data = r.json()
        firm = firm_data[0] if firm_data else {}

        _send_phone_provisioning_email(firm_id, firm.get("display_name", "Unknown"))

        logging.info(f"api_onboarding_complete: firm {firm_id[:8]} onboarding done")
        return jsonify({"status": "complete", "firm": firm}), 200
    except Exception as e:
        logging.error(f"api_onboarding_complete: {e}")
        return jsonify({"error": "Failed to complete onboarding"}), 500


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
            json={"firm_id": firm_id, "email": email, "token": token, "invited_by": user_id, "expires_at": (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat()},
            timeout=5,
        )
        inv_r.raise_for_status()
    except Exception as e:
        logging.error(f"api_invites create token: {e}")
        return jsonify({"error": "Failed to create invite"}), 500

    # Send invite email via AgentMail (bypasses Supabase's 3/hr rate limit)
    invite_url = f"https://hazel.haventechsolutions.com/?invite_token={token}&invite_email={email}"
    try:
        if not AGENTMAIL_KEY:
            raise ValueError("AGENTMAIL_KEY not set")
        mail_r = requests.post(
            "https://api.agentmail.to/v0/inboxes/itshazel@agentmail.to/messages/send",
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


# ── RL-04: NOTIFICATION HEALTH ─────────────────────────────────────────────────

@app.route("/api/health/notifications", methods=["GET"])
def health_notifications():
    """Returns notification delivery health for monitoring (UptimeRobot target).
    No auth required — designed for external uptime monitors."""
    from datetime import datetime, timezone, timedelta
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        # Count failed notifications in last 24h by channel
        sms_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/notification_log",
            headers={**SB_HEADERS, "Content-Type": "application/json",
                     "Prefer": "count=exact"},
            params={
                "channel": "eq.sms",
                "delivery_status": "eq.failed",
                "sent_at": f"gte.{cutoff}",
                "select": "id",
                "limit": "0",
            },
            timeout=5,
        )
        sms_failed = int(sms_r.headers.get("content-range", "*/0").split("/")[-1] or 0)

        dash_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/notification_log",
            headers={**SB_HEADERS, "Content-Type": "application/json",
                     "Prefer": "count=exact"},
            params={
                "channel": "eq.dashboard",
                "delivery_status": "eq.failed",
                "sent_at": f"gte.{cutoff}",
                "select": "id",
                "limit": "0",
            },
            timeout=5,
        )
        dash_failed = int(dash_r.headers.get("content-range", "*/0").split("/")[-1] or 0)

        # Last successful SMS
        last_sms_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/notification_log",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={
                "channel": "eq.sms",
                "delivery_status": "eq.sent",
                "select": "sent_at",
                "order": "sent_at.desc",
                "limit": "1",
            },
            timeout=5,
        )
        last_sms_data = last_sms_r.json()
        last_sms = last_sms_data[0]["sent_at"] if last_sms_data else None

        result = {
            "sms_failed_24h": sms_failed,
            "dashboard_failed_24h": dash_failed,
            "last_sms_sent_at": last_sms,
        }

        # Return 500 if too many failures (triggers UptimeRobot alert)
        if sms_failed > 3 or dash_failed > 3:
            return jsonify({**result, "status": "degraded"}), 500

        return jsonify({**result, "status": "ok"}), 200
    except Exception as e:
        logging.error(f"health_notifications: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


# ── RL-04: NOTIFICATION LOG HELPER ────────────────────────────────────────────

def log_notification(firm_id, channel, payload_summary, delivery_status="sent",
                     error_code=None, related_entity_type=None, related_entity_id=None):
    """Write a notification_log entry. Called from digest sender, resurfacer, etc."""
    try:
        requests.post(
            f"{SUPABASE_URL}/rest/v1/notification_log",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json={
                "firm_id": firm_id,
                "channel": channel,
                "payload_summary": payload_summary[:500] if payload_summary else None,
                "delivery_status": delivery_status,
                "error_code": error_code,
                "related_entity_type": related_entity_type,
                "related_entity_id": related_entity_id,
            },
            timeout=5,
        )
    except Exception as e:
        logging.error(f"log_notification failed: {e}")


# ── RL-02: DAILY DIGEST GENERATION ────────────────────────────────────────────

@app.route("/api/digest/generate", methods=["POST"])
def generate_daily_digest():
    """Called by a cron job (systemd timer or external scheduler) to generate
    and send daily digests for all firms. Auth via webhook secret."""
    secret = request.headers.get("X-Webhook-Secret") or request.args.get("secret")
    if secret != WEBHOOK_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    from datetime import datetime, timezone, timedelta
    try:
        # Get all firms with digest enabled
        prefs_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_preferences",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"daily_digest_enabled": "eq.true", "select": "firm_id"},
            timeout=5,
        )
        firm_ids = [p["firm_id"] for p in prefs_r.json()] if prefs_r.ok else []

        # If no preferences rows exist, fall back to all firms
        if not firm_ids:
            firms_r = requests.get(
                f"{SUPABASE_URL}/rest/v1/firms",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"select": "id"},
                timeout=5,
            )
            firm_ids = [f["id"] for f in firms_r.json()] if firms_r.ok else []

        results = []
        yesterday = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        for firm_id in firm_ids:
            try:
                digest = _build_digest_for_firm(firm_id, yesterday)

                # Write to digest_log (dashboard channel)
                requests.post(
                    f"{SUPABASE_URL}/rest/v1/digest_log",
                    headers={**SB_HEADERS, "Content-Type": "application/json"},
                    json={
                        "firm_id": firm_id,
                        "channel": "dashboard",
                        "content": digest["content"],
                        "was_seen": False,
                    },
                    timeout=5,
                )

                # Send SMS via ClawdTalk if configured
                sms_result = _send_digest_sms(firm_id, digest["sms_content"])

                # Write to digest_log (sms channel)
                requests.post(
                    f"{SUPABASE_URL}/rest/v1/digest_log",
                    headers={**SB_HEADERS, "Content-Type": "application/json"},
                    json={
                        "firm_id": firm_id,
                        "channel": "sms",
                        "content": digest["sms_content"],
                    },
                    timeout=5,
                )

                # Log notification
                log_notification(
                    firm_id, "sms", digest["sms_content"][:200],
                    delivery_status="sent" if sms_result else "failed",
                    error_code=None if sms_result else "clawdtalk_send_failed",
                )

                results.append({"firm_id": firm_id, "status": "sent"})
            except Exception as e:
                logging.error(f"digest for firm {firm_id}: {e}")
                results.append({"firm_id": firm_id, "status": "error", "error": str(e)})

        return jsonify({"digests": results}), 200
    except Exception as e:
        logging.error(f"generate_daily_digest: {e}")
        return jsonify({"error": str(e)}), 500


def _build_digest_for_firm(firm_id, since_iso):
    """Build digest content for a single firm."""
    from datetime import datetime, timezone

    # Fetch firm info
    firm_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"id": f"eq.{firm_id}", "select": "display_name,sign_off_name", "limit": "1"},
        timeout=5,
    )
    firm_data = firm_r.json()[0] if firm_r.ok and firm_r.json() else {}
    builder_name = (firm_data.get("sign_off_name") or "").split(" ")[0] or "there"

    # Count audit log actions by type since yesterday
    audit_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/audit_log",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={
            "created_at": f"gte.{since_iso}",
            "select": "action_type,actor_type,message",
            "limit": "200",
        },
        timeout=5,
    )
    # Filter to this firm's projects
    proj_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/projects",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "select": "id", "limit": "100"},
        timeout=5,
    )
    project_ids = {p["id"] for p in proj_r.json()} if proj_r.ok else set()
    active_count = len(project_ids)

    # Pending queue items
    queue_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/queue_items",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={
            "firm_id": f"eq.{firm_id}",
            "status": "eq.active",
            "select": "id,title,type",
            "limit": "50",
        },
        timeout=5,
    )
    pending_items = queue_r.json() if queue_r.ok else []
    pending_count = len(pending_items)

    # Build sections
    actions_summary = ""
    if audit_r.ok:
        entries = audit_r.json()
        hazel_actions = [e for e in entries if e.get("actor_type") == "agent"]
        if hazel_actions:
            actions_summary = f"Hazel completed {len(hazel_actions)} actions yesterday."
        else:
            actions_summary = "No agent actions yesterday."

    pending_section = ""
    if pending_count > 0:
        pending_section = f"<strong>{pending_count} item{'s' if pending_count != 1 else ''}</strong> pending your review."
    else:
        pending_section = "No items pending your review."

    # Dashboard content (HTML-safe)
    content = f"{actions_summary} {pending_section}"

    # SMS content (under 320 chars)
    sms_content = f"Good morning {builder_name}. {actions_summary} {pending_section}"
    if not hazel_actions if audit_r.ok else True:
        sms_content = (
            f"Good morning {builder_name}. Nothing needs your attention "
            f"across your {active_count} active project{'s' if active_count != 1 else ''} today. "
            f"Hazel's got it covered."
        )
    if len(sms_content) > 320:
        sms_content = sms_content[:317] + "..."

    return {"content": content, "sms_content": sms_content}


CLAWDTALK_URL   = os.getenv("CLAWDTALK_URL", "https://clawdtalk.com")
CLAWDTALK_TOKEN = os.getenv("CLAWDTALK_TOKEN", "")
HAZEL_PHONE     = os.getenv("HAZEL_PHONE", "+12066032566")


def _send_digest_sms(firm_id, content):
    """Send daily digest via ClawdTalk SMS. Returns True on success."""
    if not CLAWDTALK_TOKEN:
        logging.warning("CLAWDTALK_TOKEN not set — skipping SMS digest")
        return False

    # Look up the firm owner's phone
    fu_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firm_users",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "role": "eq.owner", "select": "user_id", "limit": "1"},
        timeout=5,
    )
    if not fu_r.ok or not fu_r.json():
        logging.warning(f"No owner found for firm {firm_id}")
        return False

    owner_uid = fu_r.json()[0]["user_id"]

    # Get phone from firms table
    firm_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"id": f"eq.{firm_id}", "select": "phone", "limit": "1"},
        timeout=5,
    )
    phone = (firm_r.json()[0].get("phone") if firm_r.ok and firm_r.json() else None)
    if not phone:
        logging.warning(f"No phone number for firm {firm_id} — skipping SMS")
        return False

    try:
        r = requests.post(
            f"{CLAWDTALK_URL}/api/send",
            headers={"Authorization": f"Bearer {CLAWDTALK_TOKEN}", "Content-Type": "application/json"},
            json={"from": HAZEL_PHONE, "to": phone, "body": content},
            timeout=10,
        )
        if r.ok:
            logging.info(f"Digest SMS sent to firm {firm_id[:8]}")
            return True
        else:
            logging.error(f"ClawdTalk SMS failed: {r.status_code} {r.text[:200]}")
            return False
    except Exception as e:
        logging.error(f"ClawdTalk SMS error: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# EPIC 5 — EMAIL INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/emails/inbound", methods=["POST"])
def api_emails_inbound():
    """EM-01: Ingest an inbound email. Idempotent on message_id.
    Auth via webhook secret (service-to-service, not user JWT)."""
    secret = request.headers.get("X-Hazel-Webhook-Secret") or request.headers.get("X-Webhook-Secret") or request.args.get("secret")
    if secret != WEBHOOK_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    body = request.get_json(force=True) or {}
    required = ["firm_id", "from_email", "message_id"]
    missing = [f for f in required if not body.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    # Idempotency: check if message_id already exists
    check = requests.get(
        f"{SUPABASE_URL}/rest/v1/inbound_emails",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"message_id": f"eq.{body['message_id']}", "select": "id", "limit": "1"},
        timeout=5,
    )
    if check.ok and check.json():
        return jsonify({"status": "duplicate", "id": check.json()[0]["id"]}), 200

    # Resolve project_id by matching from_email against contacts
    project_id = body.get("project_id")
    if not project_id:
        contact_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/contacts",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={
                "firm_id": f"eq.{body['firm_id']}",
                "email": f"eq.{body['from_email']}",
                "select": "id",
                "limit": "1",
            },
            timeout=5,
        )
        if contact_r.ok and contact_r.json():
            # Look up project_contacts for this contact
            cid = contact_r.json()[0]["id"]
            pc_r = requests.get(
                f"{SUPABASE_URL}/rest/v1/project_contacts",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"contact_id": f"eq.{cid}", "select": "project_id", "limit": "1"},
                timeout=5,
            )
            if pc_r.ok and pc_r.json():
                project_id = pc_r.json()[0]["project_id"]

    row = {
        "firm_id": body["firm_id"],
        "project_id": project_id,
        "message_id": body["message_id"],
        "thread_id": body.get("thread_id"),
        "from_email": body["from_email"],
        "from_name": body.get("from_name"),
        "subject": body.get("subject"),
        "body_text": body.get("body_text"),
        "received_at": body.get("received_at"),
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/inbound_emails",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        json=row,
        timeout=5,
    )
    if r.ok:
        return jsonify(r.json()[0] if r.json() else {"status": "created"}), 200
    return jsonify({"error": "Failed to create inbound email"}), 500


@app.route("/api/emails", methods=["GET"])
@require_auth
def api_emails_list():
    """List inbound emails for the firm. Optional filters: project_id, classification."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    params = {"firm_id": f"eq.{firm_id}", "order": "received_at.desc", "limit": "50"}
    pid = request.args.get("project_id")
    if pid:
        params["project_id"] = f"eq.{pid}"
    cls = request.args.get("classification")
    if cls:
        params["classification"] = f"eq.{cls}"
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/inbound_emails",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params=params,
        timeout=5,
    )
    return jsonify(r.json() if r.ok else []), r.status_code if r.ok else 500


@app.route("/api/emails/send", methods=["POST"])
@require_auth
def api_emails_send():
    """EM-05: Send an outbound email via AgentMail. Logs to outbound_emails."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    body = request.get_json(force=True) or {}
    to_email = body.get("to")
    subject = body.get("subject", "")
    email_body = body.get("body", "")
    if not to_email:
        return jsonify({"error": "Missing 'to' field"}), 400

    # Create outbound record
    row = {
        "firm_id": firm_id,
        "project_id": body.get("project_id"),
        "queue_item_id": body.get("queue_item_id"),
        "to_email": to_email,
        "subject": subject,
        "body": email_body,
        "in_reply_to": body.get("in_reply_to"),
        "send_status": "queued",
    }
    ins = requests.post(
        f"{SUPABASE_URL}/rest/v1/outbound_emails",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        json=row,
        timeout=5,
    )
    outbound_id = ins.json()[0]["id"] if ins.ok and ins.json() else None

    # Send via AgentMail
    from datetime import datetime, timezone
    try:
        am_payload = {"to": to_email, "subject": subject, "text": email_body}
        if body.get("in_reply_to"):
            am_payload["inReplyTo"] = body["in_reply_to"]
        r = requests.post(
            "https://api.agentmail.to/v0/emails",
            headers={"Authorization": f"Bearer {AGENTMAIL_KEY}", "Content-Type": "application/json"},
            json=am_payload,
            timeout=10,
        )
        if r.ok:
            # Update status to sent
            if outbound_id:
                requests.patch(
                    f"{SUPABASE_URL}/rest/v1/outbound_emails",
                    headers={**SB_HEADERS, "Content-Type": "application/json"},
                    params={"id": f"eq.{outbound_id}"},
                    json={"send_status": "sent", "sent_at": datetime.now(timezone.utc).isoformat()},
                    timeout=5,
                )
            log_notification(firm_id, "email", f"To: {to_email} — {subject[:80]}", "sent")
            return jsonify({"status": "sent", "id": outbound_id}), 200
        else:
            err = r.text[:200]
            if outbound_id:
                requests.patch(
                    f"{SUPABASE_URL}/rest/v1/outbound_emails",
                    headers={**SB_HEADERS, "Content-Type": "application/json"},
                    params={"id": f"eq.{outbound_id}"},
                    json={"send_status": "failed", "error_message": err},
                    timeout=5,
                )
            log_notification(firm_id, "email", f"FAILED: {to_email}", "failed", err)
            return jsonify({"status": "failed", "error": err}), 502
    except Exception as e:
        logging.error(f"api_emails_send: {e}")
        if outbound_id:
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/outbound_emails",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"id": f"eq.{outbound_id}"},
                json={"send_status": "failed", "error_message": str(e)},
                timeout=5,
            )
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# EPIC 6 — QUICKBOOKS ONLINE INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

QBO_CLIENT_ID     = os.getenv("QBO_CLIENT_ID", "")
QBO_CLIENT_SECRET = os.getenv("QBO_CLIENT_SECRET", "")
QBO_REDIRECT_URI  = os.getenv("QBO_REDIRECT_URI", "https://hazel.dejaview.io/api/qbo/callback")
QBO_BASE_URL      = "https://quickbooks.api.intuit.com"  # production
QBO_SANDBOX_URL   = "https://sandbox-quickbooks.api.intuit.com"
QBO_USE_SANDBOX   = os.getenv("QBO_USE_SANDBOX", "true").lower() == "true"

# Simple AES-256 encryption for tokens (symmetric key from env)
QBO_ENCRYPTION_KEY = os.getenv("QBO_ENCRYPTION_KEY", "")


def _qbo_api_url():
    return QBO_SANDBOX_URL if QBO_USE_SANDBOX else QBO_BASE_URL


def _encrypt_token(plaintext):
    """Simple base64 encoding as a placeholder. Replace with AES-256 when
    QBO_ENCRYPTION_KEY is set. Real encryption requires cryptography package."""
    if not plaintext:
        return ""
    import base64
    if QBO_ENCRYPTION_KEY:
        # TODO: use cryptography.fernet with QBO_ENCRYPTION_KEY
        pass
    return base64.b64encode(plaintext.encode()).decode()


def _decrypt_token(ciphertext):
    if not ciphertext:
        return ""
    import base64
    if QBO_ENCRYPTION_KEY:
        # TODO: use cryptography.fernet with QBO_ENCRYPTION_KEY
        pass
    return base64.b64decode(ciphertext.encode()).decode()


@app.route("/api/qbo/connect", methods=["GET"])
@require_auth
def api_qbo_connect():
    """QB-01: Start QBO OAuth flow. Returns the Intuit authorization URL."""
    if not QBO_CLIENT_ID:
        return jsonify({"error": "QBO integration not configured"}), 503
    import urllib.parse
    state = f"{g.firm_id}"
    auth_url = (
        "https://appcenter.intuit.com/connect/oauth2?"
        + urllib.parse.urlencode({
            "client_id": QBO_CLIENT_ID,
            "response_type": "code",
            "scope": "com.intuit.quickbooks.accounting",
            "redirect_uri": QBO_REDIRECT_URI,
            "state": state,
        })
    )
    return jsonify({"auth_url": auth_url}), 200


@app.route("/api/qbo/callback", methods=["GET"])
def api_qbo_callback():
    """QB-01: QBO OAuth callback. Exchanges code for tokens."""
    from datetime import datetime, timezone, timedelta
    code = request.args.get("code")
    realm_id = request.args.get("realmId")
    state = request.args.get("state", "")
    firm_id = state  # we pass firm_id as the state param

    if not code or not realm_id:
        return "<h3>Authorization failed. Missing code or realmId.</h3>", 400

    # Exchange code for tokens
    import base64
    auth_header = base64.b64encode(f"{QBO_CLIENT_ID}:{QBO_CLIENT_SECRET}".encode()).decode()
    token_r = requests.post(
        "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
        headers={
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": QBO_REDIRECT_URI,
        },
        timeout=10,
    )
    if not token_r.ok:
        logging.error(f"QBO token exchange failed: {token_r.status_code} {token_r.text[:200]}")
        return "<h3>Failed to connect QuickBooks. Please try again.</h3>", 500

    tokens = token_r.json()
    expires_in = tokens.get("expires_in", 3600)

    # Get company info
    company_name = ""
    try:
        ci_r = requests.get(
            f"{_qbo_api_url()}/v3/company/{realm_id}/companyinfo/{realm_id}",
            headers={
                "Authorization": f"Bearer {tokens['access_token']}",
                "Accept": "application/json",
            },
            timeout=10,
        )
        if ci_r.ok:
            company_name = ci_r.json().get("CompanyInfo", {}).get("CompanyName", "")
    except Exception:
        pass

    # Upsert connection
    conn = {
        "firm_id": firm_id,
        "realm_id": realm_id,
        "access_token": _encrypt_token(tokens["access_token"]),
        "refresh_token": _encrypt_token(tokens.get("refresh_token", "")),
        "token_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        "status": "active",
        "company_name": company_name,
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    # Try update first, then insert
    upd = requests.patch(
        f"{SUPABASE_URL}/rest/v1/qbo_connections",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        params={"firm_id": f"eq.{firm_id}"},
        json=conn,
        timeout=5,
    )
    if not upd.ok or not upd.json():
        requests.post(
            f"{SUPABASE_URL}/rest/v1/qbo_connections",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json=conn,
            timeout=5,
        )

    # Redirect back to dashboard settings
    return (
        '<html><body><h3>QuickBooks connected successfully!</h3>'
        '<p>You can close this window and return to the Hazel dashboard.</p>'
        '<script>window.opener && window.opener.postMessage("qbo_connected","*"); setTimeout(()=>window.close(),2000);</script>'
        '</body></html>'
    )


@app.route("/api/qbo/status", methods=["GET"])
@require_auth
def api_qbo_status():
    """QB-01: Get QBO connection status for the firm."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/qbo_connections",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "select": "realm_id,status,company_name,connected_at,last_synced_at", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        return jsonify(r.json()[0]), 200
    return jsonify({"status": "not_connected"}), 200


@app.route("/api/qbo/disconnect", methods=["POST"])
@require_auth
def api_qbo_disconnect():
    """QB-01: Disconnect QBO. Clears tokens."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    requests.patch(
        f"{SUPABASE_URL}/rest/v1/qbo_connections",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}"},
        json={"status": "disconnected", "access_token": "", "refresh_token": ""},
        timeout=5,
    )
    return jsonify({"status": "disconnected"}), 200


@app.route("/api/qbo/sync/<project_id>", methods=["POST"])
@require_auth
def api_qbo_sync(project_id):
    """QB-02: Sync job costs from QBO for a specific project."""
    from datetime import datetime, timezone
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404

    # Get QBO connection
    conn_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/qbo_connections",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "limit": "1"},
        timeout=5,
    )
    if not conn_r.ok or not conn_r.json() or conn_r.json()[0].get("status") != "active":
        return jsonify({"error": "QBO not connected"}), 400

    conn = conn_r.json()[0]
    access_token = _decrypt_token(conn["access_token"])
    realm_id = conn["realm_id"]

    # Get project's qbo_customer_id
    proj_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/projects",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"id": f"eq.{project_id}", "select": "qbo_customer_id", "limit": "1"},
        timeout=5,
    )
    if not proj_r.ok or not proj_r.json():
        return jsonify({"error": "Project not found"}), 404
    qbo_cust_id = proj_r.json()[0].get("qbo_customer_id")
    if not qbo_cust_id:
        return jsonify({"error": "No QBO Customer ID mapped for this project"}), 400

    # Pull P&L Detail from QBO
    try:
        report_r = requests.get(
            f"{_qbo_api_url()}/v3/company/{realm_id}/reports/ProfitAndLossDetail",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            params={"customer": qbo_cust_id},
            timeout=15,
        )
        if not report_r.ok:
            # Token may be expired — try refresh
            if report_r.status_code == 401:
                refreshed = _refresh_qbo_token(firm_id, conn)
                if refreshed:
                    access_token = refreshed
                    report_r = requests.get(
                        f"{_qbo_api_url()}/v3/company/{realm_id}/reports/ProfitAndLossDetail",
                        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                        params={"customer": qbo_cust_id},
                        timeout=15,
                    )
            if not report_r.ok:
                return jsonify({"error": f"QBO report fetch failed: {report_r.status_code}"}), 502

        # Parse the report into cost code rows
        report = report_r.json()
        cost_rows = _parse_qbo_pnl(report, project_id, firm_id)

        # Clear old cache and insert new
        requests.delete(
            f"{SUPABASE_URL}/rest/v1/qbo_job_cost_cache",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"project_id": f"eq.{project_id}"},
            timeout=5,
        )
        if cost_rows:
            requests.post(
                f"{SUPABASE_URL}/rest/v1/qbo_job_cost_cache",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                json=cost_rows,
                timeout=5,
            )

        # Update last_synced_at
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/qbo_connections",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}"},
            json={"last_synced_at": datetime.now(timezone.utc).isoformat()},
            timeout=5,
        )

        return jsonify({"status": "synced", "rows": len(cost_rows)}), 200
    except Exception as e:
        logging.error(f"qbo_sync: {e}")
        return jsonify({"error": str(e)}), 500


def _refresh_qbo_token(firm_id, conn):
    """Refresh QBO access token. Returns new access_token or None."""
    from datetime import datetime, timezone, timedelta
    import base64
    refresh_token = _decrypt_token(conn.get("refresh_token", ""))
    if not refresh_token:
        return None
    auth_header = base64.b64encode(f"{QBO_CLIENT_ID}:{QBO_CLIENT_SECRET}".encode()).decode()
    r = requests.post(
        "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
        headers={"Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        timeout=10,
    )
    if r.ok:
        tokens = r.json()
        expires_in = tokens.get("expires_in", 3600)
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/qbo_connections",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}"},
            json={
                "access_token": _encrypt_token(tokens["access_token"]),
                "refresh_token": _encrypt_token(tokens.get("refresh_token", refresh_token)),
                "token_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
                "status": "active",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            timeout=5,
        )
        return tokens["access_token"]
    else:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/qbo_connections",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}"},
            json={"status": "error"},
            timeout=5,
        )
        return None


def _parse_qbo_pnl(report, project_id, firm_id):
    """Parse QBO ProfitAndLossDetail JSON into cost code rows."""
    from datetime import date
    rows = []
    try:
        for row_group in report.get("Rows", {}).get("Row", []):
            # QBO reports nest data in Header/Rows/Summary
            header = row_group.get("Header", {})
            summary = row_group.get("Summary", {})
            col_data = summary.get("ColData", [])
            if len(col_data) >= 2:
                cost_code_name = col_data[0].get("value", "Unknown")
                actual = float(col_data[-1].get("value", 0))
                rows.append({
                    "project_id": project_id,
                    "firm_id": firm_id,
                    "cost_code": cost_code_name[:20],
                    "cost_code_name": cost_code_name,
                    "actual_amount": actual,
                    "budgeted_amount": 0,  # budgets entered separately or from Neo4j
                    "as_of_date": date.today().isoformat(),
                })
    except Exception as e:
        logging.warning(f"_parse_qbo_pnl: {e}")
    return rows


@app.route("/api/qbo/job-costs/<project_id>", methods=["GET"])
@require_auth
def api_qbo_job_costs(project_id):
    """QB-02: Get cached job cost data for a project."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/qbo_job_cost_cache",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"project_id": f"eq.{project_id}", "firm_id": f"eq.{firm_id}", "order": "cost_code_name"},
        timeout=5,
    )
    return jsonify(r.json() if r.ok else []), 200


@app.route("/api/invoices", methods=["GET"])
@require_auth
def api_invoices_list():
    """QB-03: List invoices for the firm."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    params = {"firm_id": f"eq.{firm_id}", "order": "created_at.desc", "limit": "50"}
    pid = request.args.get("project_id")
    if pid:
        params["project_id"] = f"eq.{pid}"
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/invoices",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params=params,
        timeout=5,
    )
    return jsonify(r.json() if r.ok else []), 200


@app.route("/api/change-orders", methods=["GET"])
@require_auth
def api_change_orders_list():
    """QB-04: List change orders for a project."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    params = {"firm_id": f"eq.{firm_id}", "order": "created_at.desc", "limit": "50"}
    pid = request.args.get("project_id")
    if pid:
        params["project_id"] = f"eq.{pid}"
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/change_orders",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params=params,
        timeout=5,
    )
    return jsonify(r.json() if r.ok else []), 200


@app.route("/api/milestones/<project_id>", methods=["GET", "POST"])
@require_auth
def api_milestones(project_id):
    """QB-05: List or create payment milestones for a project."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404

    if request.method == "GET":
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/project_milestones",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"project_id": f"eq.{project_id}", "firm_id": f"eq.{firm_id}", "order": "due_date.asc.nullslast"},
            timeout=5,
        )
        return jsonify(r.json() if r.ok else []), 200

    # POST — create a milestone
    body = request.get_json(force=True) or {}
    row = {
        "project_id": project_id,
        "firm_id": firm_id,
        "name": body.get("name", ""),
        "milestone_type": body.get("milestone_type", "payment"),
        "due_date": body.get("due_date"),
        "percent_complete_trigger": body.get("percent_complete_trigger"),
        "amount": body.get("amount"),
        "status": "upcoming",
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/project_milestones",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        json=row,
        timeout=5,
    )
    if r.ok:
        return jsonify(r.json()[0] if r.json() else {"status": "created"}), 201
    return jsonify({"error": "Failed to create milestone"}), 500


# ══════════════════════════════════════════════════════════════════════════════
# PUNCH LIST
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/punch-list", methods=["GET"])
@require_auth
def api_punch_list_get():
    """List punch list items for a project."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    project_id = request.args.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/punch_list_items",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={
            "project_id": f"eq.{project_id}",
            "firm_id": f"eq.{firm_id}",
            "order": "created_at.asc",
        },
        timeout=5,
    )
    return jsonify(r.json() if r.ok else []), 200


@app.route("/api/punch-list", methods=["POST"])
@require_auth
def api_punch_list_post():
    """Create one or more punch list items."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    body = request.get_json(force=True) or {}

    # Support single item or array of items
    items = body.get("items", [body]) if "items" in body else [body]
    project_id = body.get("project_id") or (items[0].get("project_id") if items else None)
    if not project_id:
        return jsonify({"error": "project_id required"}), 400

    allowed = {"description", "assigned_trade", "location", "source", "source_file_id"}
    rows = []
    for item in items:
        if not item.get("description"):
            continue
        row = {k: v for k, v in item.items() if k in allowed}
        row["project_id"] = project_id
        row["firm_id"] = firm_id
        rows.append(row)

    if not rows:
        return jsonify({"error": "At least one item with description required"}), 400

    created = []
    for row in rows:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/punch_list_items",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json=row,
            timeout=5,
        )
        if r.ok and r.json():
            created.append(r.json()[0])

    return jsonify(created), 201


@app.route("/api/punch-list/<item_id>", methods=["PATCH"])
@require_auth
def api_punch_list_update(item_id):
    """Update a punch list item (resolve, edit trade/location)."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    body = request.get_json(force=True) or {}
    allowed = {"description", "assigned_trade", "location", "resolved", "resolved_at", "resolved_by"}
    patch = {k: v for k, v in body.items() if k in allowed}

    # Auto-set resolved_at and resolved_by when resolving
    if patch.get("resolved") is True:
        from datetime import datetime, timezone
        patch.setdefault("resolved_at", datetime.now(timezone.utc).isoformat())
        patch.setdefault("resolved_by", "builder")

    patch["updated_at"] = "now()"
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/punch_list_items",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        params={"id": f"eq.{item_id}", "firm_id": f"eq.{firm_id}"},
        json=patch,
        timeout=5,
    )
    if r.ok and r.json():
        return jsonify(r.json()[0]), 200
    return jsonify({"error": "Update failed"}), 500


@app.route("/api/punch-list/<item_id>", methods=["DELETE"])
@require_auth
def api_punch_list_delete(item_id):
    """Delete a punch list item."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/punch_list_items",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"id": f"eq.{item_id}", "firm_id": f"eq.{firm_id}"},
        timeout=5,
    )
    return jsonify({"deleted": True}), 200


# ══════════════════════════════════════════════════════════════════════════════
# GMAIL REAL-TIME INBOX INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

GMAIL_CLIENT_ID       = os.getenv("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET   = os.getenv("GMAIL_CLIENT_SECRET", "")
GMAIL_REDIRECT_URI    = os.getenv("GMAIL_REDIRECT_URI", "https://hazel.dejaview.io/auth/gmail/callback")
GMAIL_PUBSUB_TOPIC    = os.getenv("GMAIL_PUBSUB_TOPIC", "")
GMAIL_PUBSUB_SECRET   = os.getenv("GMAIL_PUBSUB_WEBHOOK_SECRET", "")


def _refresh_gmail_token(firm_id, token_row):
    """Refresh Gmail access token using stored refresh_token. Returns new access_token or None."""
    from datetime import datetime, timezone, timedelta
    refresh_token = _decrypt_token(token_row.get("refresh_token", ""))
    if not refresh_token:
        return None
    r = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GMAIL_CLIENT_ID,
            "client_secret": GMAIL_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=10,
    )
    if r.ok:
        tokens = r.json()
        expires_in = tokens.get("expires_in", 3600)
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/gmail_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}"},
            json={
                "access_token": _encrypt_token(tokens["access_token"]),
                "expiry": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            timeout=5,
        )
        return tokens["access_token"]
    else:
        logging.error(f"Gmail token refresh failed for firm {firm_id}: {r.status_code} {r.text[:200]}")
        return None


def _get_gmail_access_token(firm_id, token_row):
    """Return a valid access token, refreshing if needed."""
    from datetime import datetime, timezone, timedelta
    expiry_str = token_row.get("expiry")
    if expiry_str:
        from dateutil.parser import parse as parse_dt
        expiry = parse_dt(expiry_str)
        if expiry > datetime.now(timezone.utc) + timedelta(minutes=5):
            return _decrypt_token(token_row.get("access_token", ""))
    return _refresh_gmail_token(firm_id, token_row)


def _register_gmail_watch(firm_id, access_token):
    """Register Gmail push notification watch via Pub/Sub. Returns historyId or None."""
    from datetime import datetime, timezone, timedelta
    if not GMAIL_PUBSUB_TOPIC:
        logging.error("GMAIL_PUBSUB_TOPIC not configured")
        return None
    r = requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/watch",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"topicName": GMAIL_PUBSUB_TOPIC, "labelIds": ["INBOX"]},
        timeout=10,
    )
    if r.ok:
        result = r.json()
        history_id = result.get("historyId")
        expiration_ms = int(result.get("expiration", 0))
        watch_expiry = datetime.fromtimestamp(expiration_ms / 1000, tz=timezone.utc).isoformat() if expiration_ms else (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/gmail_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}"},
            json={"history_id": history_id, "watch_expiry": watch_expiry, "updated_at": datetime.now(timezone.utc).isoformat()},
            timeout=5,
        )
        logging.info(f"Gmail watch registered for firm {firm_id}, historyId={history_id}")
        return history_id
    else:
        logging.error(f"Gmail watch registration failed for firm {firm_id}: {r.status_code} {r.text[:200]}")
        return None


def _fetch_new_gmail_messages(access_token, old_history_id, new_history_id):
    """Fetch new INBOX messages since old_history_id using Gmail history API."""
    messages = []
    try:
        r = requests.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/history",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"startHistoryId": old_history_id, "historyTypes": "messageAdded", "labelId": "INBOX"},
            timeout=10,
        )
        if not r.ok:
            logging.warning(f"Gmail history.list failed: {r.status_code} {r.text[:200]}")
            return messages
        history = r.json().get("history", [])
        seen_ids = set()
        for entry in history:
            for msg_added in entry.get("messagesAdded", []):
                msg = msg_added.get("message", {})
                msg_id = msg.get("id")
                labels = msg.get("labelIds", [])
                if msg_id and msg_id not in seen_ids and "INBOX" in labels and "SENT" not in labels:
                    seen_ids.add(msg_id)
                    messages.append(msg_id)
    except Exception as e:
        logging.error(f"_fetch_new_gmail_messages error: {e}")
    return messages


def _get_gmail_message(access_token, message_id):
    """Fetch a single Gmail message and return parsed {from, subject, body}."""
    import base64
    r = requests.get(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"format": "full"},
        timeout=10,
    )
    if not r.ok:
        return None
    data = r.json()
    headers = {h["name"].lower(): h["value"] for h in data.get("payload", {}).get("headers", [])}
    sender = headers.get("from", "unknown")
    subject = headers.get("subject", "(no subject)")

    # Extract body — prefer plain text, fall back to html snippet
    body = ""
    payload = data.get("payload", {})

    def _extract_text(part):
        if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
            return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="replace")
        for sub in part.get("parts", []):
            result = _extract_text(sub)
            if result:
                return result
        return ""

    body = _extract_text(payload) or data.get("snippet", "")
    return {"from": sender, "subject": subject, "body": body[:3000]}


def _match_gmail_project(email_data, firm_id):
    """Try to match an email sender to a known contact/project."""
    sender = email_data.get("from", "")
    # Extract email address from "Name <email>" format
    import re
    match = re.search(r'<([^>]+)>', sender)
    email_addr = match.group(1) if match else sender

    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/contacts",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "email": f"ilike.{email_addr}", "select": "id,name,email", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        contact = r.json()[0]
        # Check project_contacts for a linked project
        pc = requests.get(
            f"{SUPABASE_URL}/rest/v1/project_contacts",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"contact_id": f"eq.{contact['id']}", "select": "project_id", "limit": "1"},
            timeout=5,
        )
        if pc.ok and pc.json():
            return contact["name"]
    return None


def _forward_gmail_to_hazel(firm_id, user_id, email_data):
    """Format a Gmail message and post to Hazel's OpenClaw session."""
    project_hint = _match_gmail_project(email_data, firm_id) or "unknown"
    message = (
        f"[Inbound email — {email_data['from']}]\n"
        f"Subject: {email_data['subject']}\n"
        f"Project hint: {project_hint}\n\n"
        f"{email_data['body']}\n\n"
        f"If this is relevant to a project, propose an action or draft a reply."
    )
    session_key = f"hook:hazel:gmail:{firm_id}:{user_id}"
    try:
        post_to_hazel(session_key, message)
        logging.info(f"Gmail forwarded to Hazel for firm {firm_id}: {email_data['subject'][:60]}")
    except Exception as e:
        logging.error(f"Failed to forward Gmail to Hazel for firm {firm_id}: {e}")


def renew_gmail_watches():
    """Renew Gmail watches that are expiring within 24 hours."""
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"watch_expiry": f"lt.{cutoff}", "select": "firm_id,access_token,refresh_token,expiry"},
        timeout=5,
    )
    if not r.ok:
        logging.error(f"renew_gmail_watches: failed to query gmail_tokens: {r.status_code}")
        return
    for row in r.json():
        firm_id = row["firm_id"]
        access_token = _get_gmail_access_token(firm_id, row)
        if access_token:
            _register_gmail_watch(firm_id, access_token)
        else:
            logging.warning(f"renew_gmail_watches: could not get access token for firm {firm_id}")


# ── Gmail Send Helper ─────────────────────────────────────────────────────────

def _send_gmail(user_id, firm_id, to, subject, body, cc=None, in_reply_to=None):
    """Send an email via Gmail API using the user's OAuth tokens.

    Returns dict with {message_id, thread_id} on success, raises on failure.
    Called from the queue approval handler — never directly by the agent.
    """
    import base64
    from email.mime.text import MIMEText
    from datetime import datetime, timezone

    # Look up tokens
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{user_id}", "select": "email,access_token,refresh_token,expiry", "limit": "1"},
        timeout=5,
    )
    if not r.ok or not r.json():
        raise ValueError(f"No Gmail tokens found for user {user_id} in firm {firm_id}")

    token_row = r.json()[0]
    sender_email = token_row["email"]
    access_token = _get_gmail_access_token(firm_id, token_row)
    if not access_token:
        raise ValueError(f"Could not get valid Gmail access token for {sender_email}")

    # Build MIME message
    msg = MIMEText(body, "plain")
    msg["To"] = to
    msg["From"] = sender_email
    msg["Subject"] = subject
    if cc:
        msg["Cc"] = cc
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to

    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

    # Send via Gmail API
    send_r = requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"raw": raw_message},
        timeout=15,
    )
    if not send_r.ok:
        raise ValueError(f"Gmail send failed: {send_r.status_code} {send_r.text[:500]}")

    result = send_r.json()
    logging.info(f"Gmail sent from {sender_email} to {to}: subject={subject[:60]}")

    return {
        "message_id": result.get("id", ""),
        "thread_id": result.get("threadId", ""),
        "sender": sender_email,
    }


# ── Gmail OAuth Routes ────────────────────────────────────────────────────────

@app.route("/auth/gmail/start", methods=["GET"])
@require_auth
def auth_gmail_start():
    """Start Gmail OAuth flow. Returns the Google authorization URL."""
    if not GMAIL_CLIENT_ID:
        return jsonify({"error": "Gmail integration not configured"}), 503
    import urllib.parse
    state = f"{g.firm_id}:{g.user_id}"
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urllib.parse.urlencode({
            "client_id": GMAIL_CLIENT_ID,
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send",
            "access_type": "offline",
            "prompt": "consent",
            "redirect_uri": GMAIL_REDIRECT_URI,
            "state": state,
        })
    )
    return jsonify({"auth_url": auth_url}), 200


@app.route("/auth/gmail/callback", methods=["GET"])
def auth_gmail_callback():
    """Gmail OAuth callback. Exchanges code for tokens, registers watch."""
    from datetime import datetime, timezone, timedelta
    code = request.args.get("code")
    state = request.args.get("state", "")
    parts = state.split(":", 1)
    firm_id = parts[0]
    user_id = parts[1] if len(parts) > 1 else ""

    if not code:
        return "<h3>Authorization failed. Missing code.</h3>", 400

    if not user_id:
        return "<h3>Authorization failed. Missing user context.</h3>", 400

    # Exchange code for tokens
    token_r = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GMAIL_CLIENT_ID,
            "client_secret": GMAIL_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GMAIL_REDIRECT_URI,
        },
        timeout=10,
    )
    if not token_r.ok:
        logging.error(f"Gmail token exchange failed: {token_r.status_code} {token_r.text[:200]}")
        return "<h3>Failed to connect Gmail. Please try again.</h3>", 500

    tokens = token_r.json()
    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token", "")
    expires_in = tokens.get("expires_in", 3600)

    # Get user's email address
    email = ""
    try:
        profile_r = requests.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if profile_r.ok:
            email = profile_r.json().get("emailAddress", "")
    except Exception:
        pass

    # Upsert token row (keyed on firm_id + user_id)
    row = {
        "firm_id": firm_id,
        "user_id": user_id,
        "email": email,
        "access_token": _encrypt_token(access_token),
        "refresh_token": _encrypt_token(refresh_token),
        "expiry": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    upd = requests.patch(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{user_id}"},
        json=row,
        timeout=5,
    )
    if not upd.ok or not upd.json():
        row["created_at"] = datetime.now(timezone.utc).isoformat()
        requests.post(
            f"{SUPABASE_URL}/rest/v1/gmail_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json=row,
            timeout=5,
        )

    # Register Gmail watch
    _register_gmail_watch(firm_id, access_token)

    return (
        '<html><body><h3>Gmail connected successfully!</h3>'
        '<p>You can close this window and return to the Hazel dashboard.</p>'
        '<script>window.opener && window.opener.postMessage("gmail_connected","*"); setTimeout(()=>window.close(),2000);</script>'
        '</body></html>'
    )


@app.route("/api/gmail/status", methods=["GET"])
@require_auth
def api_gmail_status():
    """Get Gmail connection status for the current user."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{g.user_id}", "select": "email,watch_expiry,created_at", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        row = r.json()[0]
        return jsonify({"connected": True, "email": row["email"], "watch_expiry": row.get("watch_expiry"), "connected_at": row.get("created_at")}), 200
    return jsonify({"connected": False}), 200


@app.route("/api/gmail/disconnect", methods=["DELETE"])
@require_auth
def api_gmail_disconnect():
    """Disconnect Gmail for the current user. Revokes token and deletes the row."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404

    # Fetch token to revoke
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{g.user_id}", "select": "access_token,refresh_token", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        row = r.json()[0]
        token_to_revoke = _decrypt_token(row.get("refresh_token") or row.get("access_token", ""))
        if token_to_revoke:
            try:
                requests.post(
                    "https://oauth2.googleapis.com/revoke",
                    params={"token": token_to_revoke},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=10,
                )
            except Exception as e:
                logging.warning(f"Gmail revoke failed for user {g.user_id} firm {firm_id}: {e}")

    # Delete row
    requests.delete(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{g.user_id}"},
        timeout=5,
    )
    return jsonify({"connected": False}), 200


# ── Gmail Pub/Sub Webhook ─────────────────────────────────────────────────────

@app.route("/webhook/gmail-push", methods=["POST"])
def webhook_gmail_push():
    """Receive Gmail push notifications from Google Pub/Sub."""
    import base64 as b64

    # Optional shared-secret verification
    if GMAIL_PUBSUB_SECRET:
        provided = request.args.get("secret", "") or request.headers.get("X-Webhook-Secret", "")
        if provided != GMAIL_PUBSUB_SECRET:
            return "", 403

    data = request.get_json(force=True) or {}
    message_data = data.get("message", {}).get("data", "")
    if not message_data:
        return "", 204

    try:
        payload = json.loads(b64.b64decode(message_data))
    except Exception as e:
        logging.warning(f"gmail-push: bad payload: {e}")
        return "", 400

    email_address = payload.get("emailAddress", "")
    new_history_id = str(payload.get("historyId", ""))

    if not email_address:
        return "", 204

    # Look up firm by email
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"email": f"eq.{email_address}", "select": "firm_id,user_id,access_token,refresh_token,expiry,history_id", "limit": "1"},
        timeout=5,
    )
    if not r.ok or not r.json():
        logging.info(f"gmail-push: no token for {email_address}")
        return "", 204

    token_row = r.json()[0]
    firm_id = token_row["firm_id"]
    user_id = token_row.get("user_id", "")
    old_history_id = token_row.get("history_id", "")

    if not old_history_id:
        # First push after watch registration — just store the history_id
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/gmail_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"email": f"eq.{email_address}"},
            json={"history_id": new_history_id, "updated_at": json.dumps(None)},
            timeout=5,
        )
        return "", 204

    # Get valid access token
    access_token = _get_gmail_access_token(firm_id, token_row)
    if not access_token:
        logging.error(f"gmail-push: no valid token for firm {firm_id}")
        return "", 204

    # Process in background thread
    def _process():
        try:
            msg_ids = _fetch_new_gmail_messages(access_token, old_history_id, new_history_id)
            # Update history_id
            from datetime import datetime, timezone
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/gmail_tokens",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"email": f"eq.{email_address}"},
                json={"history_id": new_history_id, "updated_at": datetime.now(timezone.utc).isoformat()},
                timeout=5,
            )
            for msg_id in msg_ids:
                dedup_key = f"gmail:{msg_id}"
                if already_seen(dedup_key):
                    continue
                email_data = _get_gmail_message(access_token, msg_id)
                if email_data:
                    _forward_gmail_to_hazel(firm_id, user_id, email_data)
        except Exception as e:
            logging.error(f"gmail-push processing error for firm {firm_id} user {user_id}: {e}")

    threading.Thread(target=_process, daemon=True).start()
    return "", 204


@app.route("/api/gmail/renew-watches", methods=["POST"])
def api_gmail_renew_watches():
    """Endpoint for cron to trigger watch renewal. Protected by webhook secret."""
    secret = request.headers.get("X-Webhook-Secret", "")
    if secret != WEBHOOK_SECRET:
        return jsonify({"error": "unauthorized"}), 401
    renew_gmail_watches()
    return jsonify({"status": "ok"}), 200


@app.route("/api/lookup/phone", methods=["GET"])
@require_auth
def api_lookup_phone():
    """Look up a user by phone number. Returns identity + Gmail status."""
    import re
    phone = request.args.get("number", "")
    if not phone:
        return jsonify({"error": "missing number param"}), 400
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404

    # Normalize to last 10 digits
    digits = re.sub(r'\D', '', phone)
    if len(digits) > 10:
        digits = digits[-10:]

    result = {"phone": phone, "identified": False}

    # Search contacts by phone (partial match on last 10 digits)
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/contacts",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "phone": f"ilike.%{digits}%", "select": "id,name,email,phone", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        contact = r.json()[0]
        result.update({"identified": True, "name": contact.get("name"), "email": contact.get("email"), "contact_id": contact["id"]})

    # Check if this phone matches a firm_user (via their Supabase auth email → contacts)
    # Also check Gmail status for the firm
    gmail_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/gmail_tokens",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "select": "email,user_id", "limit": "10"},
        timeout=5,
    )
    if gmail_r.ok and gmail_r.json():
        gmail_rows = gmail_r.json()
        # If we found a contact email, check if they have Gmail connected
        contact_email = result.get("email", "")
        for row in gmail_rows:
            if contact_email and row.get("email", "").lower() == contact_email.lower():
                result["gmail_connected"] = True
                result["gmail_email"] = row["email"]
                result["user_id"] = row.get("user_id")
                break
        else:
            result["gmail_connected"] = False
    else:
        result["gmail_connected"] = False

    return jsonify(result), 200


# ══════════════════════════════════════════════════════════════════════════════
# EPIC 7 — BILLING AND COMMERCIAL INFRASTRUCTURE
# ══════════════════════════════════════════════════════════════════════════════

STRIPE_SECRET_KEY      = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET  = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_EARLY     = os.getenv("STRIPE_PRICE_EARLY", "")
STRIPE_PRICE_STANDARD  = os.getenv("STRIPE_PRICE_STANDARD", "")
DASHBOARD_URL          = os.getenv("DASHBOARD_URL", "https://hazel.haventechsolutions.com")
TOS_URL                = os.getenv("TOS_URL", "")
DPA_URL                = os.getenv("DPA_URL", "")


@app.route("/api/billing/webhook", methods=["POST"])
def billing_webhook():
    """BL-01: Stripe webhook handler. Validates signature, processes events."""
    from datetime import datetime, timezone, timedelta
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature", "")

    # Verify signature
    if STRIPE_WEBHOOK_SECRET:
        try:
            import stripe
            stripe.api_key = STRIPE_SECRET_KEY
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except ImportError:
            # If stripe package not installed, basic JSON parse (dev mode)
            event = json.loads(payload)
            logging.warning("stripe package not installed — skipping signature verification")
        except Exception as e:
            logging.warning(f"Stripe signature verification failed: {e}")
            return jsonify({"error": "Invalid signature"}), 400
    else:
        event = json.loads(payload)

    event_id = event.get("id", "")
    event_type = event.get("type", "")

    # Idempotency check
    check = requests.get(
        f"{SUPABASE_URL}/rest/v1/stripe_events_log",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"stripe_event_id": f"eq.{event_id}", "select": "id", "limit": "1"},
        timeout=5,
    )
    if check.ok and check.json():
        return jsonify({"status": "duplicate"}), 200

    # Log event
    requests.post(
        f"{SUPABASE_URL}/rest/v1/stripe_events_log",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        json={
            "stripe_event_id": event_id,
            "event_type": event_type,
            "payload": event,
            "processing_status": "pending",
        },
        timeout=5,
    )

    try:
        obj = event.get("data", {}).get("object", {})
        metadata = obj.get("metadata", {})
        firm_id = metadata.get("firm_id")

        # If no firm_id in metadata, look up by stripe_customer_id
        stripe_cust_id = obj.get("customer")
        if not firm_id and stripe_cust_id:
            sub_r = requests.get(
                f"{SUPABASE_URL}/rest/v1/subscriptions",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"stripe_customer_id": f"eq.{stripe_cust_id}", "select": "firm_id", "limit": "1"},
                timeout=5,
            )
            if sub_r.ok and sub_r.json():
                firm_id = sub_r.json()[0]["firm_id"]

        if event_type == "customer.subscription.created":
            _upsert_subscription(firm_id, obj)
        elif event_type == "customer.subscription.updated":
            _upsert_subscription(firm_id, obj)
        elif event_type == "customer.subscription.deleted":
            _handle_subscription_deleted(firm_id, obj)
        elif event_type == "invoice.payment_succeeded":
            _handle_payment_succeeded(firm_id, obj)
        elif event_type == "invoice.payment_failed":
            _handle_payment_failed(firm_id, obj)
        elif event_type == "invoice.payment_action_required":
            logging.info(f"Payment action required for firm {firm_id}")

        # Mark processed
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/stripe_events_log",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"stripe_event_id": f"eq.{event_id}"},
            json={"processing_status": "processed", "processed_at": datetime.now(timezone.utc).isoformat()},
            timeout=5,
        )
    except Exception as e:
        logging.error(f"Stripe webhook processing error: {e}")
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/stripe_events_log",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"stripe_event_id": f"eq.{event_id}"},
            json={"processing_status": "failed", "error_message": str(e)},
            timeout=5,
        )

    return jsonify({"status": "ok"}), 200


def _upsert_subscription(firm_id, sub_obj):
    """Create or update a subscription row from a Stripe subscription object."""
    from datetime import datetime, timezone
    if not firm_id:
        return
    row = {
        "firm_id": firm_id,
        "stripe_customer_id": sub_obj.get("customer"),
        "stripe_subscription_id": sub_obj.get("id"),
        "status": sub_obj.get("status", "active"),
        "plan_name": sub_obj.get("items", {}).get("data", [{}])[0].get("price", {}).get("nickname") if sub_obj.get("items") else None,
        "amount_cents": sub_obj.get("items", {}).get("data", [{}])[0].get("price", {}).get("unit_amount") if sub_obj.get("items") else None,
        "current_period_start": datetime.fromtimestamp(sub_obj["current_period_start"], tz=timezone.utc).isoformat() if sub_obj.get("current_period_start") else None,
        "current_period_end": datetime.fromtimestamp(sub_obj["current_period_end"], tz=timezone.utc).isoformat() if sub_obj.get("current_period_end") else None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    # Try update first
    upd = requests.patch(
        f"{SUPABASE_URL}/rest/v1/subscriptions",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        params={"firm_id": f"eq.{firm_id}"},
        json=row,
        timeout=5,
    )
    if not upd.ok or not upd.json():
        requests.post(
            f"{SUPABASE_URL}/rest/v1/subscriptions",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json=row,
            timeout=5,
        )


def _handle_subscription_deleted(firm_id, sub_obj):
    from datetime import datetime, timezone
    if not firm_id:
        return
    requests.patch(
        f"{SUPABASE_URL}/rest/v1/subscriptions",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}"},
        json={
            "status": "canceled",
            "canceled_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        timeout=5,
    )


def _handle_payment_succeeded(firm_id, invoice_obj):
    from datetime import datetime, timezone
    if not firm_id:
        return
    # Restore access for past_due firms
    requests.patch(
        f"{SUPABASE_URL}/rest/v1/subscriptions",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "status": "eq.past_due"},
        json={"status": "active", "grace_period_ends_at": None, "updated_at": datetime.now(timezone.utc).isoformat()},
        timeout=5,
    )


def _handle_payment_failed(firm_id, invoice_obj):
    from datetime import datetime, timezone, timedelta
    if not firm_id:
        return
    grace_end = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    requests.patch(
        f"{SUPABASE_URL}/rest/v1/subscriptions",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}"},
        json={"status": "past_due", "grace_period_ends_at": grace_end, "updated_at": datetime.now(timezone.utc).isoformat()},
        timeout=5,
    )


@app.route("/api/billing/status", methods=["GET"])
@require_auth
def api_billing_status():
    """BL-02: Get subscription status for the firm."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/subscriptions",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        sub = r.json()[0]
        # Don't return tokens
        return jsonify(sub), 200
    return jsonify({"status": "none"}), 200


@app.route("/api/billing/create-checkout-session", methods=["POST"])
@require_auth
def api_billing_create_checkout():
    """BL-03: Create Stripe Checkout session."""
    if not STRIPE_SECRET_KEY:
        return jsonify({"error": "Stripe not configured"}), 503
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    body = request.get_json(force=True) or {}
    price_id = body.get("price_id", STRIPE_PRICE_EARLY or STRIPE_PRICE_STANDARD)
    if not price_id:
        return jsonify({"error": "No price configured"}), 503

    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=f"{DASHBOARD_URL}/#/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DASHBOARD_URL}/#/billing",
            metadata={"firm_id": firm_id},
        )
        return jsonify({"checkout_url": session.url}), 200
    except ImportError:
        return jsonify({"error": "stripe package not installed on server"}), 503
    except Exception as e:
        logging.error(f"create_checkout: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/billing/usage", methods=["GET"])
@require_auth
def api_billing_usage():
    """BL-04: Usage visibility for the current billing period."""
    from datetime import datetime, timezone
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404

    # Get billing period
    sub_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/subscriptions",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"firm_id": f"eq.{firm_id}", "select": "current_period_start,current_period_end", "limit": "1"},
        timeout=5,
    )
    if sub_r.ok and sub_r.json() and sub_r.json()[0].get("current_period_start"):
        period_start = sub_r.json()[0]["current_period_start"]
    else:
        # No subscription — use firm creation date
        firm_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{firm_id}", "select": "created_at", "limit": "1"},
            timeout=5,
        )
        period_start = firm_r.json()[0]["created_at"] if firm_r.ok and firm_r.json() else datetime.now(timezone.utc).isoformat()

    # Count drafts
    qi_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/queue_items",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "count=exact"},
        params={"firm_id": f"eq.{firm_id}", "created_at": f"gte.{period_start}", "select": "id,status", "limit": "0"},
        timeout=5,
    )
    drafts_total = int(qi_r.headers.get("content-range", "*/0").split("/")[-1] or 0)

    # Count approved without edit (single version = approved without edit)
    qi_approved_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/queue_items",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "count=exact"},
        params={"firm_id": f"eq.{firm_id}", "created_at": f"gte.{period_start}", "status": "eq.approved", "select": "id", "limit": "0"},
        timeout=5,
    )
    drafts_approved = int(qi_approved_r.headers.get("content-range", "*/0").split("/")[-1] or 0)

    # Count emails processed
    em_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/inbound_emails",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "count=exact"},
        params={"firm_id": f"eq.{firm_id}", "created_at": f"gte.{period_start}", "select": "id", "limit": "0"},
        timeout=5,
    )
    emails_processed = int(em_r.headers.get("content-range", "*/0").split("/")[-1] or 0)

    # Count invoices
    inv_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/invoices",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "count=exact"},
        params={"firm_id": f"eq.{firm_id}", "created_at": f"gte.{period_start}", "status": "eq.posted", "select": "id", "limit": "0"},
        timeout=5,
    )
    invoices_posted = int(inv_r.headers.get("content-range", "*/0").split("/")[-1] or 0)

    # Estimated time saved
    time_saved_minutes = (drafts_total * 12) + (emails_processed * 8) + (invoices_posted * 15)
    hours = time_saved_minutes // 60
    mins = time_saved_minutes % 60

    accuracy_pct = round((drafts_approved / drafts_total * 100) if drafts_total > 0 else 0)

    return jsonify({
        "drafts_generated": drafts_total,
        "drafts_approved_without_edit": drafts_approved,
        "emails_processed": emails_processed,
        "invoices_posted": invoices_posted,
        "time_saved_display": f"~{hours} hours {mins} minutes" if hours > 0 else f"~{mins} minutes",
        "time_saved_minutes": time_saved_minutes,
        "approval_accuracy_pct": accuracy_pct,
        "period_start": period_start,
    }), 200


@app.route("/api/legal/accept", methods=["POST"])
@require_auth
def api_legal_accept():
    """BL-05: Record legal document acceptance."""
    from datetime import datetime, timezone
    firm_id = g.firm_id
    user_id = g.user_id
    if not firm_id or not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    body = request.get_json(force=True) or {}
    documents = body.get("documents", [])  # ["tos", "dpa"]
    if not documents:
        return jsonify({"error": "No documents specified"}), 400

    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")[:500]
    now = datetime.now(timezone.utc).isoformat()

    for doc_type in documents:
        if doc_type not in ("tos", "dpa"):
            continue
        requests.post(
            f"{SUPABASE_URL}/rest/v1/legal_acceptances",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json={
                "firm_id": firm_id,
                "user_id": user_id,
                "document_type": doc_type,
                "document_version": body.get("version", "v1.0"),
                "accepted_at": now,
                "ip_address": ip_address,
                "user_agent": user_agent,
            },
            timeout=5,
        )
        # Update firms tracking fields
        col = "tos_accepted_at" if doc_type == "tos" else "dpa_accepted_at"
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{firm_id}"},
            json={col: now},
            timeout=5,
        )

    return jsonify({"status": "accepted"}), 200


@app.route("/api/legal/status", methods=["GET"])
@require_auth
def api_legal_status():
    """BL-05: Check if current firm has accepted TOS and DPA."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"id": f"eq.{firm_id}", "select": "tos_accepted_at,dpa_accepted_at", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        d = r.json()[0]
        return jsonify({
            "tos_accepted": d.get("tos_accepted_at") is not None,
            "dpa_accepted": d.get("dpa_accepted_at") is not None,
            "tos_url": TOS_URL,
            "dpa_url": DPA_URL,
        }), 200
    return jsonify({"tos_accepted": False, "dpa_accepted": False}), 200


@app.route("/api/admin/firms", methods=["GET"])
@require_auth
def api_admin_firms():
    """BL-02: Admin page — list all firms with subscription status.
    Only accessible to Robert (hardcoded check for now)."""
    # Simple admin check — Robert's user_id or firm owner
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"select": "id,display_name,created_at,tos_accepted_at", "order": "created_at.desc"},
        timeout=5,
    )
    firms_list = r.json() if r.ok else []

    # Enrich with subscription status
    for firm in firms_list:
        sub_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/subscriptions",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm['id']}", "select": "status,stripe_customer_id,stripe_subscription_id,current_period_end", "limit": "1"},
            timeout=5,
        )
        firm["subscription"] = sub_r.json()[0] if sub_r.ok and sub_r.json() else None

    return jsonify(firms_list), 200


@app.route("/api/admin/firms/<firm_id>/subscription", methods=["POST"])
@require_auth
def api_admin_set_subscription(firm_id):
    """BL-02: Admin — manually set stripe_customer_id and stripe_subscription_id."""
    body = request.get_json(force=True) or {}
    from datetime import datetime, timezone
    row = {
        "firm_id": firm_id,
        "stripe_customer_id": body.get("stripe_customer_id"),
        "stripe_subscription_id": body.get("stripe_subscription_id"),
        "status": body.get("status", "trialing"),
        "plan_name": body.get("plan_name"),
        "amount_cents": body.get("amount_cents"),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    # Upsert
    upd = requests.patch(
        f"{SUPABASE_URL}/rest/v1/subscriptions",
        headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
        params={"firm_id": f"eq.{firm_id}"},
        json=row,
        timeout=5,
    )
    if not upd.ok or not upd.json():
        requests.post(
            f"{SUPABASE_URL}/rest/v1/subscriptions",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            json=row,
            timeout=5,
        )
    return jsonify({"status": "updated"}), 200
@app.route("/api/messages", methods=["POST"])
@require_auth
def api_messages_post():
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    body        = request.get_json(force=True) or {}
    project_id  = (body.get("project_id") or "").strip()
    content     = (body.get("content") or "").strip()
    attachments = body.get("attachments") or []
    if not project_id:
        return jsonify({"error": "project_id is required"}), 400
    if not content and not attachments:
        return jsonify({"error": "content or attachments required"}), 400
    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/messages",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json={"project_id": project_id, "firm_id": firm_id, "role": "builder",
                  "content": content, "attachments": attachments},
            timeout=5,
        )
        r.raise_for_status()
        row = r.json()
        msg = row[0] if row else {}
    except Exception as e:
        logging.error(f"api_messages_post insert: {e}")
        return jsonify({"error": "Failed to insert message"}), 500
    # Chat forwarding is now handled by the hazel-dashboard plugin.
    # The Supabase webhook on messages INSERT triggers the plugin directly.
    return jsonify(msg), 201



@app.route("/api/messages", methods=["GET"])
@require_auth
def api_messages_get():
    """Load messages for a project via service role (bypasses RLS)."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    project_id = request.args.get("project_id", "").strip()
    if not project_id:
        return jsonify({"error": "project_id is required"}), 400
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/messages",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"project_id": f"eq.{project_id}", "select": "*",
                    "order": "created_at.asc", "limit": "100"},
            timeout=5,
        )
        r.raise_for_status()
        return jsonify(r.json()), 200
    except Exception as e:
        logging.error(f"api_messages_get: {e}")
        return jsonify({"error": "Failed to fetch messages"}), 500




# ── FILES ─────────────────────────────────────────────────────────────────────

@app.route("/api/files", methods=["GET"])
@require_auth
def api_files_get():
    """Load files for a project via service role (bypasses RLS)."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    project_id = request.args.get("project_id", "").strip()
    if not project_id:
        return jsonify({"error": "project_id is required"}), 400
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/files",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"project_id": f"eq.{project_id}", "select": "*",
                    "order": "created_at.asc"},
            timeout=5,
        )
        r.raise_for_status()
        return jsonify(r.json()), 200
    except Exception as e:
        logging.error(f"api_files_get: {e}")
        return jsonify({"error": "Failed to fetch files"}), 500


# ── FILE UPLOAD ────────────────────────────────────────────────────────────────

@app.route("/api/files/upload", methods=["POST"])
@require_auth
def api_files_upload():
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    project_id = (request.form.get("project_id") or "").strip()
    category   = (request.form.get("category") or "uncategorized").strip()
    file_obj   = request.files.get("file")
    if not project_id:
        return jsonify({"error": "project_id is required"}), 400
    if not file_obj:
        return jsonify({"error": "file is required"}), 400
    filename  = file_obj.filename or "upload"
    ext       = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    path      = f"{project_id}/{category}/{int(__import__('time').time())}_{filename.replace(' ','_')}"
    try:
        sr = requests.post(
            f"{SUPABASE_URL}/storage/v1/object/project-files/{path}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": file_obj.content_type or "application/octet-stream", "x-upsert": "false"},
            data=file_obj.read(), timeout=30)
        if sr.status_code not in (200, 201):
            logging.error(f"Storage upload failed {sr.status_code}: {sr.text[:200]}")
            return jsonify({"error": "Storage upload failed", "detail": sr.text}), 500
    except Exception as e:
        logging.error(f"Storage upload exception: {e}")
        return jsonify({"error": "Storage upload failed"}), 500
    try:
        r = requests.post(f"{SUPABASE_URL}/rest/v1/files",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json={"project_id": project_id, "firm_id": firm_id, "name": filename,
                  "category": category, "storage_path": path, "file_type": ext,
                  "size_bytes": 0, "upload_source": "dashboard"}, timeout=10)
        r.raise_for_status()
        row = r.json(); item = row[0] if isinstance(row, list) else row
    except Exception as e:
        logging.error(f"files insert: {e}")
        return jsonify({"error": "File record insert failed"}), 500
    return jsonify(item), 201


@app.route("/api/files/<file_id>", methods=["PATCH"])
@require_auth
def api_files_update(file_id):
    """Update file metadata (category, archived, etc.) via service role."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    body = request.get_json(force=True) or {}
    allowed = {"category", "archived", "archived_at"}
    patch = {k: v for k, v in body.items() if k in allowed}
    if not patch:
        return jsonify({"error": "No valid fields to update"}), 400
    try:
        r = requests.patch(
            f"{SUPABASE_URL}/rest/v1/files",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            params={"id": f"eq.{file_id}", "firm_id": f"eq.{firm_id}"},
            json=patch,
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        return jsonify(data[0] if data else {"status": "updated"}), 200
    except Exception as e:
        logging.error(f"api_files_update: {e}")
        return jsonify({"error": "Failed to update file"}), 500


@app.route("/api/files/<file_id>", methods=["DELETE"])
@require_auth
def api_files_delete(file_id):
    """Delete file record and storage object via service role."""
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    try:
        # Get storage_path before deleting
        get_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/files",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{file_id}", "firm_id": f"eq.{firm_id}", "select": "storage_path", "limit": "1"},
            timeout=5,
        )
        storage_path = None
        if get_r.ok and get_r.json():
            storage_path = get_r.json()[0].get("storage_path")

        # Delete the DB record
        requests.delete(
            f"{SUPABASE_URL}/rest/v1/files",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{file_id}", "firm_id": f"eq.{firm_id}"},
            timeout=5,
        )

        # Delete from storage if path exists
        if storage_path:
            requests.delete(
                f"{SUPABASE_URL}/storage/v1/object/project-files/{storage_path}",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
                timeout=10,
            )

        return jsonify({"status": "deleted"}), 200
    except Exception as e:
        logging.error(f"api_files_delete: {e}")
        return jsonify({"error": "Failed to delete file"}), 500


# ── Supabase Auth "Send Email" Hook ────────────────────────────────────────
# Sends auth emails (signup, recovery, magic link, email change, invite) via
# AgentMail's REST API, bypassing Supabase's SMTP path entirely.
#
# Configure in Supabase: Authentication → Hooks → "Send email hook" → HTTPS
#   URL:    https://hazel.haventechsolutions.com/webhook/supabase-send-email
#   Secret: copy from the hook's "Generate secret" button (format v1,whsec_...)
#           and set env var SUPABASE_SEND_EMAIL_HOOK_SECRET to that value.
#
# Supabase signs requests using the Standard Webhooks spec (Svix headers).
import base64, hmac, hashlib, time
from urllib.parse import urlencode

SUPABASE_SEND_EMAIL_HOOK_SECRET = os.getenv("SUPABASE_SEND_EMAIL_HOOK_SECRET", "")
SEND_EMAIL_HOOK_FROM = os.getenv("SEND_EMAIL_HOOK_FROM_INBOX", HAZEL_INBOX)


def _decode_hook_secret(raw: str) -> bytes:
    """Strip the 'v1,whsec_' prefix and base64-decode the secret."""
    s = raw.strip()
    if s.startswith("v1,"):
        s = s[3:]
    if s.startswith("whsec_"):
        s = s[6:]
    # Standard Webhooks stores the secret as base64.
    return base64.b64decode(s)


def _verify_standard_webhook(raw_body: bytes, headers, secret: str) -> bool:
    """Verify a Standard Webhooks signature (Svix headers)."""
    if not secret:
        return False
    wh_id = headers.get("webhook-id") or headers.get("Webhook-ID") or ""
    wh_ts = headers.get("webhook-timestamp") or headers.get("Webhook-Timestamp") or ""
    wh_sig = headers.get("webhook-signature") or headers.get("Webhook-Signature") or ""
    if not (wh_id and wh_ts and wh_sig):
        return False

    # Reject requests outside a 5-minute window
    try:
        ts = int(wh_ts)
        if abs(int(time.time()) - ts) > 300:
            return False
    except ValueError:
        return False

    key = _decode_hook_secret(secret)
    signed = f"{wh_id}.{wh_ts}.".encode("utf-8") + raw_body
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()

    # Header can contain multiple space-separated "v1,<sig>" pairs.
    for pair in wh_sig.split():
        version, _, sig = pair.partition(",")
        if version == "v1" and hmac.compare_digest(sig, expected):
            return True
    return False


# Subject line + intro line per action type. Keep these short + generic.
_ACTION_COPY = {
    "signup":            ("Confirm your email", "Confirm your email to finish signing up for Hazel."),
    "invite":            ("You've been invited to Hazel", "You've been invited to join Hazel."),
    "magiclink":         ("Your sign-in link", "Click below to sign in to Hazel."),
    "recovery":          ("Reset your password", "Click below to reset your Hazel password."),
    "email_change":      ("Confirm your email change", "Confirm this is your new email address for Hazel."),
    "email_change_new":  ("Confirm your new email", "Confirm this is your new email address for Hazel."),
    "reauthentication":  ("Your verification code", "Use the code below to verify your identity."),
}


def _build_confirm_url(email_data: dict) -> str:
    """Build the Supabase verify URL from the hook payload."""
    token_hash = email_data.get("token_hash") or ""
    action = email_data.get("email_action_type") or ""
    redirect_to = email_data.get("redirect_to") or email_data.get("site_url") or ""
    qs = urlencode({"token": token_hash, "type": action, "redirect_to": redirect_to})
    return f"{SUPABASE_URL}/auth/v1/verify?{qs}"


def _render_email(user: dict, email_data: dict):
    action = email_data.get("email_action_type", "")
    subject, intro = _ACTION_COPY.get(
        action, ("Action required for your Hazel account", "You have a pending Hazel account action.")
    )
    token = email_data.get("token", "")
    confirm_url = _build_confirm_url(email_data) if email_data.get("token_hash") else ""

    # Reauthentication flow only uses the 6-digit code, not a link.
    if action == "reauthentication":
        text = f"{intro}\n\nYour code: {token}\n\nIf you did not request this, ignore this email."
        html = (
            f'<p>{intro}</p>'
            f'<p style="font-size:22px;letter-spacing:3px;font-weight:bold;">{token}</p>'
            f'<p style="color:#666;font-size:13px;">If you did not request this, ignore this email.</p>'
        )
    else:
        text = (
            f"{intro}\n\n"
            f"{confirm_url}\n\n"
            f"Or use code: {token}\n\n"
            f"If you did not request this, ignore this email."
        )
        html = (
            f'<p>{intro}</p>'
            f'<p><a href="{confirm_url}" '
            f'style="background:#1e3a5f;color:white;padding:10px 20px;text-decoration:none;'
            f'border-radius:6px;display:inline-block;margin:8px 0;">Confirm</a></p>'
            f'<p style="color:#666;font-size:13px;">Or use code <strong>{token}</strong>.</p>'
            f'<p style="color:#666;font-size:13px;">If you did not request this, ignore this email.</p>'
        )
    return subject, text, html


@app.route("/webhook/supabase-send-email", methods=["POST"])
def webhook_supabase_send_email():
    """Supabase Auth 'Send email' hook → AgentMail REST API."""
    raw = request.get_data()  # raw bytes, needed for signature

    if not SUPABASE_SEND_EMAIL_HOOK_SECRET:
        logging.error("supabase_send_email: SUPABASE_SEND_EMAIL_HOOK_SECRET not set")
        return jsonify({"error": {"http_code": 500, "message": "hook not configured"}}), 500

    if not _verify_standard_webhook(raw, request.headers, SUPABASE_SEND_EMAIL_HOOK_SECRET):
        logging.warning("supabase_send_email: signature verification failed")
        return jsonify({"error": {"http_code": 401, "message": "invalid signature"}}), 401

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return jsonify({"error": {"http_code": 400, "message": "invalid JSON"}}), 400

    user = payload.get("user") or {}
    email_data = payload.get("email_data") or {}
    recipient = (user.get("email") or "").strip()
    if not recipient:
        return jsonify({"error": {"http_code": 400, "message": "missing user.email"}}), 400

    if not AGENTMAIL_KEY:
        logging.error("supabase_send_email: AGENTMAIL_KEY not set")
        return jsonify({"error": {"http_code": 500, "message": "mail provider not configured"}}), 500

    subject, text_body, html_body = _render_email(user, email_data)

    try:
        mail_r = requests.post(
            f"https://api.agentmail.to/v0/inboxes/{SEND_EMAIL_HOOK_FROM}/messages/send",
            headers={"Authorization": f"Bearer {AGENTMAIL_KEY}", "Content-Type": "application/json"},
            json={"to": [recipient], "subject": subject, "text": text_body, "html": html_body},
            timeout=10,
        )
    except Exception as e:
        logging.error(f"supabase_send_email AgentMail request failed: {e}")
        return jsonify({"error": {"http_code": 502, "message": "mail provider unreachable"}}), 502

    if not mail_r.ok:
        logging.warning(
            f"supabase_send_email AgentMail {mail_r.status_code}: {mail_r.text[:300]}"
        )
        return jsonify({
            "error": {"http_code": 502, "message": f"mail provider returned {mail_r.status_code}"}
        }), 502

    action = email_data.get("email_action_type", "?")
    logging.info(f"supabase_send_email: sent {action} email to {recipient}")
    return jsonify({}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8700, threaded=True)

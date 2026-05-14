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
        # Morning briefing prefs (Trello uFWe99xk + OaV9vSGT). Migration 020
        # added the enabled+time columns; migration 027 added sms_enabled.
        # The dashboard's Settings UI (Trello 28aKzGpN) PATCHes them on
        # toggle/picker change.
        "morning_briefing_enabled", "morning_briefing_time",
        "morning_briefing_sms_enabled",
    }
    patch = {k: v for k, v in body.items() if k in allowed}
    if not patch:
        return jsonify({"error": "No valid fields to update"}), 400
    # Validate morning_briefing_time when present. Accept HH:MM (24-hour) and
    # HH:MM:SS — Postgres time accepts both, but we normalize to HH:MM:SS to
    # keep the column shape consistent. Reject anything else with a 400 so a
    # malformed save doesn't quietly corrupt the value or 500 on the upstream.
    mbt = patch.get("morning_briefing_time")
    if mbt is not None:
        if not isinstance(mbt, str):
            return jsonify({"error": "morning_briefing_time must be a string in HH:MM format"}), 400
        import re as _re
        if not _re.match(r"^\d{2}:\d{2}(:\d{2})?$", mbt):
            return jsonify({"error": "morning_briefing_time must be HH:MM (24-hour)"}), 400
        # Defensive: parse out hour/minute and bounds-check
        try:
            hh, mm = int(mbt[0:2]), int(mbt[3:5])
            if not (0 <= hh <= 23 and 0 <= mm <= 59):
                raise ValueError("out of range")
        except ValueError:
            return jsonify({"error": "morning_briefing_time must be a valid 24-hour clock value"}), 400
        patch["morning_briefing_time"] = mbt if len(mbt) == 8 else mbt + ":00"
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


@app.route("/api/projects/portfolio", methods=["GET"])
@require_auth
def api_projects_portfolio():
    """Return all card data the portfolio view needs in a single round trip.
    Trello card t8gNelRc.

    For each non-archived project the caller's firm owns, returns:
      id, name, client_name, status, schedule_variance_days, contract_value,
      spent_to_date, risks[], queue_items[] (max 3), punch_list { open, total }

    Sort order: delayed > at-risk > on-track. Returns [] (not 404) when the
    firm has no active projects.

    schedule_variance_days is a placeholder (returns 0) until we have a real
    scheduling signal source — either a graph rebuild or a Supabase column
    populated from QBO/external data. Documented in the Cgbxvr4m / YsevHmJQ
    discussion as out-of-scope here.
    """
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404

    sb = lambda path, params: requests.get(
        f"{SUPABASE_URL}/rest/v1/{path}",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params=params, timeout=5,
    )

    try:
        # 1. Active projects for this firm
        pr = sb("projects", {
            "firm_id": f"eq.{firm_id}",
            "status": "neq.archived",
            "select": "id,name,client_name,status,contract_value",
            "order": "created_at.asc",
        })
        pr.raise_for_status()
        projects = pr.json()
        if not projects:
            return jsonify([]), 200

        project_ids = [p["id"] for p in projects]
        in_clause = "in.(" + ",".join(project_ids) + ")"

        # 2-5: parallelizable in principle; sequential is fine at portfolio
        # cardinalities (4-10 projects). Each query is firm-scoped via the
        # project_id filter through projects we already vetted.
        risks_r = sb("project_risks", {
            "firm_id": f"eq.{firm_id}",
            "resolved": "eq.false",
            "select": "project_id,category,severity,description",
        })
        queue_r = sb("queue_items", {
            "firm_id": f"eq.{firm_id}",
            "status": "eq.active",
            "project_id": in_clause,
            "select": "id,title,type,project_id,created_at",
            "order": "created_at.asc",
        })
        punch_r = sb("punch_list_items", {
            "firm_id": f"eq.{firm_id}",
            "project_id": in_clause,
            "select": "project_id,resolved",
        })
        cost_r = sb("qbo_job_cost_cache", {
            "firm_id": f"eq.{firm_id}",
            "project_id": in_clause,
            "select": "project_id,actual_amount,budgeted_amount",
        })

        risks  = risks_r.json()  if risks_r.ok  else []
        queue  = queue_r.json()  if queue_r.ok  else []
        punch  = punch_r.json()  if punch_r.ok  else []
        costs  = cost_r.json()   if cost_r.ok   else []

        # Bucket by project_id for O(1) lookup as we compose cards
        risks_by_pid = {}
        for r in risks:
            risks_by_pid.setdefault(r["project_id"], []).append({
                "category": r.get("category"),
                "severity": r.get("severity"),
                "description": r.get("description"),
            })

        queue_by_pid = {}
        for q in queue:
            lst = queue_by_pid.setdefault(q["project_id"], [])
            if len(lst) < 3:  # cap at 3 per spec
                lst.append({
                    "id": q.get("id"),
                    "title": q.get("title"),
                    "type": q.get("type"),
                })

        punch_by_pid = {}
        for pli in punch:
            pid = pli["project_id"]
            slot = punch_by_pid.setdefault(pid, {"open": 0, "total": 0})
            slot["total"] += 1
            if not pli.get("resolved"):
                slot["open"] += 1

        spent_by_pid = {}
        budgeted_by_pid = {}
        for c in costs:
            pid = c["project_id"]
            try:
                spent_by_pid[pid] = spent_by_pid.get(pid, 0) + float(c.get("actual_amount") or 0)
            except (TypeError, ValueError):
                pass
            try:
                budgeted_by_pid[pid] = budgeted_by_pid.get(pid, 0) + float(c.get("budgeted_amount") or 0)
            except (TypeError, ValueError):
                pass

        # Compose card payloads
        cards = []
        for p in projects:
            pid = p["id"]
            spent    = spent_by_pid.get(pid, 0)
            budgeted = budgeted_by_pid.get(pid, 0)
            # budget_variance: positive = OVER budget (bad/red); negative =
            # under budget (good/green). Computed as actual - budgeted, the
            # opposite sign convention from qbo_job_cost_cache.variance
            # (which is budgeted - actual) — matches the design's "+$6,200"
            # red display where positive means over.
            cards.append({
                "id": pid,
                "name": p.get("name") or "Unnamed Project",
                "client_name": p.get("client_name"),
                "status": p.get("status") or "on-track",
                # Placeholder until we have a real schedule-signal source.
                "schedule_variance_days": 0,
                "contract_value":  p.get("contract_value") or 0,
                "spent_to_date":   spent,
                "budgeted_amount": budgeted,
                "budget_variance": spent - budgeted,
                "risks": risks_by_pid.get(pid, []),
                "queue_items": queue_by_pid.get(pid, []),
                "punch_list": punch_by_pid.get(pid, {"open": 0, "total": 0}),
            })

        # Status sort: delayed first, then at-risk, then everything else
        status_rank = {"delayed": 0, "at-risk": 1, "on-track": 2}
        cards.sort(key=lambda c: status_rank.get(c["status"], 3))

        return jsonify(cards), 200
    except Exception as e:
        logging.error(f"api_projects_portfolio: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/morning-briefing/today", methods=["GET"])
@require_auth
def api_morning_briefing_today():
    """Return today's morning briefing for the caller's firm, or 404 if none.
    Trello card Fpi3SVTx (route deferred from the migrations PR), consumed by
    v14QKFcI's portfolio briefing component.

    Date is computed in UTC. The briefing scheduler uses the same convention
    when writing rows, so a firm's briefing for 'today' is keyed off the UTC
    date the scheduler ran. (Per-firm timezone is a future story.)
    """
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found"}), 404
    from datetime import datetime as _dt
    today = _dt.utcnow().strftime("%Y-%m-%d")
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/morning_briefings",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={
                "firm_id": f"eq.{firm_id}",
                "briefing_date": f"eq.{today}",
                "select": "*",
                "limit": "1",
            },
            timeout=5,
        )
        r.raise_for_status()
        rows = r.json()
        if not rows:
            return jsonify({"error": "No briefing for today"}), 404
        return jsonify(rows[0]), 200
    except Exception as e:
        logging.error(f"api_morning_briefing_today: {e}")
        return jsonify({"error": "Internal server error"}), 500


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


def _send_welcome_email(firm: dict, user_id: str):
    """Welcome email on first onboarding completion (Trello xliplqOs).

    Sent to the authenticated user's email address (resolved from the
    Supabase Auth admin API). Fire-and-forget: any failure is logged but
    never raises — onboarding completion must succeed even if email
    delivery fails.

    Sender note: Agentmail's API is inbox-scoped, so the "from" address
    is determined by which inbox URL we POST to. Every other send in this
    file uses itshazel@agentmail.to, so we do the same. If/when a
    Hazel-branded sender (support@hazel.build, hello@hazel.build, etc.)
    is provisioned in Agentmail, swap the inbox path here.
    """
    if not AGENTMAIL_KEY:
        logging.warning("_send_welcome_email: AGENTMAIL_KEY not set, skipping")
        return
    try:
        # Resolve recipient email via Supabase Auth admin endpoint
        u = requests.get(
            f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
            headers=SB_HEADERS,
            timeout=5,
        )
        u.raise_for_status()
        user_email = (u.json().get("email") or "").strip()
        if not user_email:
            logging.warning(f"_send_welcome_email: no email for user {user_id}, skipping")
            return

        # [FIRST NAME] = first whitespace-separated token of sign_off_name.
        # Falls back to a generic greeting if sign_off_name is empty (some
        # firms may complete onboarding without filling that field).
        sign_off = (firm.get("sign_off_name") or "").strip()
        first_name = sign_off.split()[0] if sign_off else "there"

        subject = "Welcome to Hazel!"
        body = (
            f"Hello {first_name}, welcome to Hazel! Here is some information to help you get started.\n\n"
            "- You can text Hazel at: 1 (888) 281-2061\n"
            "- Your dashboard login is here: https://hazel.haventechsolutions.com/\n"
            "- Contact support@hazel.build if you need any help\n\n"
            "How To Communicate With Hazel\n\n"
            "Text Hazel as you would a person.\n\n"
            "- Punch lists: \"I'm finishing a walk-through at Cedar Hills. "
            "Garage door opener still isn't in. Flag it. John is the sub for this.\"\n"
            "- Change orders: \"Client wants to add a gas fireplace in the "
            "living room. Need a change order for $3,800.\"\n"
            "- Client updates: \"Send Jim Harlow a status update. "
            "We're on schedule, siding starts Monday.\"\n\n"
            "What Happens After You Text\n\n"
            "Hazel records everything that needs action on the project "
            "dashboard. She will also draft emails and change orders for "
            "your approval.\n\n"
            "- Hazel texts you back with a summary of what she did and "
            "what needs your approval.\n"
            "- Log in to your dashboard for a full view.\n"
            "- Once approved, Hazel sends, files, or records, and then "
            "logs a permanent audit trail.\n"
            "- If Hazel isn't sure, she'll ask.\n\n"
            "Send Her Emails\n\n"
            "You can also forward emails with project information, such "
            "as client change requests or invoices. She will log them "
            "and, if necessary, take action (for example, a schedule "
            "change). Hazel's email address is: itshazel@agentmail.to\n"
        )

        mail_r = requests.post(
            "https://api.agentmail.to/v0/inboxes/itshazel@agentmail.to/messages/send",
            headers={"Authorization": f"Bearer {AGENTMAIL_KEY}", "Content-Type": "application/json"},
            json={"to": [user_email], "subject": subject, "text": body},
            timeout=10,
        )
        if not mail_r.ok:
            logging.warning(
                f"_send_welcome_email AgentMail error {mail_r.status_code}: {mail_r.text[:200]}"
            )
        else:
            logging.info(f"_send_welcome_email: sent welcome to {user_email}")
    except Exception as e:
        logging.warning(f"_send_welcome_email (non-fatal): {e}")


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
        # Read prior state so the welcome email (Trello xliplqOs) only fires
        # on the FIRST completion — acceptance criteria: "No duplicate emails
        # are sent if onboarding/complete is called more than once". The
        # phone-provisioning email is left as-is (pre-existing behavior, out
        # of scope for xliplqOs); if dedup is wanted there too it can move
        # inside this same guard later.
        prev_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firms",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{firm_id}", "select": "onboarding_complete", "limit": "1"},
            timeout=5,
        )
        prev_r.raise_for_status()
        prev_rows = prev_r.json()
        was_already_complete = bool(prev_rows and prev_rows[0].get("onboarding_complete"))

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

        # Welcome email only on first completion. _send_welcome_email is
        # fire-and-forget — failures are logged and never block the response.
        if not was_already_complete:
            _send_welcome_email(firm, g.user_id)
        else:
            logging.info(
                f"api_onboarding_complete: firm {firm_id[:8]} re-completion, "
                "skipping welcome email"
            )

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
        # Trello ST-02 — pull email/phone overrides from firm_users so the
        # Team settings UI can show + edit them.
        members_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}",
                    "select": "id,user_id,role,created_at,email,phone",
                    "order": "created_at.asc"},
            timeout=5,
        )
        members_r.raise_for_status()
        members = members_r.json()

        invites_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/invite_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "used_at": "is.null",
                    "select": "id,email,phone,created_at,expires_at",
                    "order": "created_at.desc"},
            timeout=5,
        )
        invites_r.raise_for_status()
        pending_invites = invites_r.json()

        # Enrich with email from auth.users when firm_users.email isn't set.
        # auth_email stays available as a fallback so the UI can show the
        # login email when no display override exists.
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
            {
                "id": m["id"],
                "user_id": m["user_id"],
                "email": (m.get("email") or "").lower() or user_emails.get(m["user_id"], ""),
                "auth_email": user_emails.get(m["user_id"], ""),
                "phone": m.get("phone"),
                "role": m["role"],
                "created_at": m["created_at"],
            }
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
    # Optional phone (Trello ST-01). Normalize to E.164-ish by stripping
    # non-digits and prepending +1 for 10-digit US numbers. Empty phone is
    # written as null. We do NOT block invite creation on invalid phone —
    # the field is optional and the owner can fix it later via Edit Team Member.
    raw_phone = (body.get("phone") or "").strip()
    phone_normalized = None
    if raw_phone:
        digits = "".join(c for c in raw_phone if c.isdigit())
        if len(digits) == 10:
            phone_normalized = "+1" + digits
        elif len(digits) == 11 and digits.startswith("1"):
            phone_normalized = "+" + digits
        elif raw_phone.startswith("+") and len(digits) >= 10:
            phone_normalized = "+" + digits
        # else: unparseable shape — write null and log, don't reject the invite
        if phone_normalized is None:
            logging.info(f"api_invites: phone '{raw_phone}' not parseable; storing null")

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
            json={
                "firm_id": firm_id,
                "email": email,
                "phone": phone_normalized,
                "token": token,
                "invited_by": user_id,
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat(),
            },
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
        # Trello ST-01: carry through the optional phone + the email captured
        # on the invite to the firm_users row so the SMS handler can recognize
        # this team member when they text Hazel.
        invite_phone = invite.get("phone") or None
        invite_email = (invite.get("email") or "").lower() or None

        # Add to firm (ignore duplicate)
        requests.post(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json",
                     "Prefer": "return=representation,resolution=ignore-duplicates"},
            json={
                "firm_id": firm_id,
                "user_id": user_id,
                "role": "member",
                "invited_by": invite.get("invited_by"),
                "phone": invite_phone,
                "email": invite_email,
            },
            timeout=5,
        )

        # If the row already existed (ignore-duplicates path), patch the
        # phone + email forward in case they were captured on a re-invite.
        if invite_phone or invite_email:
            patch_fields = {}
            if invite_phone: patch_fields["phone"] = invite_phone
            if invite_email: patch_fields["email"] = invite_email
            try:
                requests.patch(
                    f"{SUPABASE_URL}/rest/v1/firm_users",
                    headers={**SB_HEADERS, "Content-Type": "application/json"},
                    params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{user_id}"},
                    json=patch_fields,
                    timeout=5,
                )
            except Exception as e:
                logging.warning(f"api_invites_accept: forward phone/email patch failed (non-fatal): {e}")

        # Mark token used
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/invite_tokens",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"id": f"eq.{invite['id']}"},
            json={"used_at": datetime.now(timezone.utc).isoformat()},
            timeout=5,
        )

        # Trello ST-01: welcome email on acceptance. Non-fatal — if AgentMail
        # is unreachable the user is still added to the firm.
        try:
            firm_r = requests.get(
                f"{SUPABASE_URL}/rest/v1/firms",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"id": f"eq.{firm_id}", "select": "display_name", "limit": "1"},
                timeout=5,
            )
            firm_name = (firm_r.json()[0].get("display_name") if firm_r.ok and firm_r.json() else None) or "your firm"
        except Exception:
            firm_name = "your firm"

        welcome_to = invite_email
        if welcome_to and AGENTMAIL_KEY:
            try:
                # Hazel's primary inbound SMS number — the verified Telnyx TFN.
                # Update this constant if the public Hazel number ever changes.
                HAZEL_PHONE = "+1 (888) 281-2061"
                DASHBOARD_URL = "https://hazel.haventechsolutions.com/"
                requests.post(
                    "https://api.agentmail.to/v0/inboxes/itshazel@agentmail.to/messages/send",
                    headers={"Authorization": f"Bearer {AGENTMAIL_KEY}", "Content-Type": "application/json"},
                    json={
                        "to": [welcome_to],
                        "subject": f"You're on the team — here's how to reach Hazel",
                        "text": (
                            f"You've been added to {firm_name} on Hazel. "
                            f"Hazel is your AI back-of-house assistant.\n\n"
                            f"You can reach her any time by text or call at {HAZEL_PHONE}.\n\n"
                            f"You can also log in to your dashboard at {DASHBOARD_URL}\n"
                        ),
                        "html": (
                            f"<p>You've been added to <strong>{firm_name}</strong> on Hazel. "
                            f"Hazel is your AI back-of-house assistant.</p>"
                            f"<p>You can reach her any time by text or call at "
                            f"<strong>{HAZEL_PHONE}</strong>.</p>"
                            f"<p>You can also log in to your dashboard at "
                            f"<a href=\"{DASHBOARD_URL}\">{DASHBOARD_URL}</a>.</p>"
                        ),
                    },
                    timeout=10,
                )
            except Exception as e:
                logging.warning(f"api_invites_accept welcome email (non-fatal): {e}")

        # Trello ST-01: welcome SMS to the new team member's phone. DEFERRED
        # pending TCPA / Telnyx opt-in confirmation from Robert — sending
        # outbound SMS to a new number without prior consent is risky under
        # carrier rules. When Robert confirms the opt-in story (likely the
        # ST-03 placeholder), add the Telnyx sendSms call here using
        # invite_phone as the destination. Copy template:
        #   "Hi <FirstName>, you've been added to <firm_name> on Hazel.
        #    Text or call this number any time. Reply STOP to opt out."
        if invite_phone:
            logging.info(
                f"api_invites_accept: skipping welcome SMS to {invite_phone[-4:]} — pending TCPA confirmation (ST-03)"
            )

        logging.info(f"Invite accepted: user {user_id[:8]} joined firm {firm_id[:8]}")
        return jsonify({"status": "accepted", "firm_id": firm_id}), 200
    except Exception as e:
        logging.error(f"api_invites_accept: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/firm-users/<target_user_id>", methods=["PATCH"])
@require_auth
def api_firm_users_patch(target_user_id):
    """Update a team member's display email or phone.

    Trello ST-02. Access rules:
      - Owner of the firm: may patch ANY firm_users row in their firm.
      - Member: may patch ONLY their own row. 403 on any other target.

    Body accepts:
      email — string (optional). Stored on firm_users.email as a display
              override. Does NOT modify auth.users.email — keeping the auth
              login email decoupled avoids OAuth + re-verification rabbit
              holes. The /api/team endpoint falls back to auth email when
              firm_users.email is null.
      phone — string (optional). Normalized to E.164 the same way the
              invite path does it. Empty / unparseable shapes are written
              as null rather than rejected so a member can clear their
              phone.

    Either or both may be present. At least one must be present (else 400).
    """
    user_id = g.user_id
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404

    body = request.get_json(force=True) or {}
    has_email = "email" in body
    has_phone = "phone" in body
    if not has_email and not has_phone:
        return jsonify({"error": "email or phone required"}), 400

    # Resolve caller role + verify target belongs to caller's firm
    try:
        caller_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{user_id}",
                    "select": "role", "limit": "1"},
            timeout=5,
        )
        caller_r.raise_for_status()
        caller_rows = caller_r.json()
        if not caller_rows:
            return jsonify({"error": "Caller not in any firm"}), 403
        caller_role = caller_rows[0].get("role")
    except Exception as e:
        logging.error(f"api_firm_users_patch caller lookup: {e}")
        return jsonify({"error": "Internal server error"}), 500

    is_owner = caller_role == "owner"
    is_self = user_id == target_user_id

    if not is_owner and not is_self:
        return jsonify({"error": "Only the firm owner can edit other team members"}), 403

    # Verify target exists in this firm (otherwise an owner could try to
    # PATCH a user_id from a different firm).
    try:
        tgt_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{target_user_id}",
                    "select": "id", "limit": "1"},
            timeout=5,
        )
        tgt_r.raise_for_status()
        if not tgt_r.json():
            return jsonify({"error": "Target user is not in your firm"}), 404
    except Exception as e:
        logging.error(f"api_firm_users_patch target lookup: {e}")
        return jsonify({"error": "Internal server error"}), 500

    patch = {}
    if has_email:
        email_val = (body.get("email") or "").strip().lower()
        patch["email"] = email_val if email_val else None
    if has_phone:
        raw_phone = (body.get("phone") or "").strip()
        if not raw_phone:
            patch["phone"] = None
        else:
            digits = "".join(c for c in raw_phone if c.isdigit())
            normalized = None
            if len(digits) == 10:
                normalized = "+1" + digits
            elif len(digits) == 11 and digits.startswith("1"):
                normalized = "+" + digits
            elif raw_phone.startswith("+") and len(digits) >= 10:
                normalized = "+" + digits
            # Unparseable — write null and log. Don't reject the whole patch.
            if normalized is None:
                logging.info(f"api_firm_users_patch: phone '{raw_phone}' not parseable; storing null")
            patch["phone"] = normalized

    try:
        r = requests.patch(
            f"{SUPABASE_URL}/rest/v1/firm_users",
            headers={**SB_HEADERS, "Content-Type": "application/json",
                     "Prefer": "return=representation"},
            params={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{target_user_id}"},
            json=patch,
            timeout=5,
        )
        r.raise_for_status()
        rows = r.json()
        if not rows:
            return jsonify({"error": "No row updated"}), 404
        return jsonify({"status": "updated", "firm_user": rows[0]}), 200
    except Exception as e:
        logging.error(f"api_firm_users_patch update: {e}")
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
            "scope": "https://www.googleapis.com/auth/gmail.send",
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
    # project_id is now optional. When omitted (or explicitly null), the
    # message is portfolio-level (Trello bjmtUk8K) — the hazel-plugin's
    # ChatHandler branches on null project_id to inject firm-only context
    # and use the firm-scoped session key. Migration 023 makes the column
    # nullable; without that this insert will 500 on the upstream.
    project_id  = (body.get("project_id") or "").strip() or None
    content     = (body.get("content") or "").strip()
    attachments = body.get("attachments") or []
    if not content and not attachments:
        return jsonify({"error": "content or attachments required"}), 400
    insert = {"firm_id": firm_id, "role": "builder",
              "content": content, "attachments": attachments}
    if project_id:
        insert["project_id"] = project_id
    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/messages",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation"},
            json=insert,
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
    """Load messages via service role (bypasses RLS). Two modes:

    - ?project_id=<uuid>     project-scoped chat history (existing behavior)
    - ?scope=portfolio       firm-scoped portfolio chat (Trello bjmtUk8K) —
                             returns rows where project_id IS NULL for the
                             caller's firm.

    Exactly one of the two must be provided. Both modes are firm-scoped via
    g.firm_id, so cross-firm reads are impossible regardless of which the
    caller picks.
    """
    firm_id = g.firm_id
    if not firm_id:
        return jsonify({"error": "No firm found for this user"}), 404
    project_id = request.args.get("project_id", "").strip()
    scope      = request.args.get("scope", "").strip().lower()
    if not project_id and scope != "portfolio":
        return jsonify({"error": "project_id or scope=portfolio is required"}), 400
    params = {"select": "*", "order": "created_at.asc", "limit": "100",
              "firm_id": f"eq.{firm_id}"}
    if project_id:
        params["project_id"] = f"eq.{project_id}"
    else:
        # Portfolio scope: only rows with no project anchor.
        params["project_id"] = "is.null"
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/messages",
            headers={**SB_HEADERS, "Content-Type": "application/json"},
            params=params,
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


# ── FILE-INSERT WEBHOOK: HEIC convert + auto analysis ─────────────────────────
# Trello lMF0d0MQ (auto analyze) + exLqKUSR (HEIC preview conversion).
#
# Triggered by a Supabase Database Webhook on `files` INSERT. One download,
# two passes:
#
#   1. HEIC pass (exLqKUSR)
#      .heic/.heif → convert to JPEG via pillow-heif + Pillow, upload as
#      project-files/{project_id}/photos/{stem}_converted.jpg, PATCH
#      files.converted_path. The dashboard renders converted_path so the
#      builder sees a thumbnail seconds after upload instead of waiting on
#      the systemd backstop timer.
#
#   2. Analyze pass (lMF0d0MQ)
#      Extract text (pdfplumber for PDFs, python-docx for .docx, raw decode
#      for txt/md/csv/json/etc.), POST to the plugin's
#      /hazel/internal/analyze-file endpoint. The plugin runs an agent turn
#      under the project's dashboard session key and writes Hazel's read of
#      the file straight to messages.
#
# Idempotency:
#   - analyzed_at flips to now() before the worker spawns, so retries no-op
#     and a crash mid-analysis won't loop us forever.
#   - converted_path is set by the HEIC pass itself; the systemd timer
#     (hazel-heic-convert.timer, 15min cadence) sweeps up rows that the
#     webhook missed (server down at insert time, transient pillow crash,
#     backfills).
#
# Supabase webhook config (one-time setup in Studio):
#   Table: files, Events: INSERT
#   URL:    https://<this-host>/webhook/file-inserted
#   Headers: Authorization: Bearer <SUPABASE_FILE_WEBHOOK_SECRET>
#
# Droplet deps:
#   pip3 install pdfplumber python-docx pillow-heif Pillow --break-system-packages
SUPABASE_FILE_WEBHOOK_SECRET = os.getenv("SUPABASE_FILE_WEBHOOK_SECRET", "")
_TEXT_LIKE_EXTS = {"txt", "md", "csv", "log", "json", "xml", "html", "htm"}
_HEIC_EXTS      = {"heic", "heif"}
_MAX_TEXT_CHARS = 20_000  # cap what we ship to the agent
_JPEG_QUALITY   = 85      # match heic_convert.py


def _extract_pdf_text(data: bytes) -> str:
    try:
        import io
        import pdfplumber  # type: ignore
        out = []
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for page in pdf.pages:
                t = page.extract_text() or ""
                if t.strip():
                    out.append(t)
                if sum(len(s) for s in out) > _MAX_TEXT_CHARS:
                    break
        return "\n\n".join(out).strip()
    except Exception as e:
        logging.warning(f"extract_pdf_text: {e}")
        return ""


def _extract_docx_text(data: bytes) -> str:
    try:
        import io
        import docx  # python-docx, type: ignore
        d = docx.Document(io.BytesIO(data))
        paras = [p.text for p in d.paragraphs if p.text and p.text.strip()]
        return "\n".join(paras).strip()
    except Exception as e:
        logging.warning(f"extract_docx_text: {e}")
        return ""


def _extract_text(data: bytes, ext: str) -> str:
    ext = (ext or "").lower().lstrip(".")
    if ext == "pdf":
        return _extract_pdf_text(data)
    if ext == "docx":
        return _extract_docx_text(data)
    if ext in _TEXT_LIKE_EXTS:
        try:
            return data.decode("utf-8", errors="replace")[:_MAX_TEXT_CHARS]
        except Exception:
            return ""
    return ""  # image, heic, xlsx, etc. — let Hazel pull the bytes herself if needed


def _convert_heic_to_jpeg(heic_bytes: bytes) -> bytes:
    """Decode HEIC → JPEG bytes. Mirrors heic_convert.py's logic so the
    backstop timer and the live webhook produce identical output."""
    import io
    import pillow_heif  # type: ignore
    from PIL import Image, ImageOps  # type: ignore
    pillow_heif.register_heif_opener()
    img = Image.open(io.BytesIO(heic_bytes))
    try:
        img = ImageOps.exif_transpose(img)  # respect iPhone orientation EXIF
    except Exception:
        pass
    if img.mode != "RGB":
        img = img.convert("RGB")  # JPEG can't carry alpha
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=_JPEG_QUALITY, optimize=True)
    return out.getvalue()


def _heic_pass(file_id: str, project_id: str, storage_path: str, raw_bytes: bytes):
    """Convert + upload JPEG sibling + persist converted_path. No-ops on failure
    (the systemd backstop will retry)."""
    try:
        jpeg_bytes = _convert_heic_to_jpeg(raw_bytes)
    except ImportError:
        logging.error(
            "file_inserted: pillow-heif/Pillow not installed — "
            "run: pip3 install pillow-heif Pillow --break-system-packages"
        )
        return
    except Exception as e:
        logging.warning(f"file_inserted: HEIC decode failed for {storage_path}: {e}")
        return

    # Path mirrors heic_convert.py exactly so the dashboard renders consistently.
    from os.path import splitext, basename
    stem = splitext(basename(storage_path))[0]
    dest_path = f"{project_id}/photos/{stem}_converted.jpg"
    try:
        up = requests.post(
            f"{SUPABASE_URL}/storage/v1/object/project-files/{dest_path}",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "image/jpeg",
                "x-upsert": "true",  # safe on webhook retry / timer collision
            },
            data=jpeg_bytes, timeout=60,
        )
        if not up.ok:
            logging.warning(
                f"file_inserted: HEIC JPEG upload {up.status_code}: {up.text[:200]}"
            )
            return
    except Exception as e:
        logging.warning(f"file_inserted: HEIC JPEG upload exception: {e}")
        return

    try:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/files",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal"},
            params={"id": f"eq.{file_id}"},
            json={"converted_path": dest_path},
            timeout=5,
        )
        logging.info(
            f"file_inserted: HEIC→JPEG {file_id[:8]} converted_path={dest_path}"
        )
    except Exception as e:
        logging.warning(f"file_inserted: HEIC converted_path PATCH exception: {e}")


def _process_uploaded_file_async(file_row: dict):
    """Background worker: download bytes once, then run any passes the file
    type qualifies for (HEIC conversion, text extraction + analyze handoff)."""
    file_id      = file_row.get("id") or ""
    project_id   = file_row.get("project_id") or ""
    firm_id      = file_row.get("firm_id") or ""
    storage_path = file_row.get("storage_path") or ""
    file_name    = file_row.get("name") or "unnamed file"
    file_type    = (file_row.get("file_type") or "").lower().lstrip(".")
    category     = file_row.get("category") or "uncategorized"

    if not (file_id and project_id and storage_path):
        logging.warning(f"file_inserted: skipping incomplete row file_id={file_id}")
        return

    # Single download — both passes share the bytes.
    raw_bytes = b""
    try:
        dr = requests.get(
            f"{SUPABASE_URL}/storage/v1/object/project-files/{storage_path}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
            timeout=60,
        )
        if not dr.ok:
            logging.warning(
                f"file_inserted: storage download {dr.status_code} for {storage_path}"
            )
            return
        raw_bytes = dr.content
    except Exception as e:
        logging.warning(f"file_inserted: download exception: {e}")
        return

    # Pass 1 — HEIC conversion (independent of analyze pass; failures don't
    # block the analyze handoff because the timer will retry conversion).
    if file_type in _HEIC_EXTS:
        _heic_pass(file_id, project_id, storage_path, raw_bytes)

    # Pass 2 — text extraction + analyze handoff. We currently run this for
    # every file type (per "leave it as is" decision); images fall through
    # to the plugin with extracted_text="" and Hazel may give a light
    # acknowledgement. Swap in a skip-set if that proves noisy.
    extracted_text = _extract_text(raw_bytes, file_type)
    if extracted_text:
        logging.info(
            f"file_inserted: extracted {len(extracted_text)} chars from {file_name}"
        )

    plugin_url = f"{OPENCLAW_URL}/hazel/internal/analyze-file"
    headers = {"Content-Type": "application/json"}
    plugin_token = os.getenv("HAZEL_INTERNAL_TOKEN", "")
    if plugin_token:
        headers["X-Internal-Token"] = plugin_token
    try:
        pr = requests.post(
            plugin_url,
            headers=headers,
            json={
                "project_id": project_id,
                "firm_id": firm_id,
                "file_id": file_id,
                "file_name": file_name,
                "file_type": file_type,
                "category": category,
                "storage_path": storage_path,
                "extracted_text": extracted_text,
            },
            timeout=15,  # plugin acks fast and runs the turn async
        )
        if not pr.ok:
            logging.warning(
                f"file_inserted: plugin returned {pr.status_code} {pr.text[:200]}"
            )
    except Exception as e:
        logging.warning(f"file_inserted: plugin POST exception: {e}")


@app.route("/webhook/file-inserted", methods=["POST"])
def webhook_file_inserted():
    """Supabase Database Webhook → kick off auto file analysis.

    Body shape (Supabase Database Webhooks):
      { "type": "INSERT", "table": "files", "record": {...}, "old_record": null, ... }
    """
    # Auth: shared secret in Authorization header. Webhooks dashboard lets
    # you configure arbitrary headers per webhook.
    if SUPABASE_FILE_WEBHOOK_SECRET:
        auth = request.headers.get("Authorization", "")
        expected = f"Bearer {SUPABASE_FILE_WEBHOOK_SECRET}"
        if auth != expected and auth.replace("bearer ", "Bearer ", 1) != expected:
            logging.warning("file_inserted: bad/missing Authorization header")
            return jsonify({"error": "unauthorized"}), 401
    else:
        # No secret configured — only allow loopback callers.
        if request.remote_addr not in ("127.0.0.1", "::1"):
            return jsonify({"error": "SUPABASE_FILE_WEBHOOK_SECRET not set"}), 401

    try:
        payload = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    if (payload.get("type") or "").upper() != "INSERT":
        return jsonify({"status": "ignored", "reason": "non-insert"}), 200

    record = payload.get("record") or {}
    file_id      = record.get("id") or ""
    project_id   = record.get("project_id")
    archived     = bool(record.get("archived"))
    analyzed_at  = record.get("analyzed_at")
    upload_source = (record.get("upload_source") or "").lower()

    # Skip rows the partial index wouldn't have picked up anyway.
    if not file_id:
        return jsonify({"status": "ignored", "reason": "missing id"}), 200
    if not project_id:
        return jsonify({"status": "ignored", "reason": "no project (inbox MMS)"}), 200
    if archived:
        return jsonify({"status": "ignored", "reason": "archived"}), 200
    if analyzed_at:
        return jsonify({"status": "ignored", "reason": "already analyzed"}), 200

    # Mark analyzed_at NOW (before handing off) so any retry of this webhook
    # — or a parallel discovery via the partial index — no-ops. We accept
    # losing the analysis if the background thread crashes; better than
    # looping on a poison-pill file.
    try:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/files",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal"},
            params={"id": f"eq.{file_id}"},
            json={"analyzed_at": "now()"},
            timeout=5,
        )
    except Exception as e:
        logging.warning(f"file_inserted: failed to mark analyzed_at: {e}")

    # Hand off. Daemon thread so a process restart doesn't hang on it.
    t = threading.Thread(
        target=_process_uploaded_file_async,
        args=(record,),
        daemon=True,
        name=f"file-analyze-{file_id[:8]}",
    )
    t.start()
    logging.info(
        f"file_inserted: queued analysis for {file_id[:8]} project={str(project_id)[:8]} source={upload_source or '?'}"
    )
    return jsonify({"status": "queued"}), 200


# ── RISK DETECTION (Trello YsevHmJQ — Option B, Supabase-only) ────────────────
# Aggregates per-project signals from Supabase tables into project_risks rows
# the dashboard's portfolio cards consume directly. No graph/Neo4j dependency.
#
# Trigger: POST /api/hazel/internal/detect-risks (cron every 30 min on droplet,
# or manual trigger for testing). Auth via shared X-Internal-Token header.
#
# Categories implemented in v1:
#   pending-decision : oldest active queue_item age (48-72h yellow / >72h red)
#   unapproved-co    : change-order queue_item age in business days (>5 red)
#   budget-variance  : worst-pct-over from qbo_job_cost_cache (5-10% yellow / >10% red)
# Categories deferred:
#   sub-gap          : needs reliable inbound-sender tracking we don't have yet
#   schedule-slip    : no schedule signal source without graph
#   permit-delay     : out of scope per original spec

INTERNAL_TOKEN = os.getenv("HAZEL_INTERNAL_TOKEN", "")


def _require_internal_token():
    """Reject request unless X-Internal-Token matches HAZEL_INTERNAL_TOKEN.
    If the env var is unset, allow only loopback callers — keeps a freshly
    deployed droplet from accidentally exposing the endpoint."""
    if not INTERNAL_TOKEN:
        if request.remote_addr not in ("127.0.0.1", "::1"):
            return False
        return True
    return request.headers.get("X-Internal-Token", "") == INTERNAL_TOKEN


def _sb_get(path, params):
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{path}",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params=params, timeout=8,
    )
    r.raise_for_status()
    return r.json()


_QUEUE_TYPE_LABELS = {
    "change-order": "Change order",
    "email":        "Email reply",
    "invoice":      "Invoice",
    "daily-log":    "Daily log",
    "needs-info":   "Needs info",
}


def _business_days_between(start_dt, end_dt):
    """Whole business days between two datetimes (Mon-Fri). Good enough for
    threshold checks; no holiday calendar."""
    from datetime import timedelta
    if end_dt < start_dt:
        return 0
    days = 0
    cur = start_dt.date()
    end = end_dt.date()
    while cur < end:
        cur = cur + timedelta(days=1)
        if cur.weekday() < 5:
            days += 1
    return days


def _detect_pending_decision(firm_id, project_id):
    rows = _sb_get("queue_items", {
        "firm_id": f"eq.{firm_id}",
        "project_id": f"eq.{project_id}",
        "status": "eq.active",
        "select": "id,type,title,created_at",
        "order": "created_at.asc",
        "limit": "1",
    })
    if not rows:
        return None
    from datetime import datetime, timezone
    oldest = rows[0]
    created = datetime.fromisoformat(oldest["created_at"].replace("Z", "+00:00"))
    age_hours = (datetime.now(timezone.utc) - created).total_seconds() / 3600
    if age_hours < 48:
        return None
    label = _QUEUE_TYPE_LABELS.get(oldest.get("type") or "", "Item")
    days = max(1, round(age_hours / 24))
    sev = "red" if age_hours > 72 else "yellow"
    title = oldest.get("title") or label
    desc = f"{title} pending {days} day{'s' if days != 1 else ''}"
    return {"severity": sev, "description": desc}


def _detect_unapproved_co(firm_id, project_id):
    rows = _sb_get("queue_items", {
        "firm_id": f"eq.{firm_id}",
        "project_id": f"eq.{project_id}",
        "status": "eq.active",
        "type": "eq.change-order",
        "select": "id,title,created_at",
        "order": "created_at.asc",
        "limit": "1",
    })
    if not rows:
        return None
    from datetime import datetime, timezone
    oldest = rows[0]
    created = datetime.fromisoformat(oldest["created_at"].replace("Z", "+00:00"))
    bdays = _business_days_between(created, datetime.now(timezone.utc))
    if bdays < 5:
        return None
    title = oldest.get("title") or "Change order"
    return {
        "severity": "red",
        "description": f"{title} awaiting approval — {bdays} business days",
    }


def _detect_budget_variance(firm_id, project_id):
    rows = _sb_get("qbo_job_cost_cache", {
        "firm_id": f"eq.{firm_id}",
        "project_id": f"eq.{project_id}",
        "select": "cost_code,cost_code_name,budgeted_amount,actual_amount",
    })
    if not rows:
        return None
    worst_pct = 0.0
    worst_row = None
    for row in rows:
        try:
            b = float(row.get("budgeted_amount") or 0)
            a = float(row.get("actual_amount") or 0)
        except (TypeError, ValueError):
            continue
        if b <= 0:
            continue
        pct = (a - b) / b
        if pct > worst_pct:
            worst_pct = pct
            worst_row = row
    if worst_pct <= 0.05 or not worst_row:
        return None
    name = worst_row.get("cost_code_name") or worst_row.get("cost_code") or "a cost code"
    over = float(worst_row["actual_amount"]) - float(worst_row["budgeted_amount"])
    sev = "red" if worst_pct > 0.10 else "yellow"
    if sev == "red":
        return {"severity": sev, "description": f"Over budget on {name} by ${int(over):,}"}
    return {"severity": sev, "description": f"Trending over budget on {name}"}


_DETECTORS = [
    ("pending-decision", _detect_pending_decision),
    ("unapproved-co",    _detect_unapproved_co),
    ("budget-variance",  _detect_budget_variance),
]


def _upsert_risk(firm_id, project_id, category, finding):
    """Idempotent upsert keyed on (project_id, category). When finding is
    None and an active row exists, mark it resolved."""
    existing = _sb_get("project_risks", {
        "project_id": f"eq.{project_id}",
        "category":   f"eq.{category}",
        "select": "id,severity,description,resolved",
        "limit": "1",
    })
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    if finding is None:
        # Condition cleared. Resolve any existing active row.
        if existing and not existing[0].get("resolved"):
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/project_risks",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"id": f"eq.{existing[0]['id']}"},
                json={"resolved": True, "resolved_at": now_iso},
                timeout=5,
            )
        return None

    if existing:
        # Update if severity or description changed
        cur = existing[0]
        changed = (
            cur.get("severity") != finding["severity"]
            or cur.get("description") != finding["description"]
            or cur.get("resolved")
        )
        if changed:
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/project_risks",
                headers={**SB_HEADERS, "Content-Type": "application/json"},
                params={"id": f"eq.{cur['id']}"},
                json={
                    "severity":    finding["severity"],
                    "description": finding["description"],
                    "detected_at": now_iso,
                    "resolved":    False,
                    "resolved_at": None,
                },
                timeout=5,
            )
        return finding["severity"]

    requests.post(
        f"{SUPABASE_URL}/rest/v1/project_risks",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        json={
            "project_id":  project_id,
            "firm_id":     firm_id,
            "category":    category,
            "severity":    finding["severity"],
            "description": finding["description"],
            "detected_at": now_iso,
        },
        timeout=5,
    )
    return finding["severity"]


def _roll_up_status(severities):
    """Worst-active-severity → projects.status."""
    s = [x for x in severities if x]
    if "red" in s:    return "delayed"
    if "yellow" in s: return "at-risk"
    return "on-track"


def _detect_for_project(firm_id, project_id):
    """Run all detectors against one project. Returns the rolled-up status."""
    severities = []
    for category, fn in _DETECTORS:
        try:
            finding = fn(firm_id, project_id)
        except Exception as e:
            logging.warning(f"risk_detect[{category}] {project_id[:8]}: {e}")
            finding = None
        severities.append(_upsert_risk(firm_id, project_id, category, finding))
    return _roll_up_status(severities)


@app.route("/api/hazel/internal/detect-risks", methods=["POST"])
def api_detect_risks():
    if not _require_internal_token():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    firm_id_filter = (body.get("firm_id") or "").strip() or None

    # Resolve target firms
    if firm_id_filter:
        firms = [{"id": firm_id_filter}]
    else:
        firms = _sb_get("firms", {"select": "id"})

    summary = {"firms": 0, "projects": 0, "errors": []}
    for firm in firms:
        firm_id = firm["id"]
        summary["firms"] += 1
        try:
            projects = _sb_get("projects", {
                "firm_id": f"eq.{firm_id}",
                "status": "neq.archived",
                "select": "id,status",
            })
        except Exception as e:
            summary["errors"].append(f"firm {firm_id[:8]}: {e}")
            continue
        for p in projects:
            summary["projects"] += 1
            try:
                new_status = _detect_for_project(firm_id, p["id"])
                if new_status and p.get("status") != new_status:
                    requests.patch(
                        f"{SUPABASE_URL}/rest/v1/projects",
                        headers={**SB_HEADERS, "Content-Type": "application/json"},
                        params={"id": f"eq.{p['id']}"},
                        json={"status": new_status},
                        timeout=5,
                    )
            except Exception as e:
                summary["errors"].append(f"project {p['id'][:8]}: {e}")
    return jsonify(summary), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8700, threaded=True)

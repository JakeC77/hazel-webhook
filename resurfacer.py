#!/usr/bin/env python3
"""
AQ-04: Hold Re-surface Poller
Runs on a systemd timer (every 15 min).
Finds queue_items where status='snoozed' AND held_at IS NOT NULL
AND held_at + resurface_after <= now()
→ flips them back to 'active', sets last_nudge_at
Optionally sends an SMS nudge via ClawdTalk.
"""

import os
import sys
import logging
import requests
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://zrolyrtaaaiauigrvusl.supabase.co")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
CLAWDTALK_TOKEN = os.environ.get("CLAWDTALK_TOKEN", "")
HAZEL_PHONE = os.environ.get("HAZEL_PHONE", "+12066032566")

SB_HEADERS = {
    "apikey": SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
}

def resurfaced_items():
    """Query queue_items ready to resurface."""
    # Postgres: held_at + resurface_after <= now() AND status = 'snoozed'
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/rpc/get_resurface_items",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        json={},
        timeout=10,
    )
    if r.status_code == 200:
        return r.json()

    # Fallback: direct query with PostgREST filter
    # resurface_after is an interval — calculate deadline client-side isn't possible via REST.
    # Use a DB function for correctness; if missing, fall back to items snoozed > 24h ago.
    r2 = requests.get(
        f"{SUPABASE_URL}/rest/v1/queue_items",
        headers={**SB_HEADERS},
        params={
            "status": "eq.snoozed",
            "held_at": "not.is.null",
            "select": "id,title,project_id,held_at,resurface_after,firm_id",
        },
        timeout=10,
    )
    r2.raise_for_status()
    now = datetime.now(timezone.utc)
    results = []
    for item in r2.json():
        held_at_str = item.get("held_at")
        if not held_at_str:
            continue
        # Parse interval: resurface_after like "24 hours" → 24h
        interval_str = item.get("resurface_after") or "24 hours"
        try:
            hours = float(interval_str.split()[0])
        except Exception:
            hours = 24.0
        from datetime import timedelta
        held_at = datetime.fromisoformat(held_at_str.replace("Z", "+00:00"))
        deadline = held_at + timedelta(hours=hours)
        if now >= deadline:
            results.append(item)
    return results


def reactivate(item_id: str) -> bool:
    now_iso = datetime.now(timezone.utc).isoformat()
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/queue_items",
        headers={**SB_HEADERS, "Content-Type": "application/json"},
        params={"id": f"eq.{item_id}"},
        json={"status": "active", "last_nudge_at": now_iso},
        timeout=10,
    )
    return r.ok


def send_sms_nudge(item: dict):
    if not CLAWDTALK_TOKEN:
        return
    # Look up the firm's phone number
    firm_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers={**SB_HEADERS},
        params={"id": f"eq.{item.get('firm_id')}", "select": "phone", "limit": "1"},
        timeout=5,
    )
    if not firm_r.ok:
        return
    rows = firm_r.json()
    builder_phone = rows[0].get("phone") if rows else None
    if not builder_phone:
        return

    msg = f"📋 Hazel reminder: '{item.get('title', 'An item')}' is back in your approval queue."
    requests.post(
        "https://clawdtalk.com/v1/messages/send",
        headers={"Authorization": f"Bearer {CLAWDTALK_TOKEN}", "Content-Type": "application/json"},
        json={"to": builder_phone, "from": HAZEL_PHONE, "message": msg},
        timeout=10,
    )


def main():
    logging.info("Resurfacer: checking for held items ready to resurface...")
    try:
        items = resurfaced_items()
    except Exception as e:
        logging.error(f"Failed to fetch items: {e}")
        sys.exit(1)

    if not items:
        logging.info("Nothing to resurface.")
        return

    for item in items:
        item_id = item["id"]
        title   = item.get("title", item_id)
        logging.info(f"Reactivating: {title} ({item_id})")
        ok = reactivate(item_id)
        if ok:
            logging.info(f"  ✅ Reactivated")
            send_sms_nudge(item)
        else:
            logging.error(f"  ❌ Failed to reactivate {item_id}")

    logging.info(f"Resurfacer done. Processed {len(items)} item(s).")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Hazel daily briefing scheduler (Trello YEVhbMpF).

Run every minute via systemd timer (hazel-briefing-scheduler.timer). At each
tick we:

  1. Query firm_preferences for firms where:
       morning_briefing_enabled = true     (opt-in gate — migration 024 set
                                            the default to false and reset
                                            all existing firms; a firm must
                                            explicitly toggle it on in
                                            Settings > Preferences before
                                            they'll ever be in this list)
       morning_briefing_time   LIKE 'HH:MM:%'   (matches the current UTC
                                                 minute)

  2. For each match, check idempotency: is there already a morning_briefings
     row for this firm + today's UTC date? Skip if so.

  3. POST to the plugin's /hazel/internal/generate-briefing endpoint with
     {firm_id}. The plugin runs Hazel agent, writes the briefing row, and
     sends SMS via Telnyx.

The opt-in gate is enforced by the SQL filter — no exception path. Triple-
checked: scheduler filter + plugin endpoint (also pulls firm context only
when firmId resolved) + migration 024 default.

Time handling: morning_briefing_time is stored as Postgres TIME (HH:MM:SS),
representing the BUILDER'S LOCAL TIME (whatever the user picked in the
Settings <input type="time">). Per-firm timezone is read from firms.timezone
(IANA string, default 'America/Los_Angeles' per migration 006). For each
tick we compute "now in that firm's timezone" and HH:MM-compare against
the configured time. So a Pacific-time firm picking 7:00 AM fires at
07:00 PT (= 15:00 UTC during PDT), not at 07:00 UTC.

Logging is intentionally quiet on idle ticks — there's a tick every minute,
and at any given minute most firms won't match. We only log when there's
work to do or an error occurs.
"""

import os
import sys
import logging
import requests
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s briefing-scheduler %(levelname)s %(message)s",
)
log = logging.getLogger()

# SUPABASE_URL is hardcoded in server.py (line ~67) rather than .env, so we
# do the same here to keep the deploy story consistent. Override via env if
# we ever set up a second Supabase project.
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://zrolyrtaaaiauigrvusl.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
PLUGIN_URL   = os.getenv("PLUGIN_URL", "http://127.0.0.1:18789")
AGENTMAIL_KEY = os.getenv("AGENTMAIL_KEY", "")

# Internal alert recipients for briefing-SMS-failure notifications. We
# learned the hard way (2026-05-17 through 2026-05-21) that a silent
# sent_sms=false is invisible to the team — Robert just stopped getting
# briefings and no one knew until he asked five days later.
ALERT_RECIPIENTS = [
    "jake@haventechsolutions.com",
    "robert@haventechsolutions.com",
]

if not SUPABASE_KEY:
    log.error("Missing SUPABASE_SERVICE_KEY in environment")
    sys.exit(1)

SB_HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
}


DEFAULT_TZ = "America/Los_Angeles"


def _send_briefing_failure_alert(firm_id: str, firm_name: str, briefing_id: str, today_iso: str):
    """Internal alert to the Haven team when the plugin returns
    sent_sms=false on a generated briefing. Fires from the scheduler so
    Telnyx hiccups, malformed phone numbers, encoding failures, etc., all
    surface to a human within minutes instead of accumulating into a
    silent multi-day outage. Fire-and-forget — never raises."""
    if not AGENTMAIL_KEY:
        log.warning("_send_briefing_failure_alert: AGENTMAIL_KEY not set, skipping")
        return
    try:
        ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        body = (
            f"Hazel generated a morning briefing for {firm_name} but the SMS to the "
            "firm's phone failed.\n\n"
            f"Firm:        {firm_name}\n"
            f"Firm ID:     {firm_id}\n"
            f"Briefing ID: {briefing_id}\n"
            f"Date:        {today_iso}\n"
            f"Detected:    {ts_utc}\n\n"
            "The briefing content is still in the database and visible to the "
            "builder on their dashboard (Settings / Account or the Hazel Chat "
            "portfolio card). Only the SMS leg failed.\n\n"
            "Check the plugin logs around the time above for the Telnyx error:\n"
            f"  ssh root@64.23.173.57 \"journalctl -u openclaw --since '{ts_utc}' | grep -i 'briefing\\\\|telnyx'\"\n\n"
            "Common causes:\n"
            "- Telnyx 40302: SMS body exceeded 10-segment cap (recently fixed in formatSmsBody)\n"
            "- Telnyx 40310: firm.phone not in E.164 / not a real US mobile\n"
            "- Telnyx outage / API key revoked\n"
            "- Plugin restart mid-send"
        )
        r = requests.post(
            "https://api.agentmail.to/v0/inboxes/itshazel@agentmail.to/messages/send",
            headers={"Authorization": f"Bearer {AGENTMAIL_KEY}", "Content-Type": "application/json"},
            json={
                "to": ALERT_RECIPIENTS,
                "subject": f"[Hazel] Briefing SMS failed for {firm_name}",
                "text": body,
            },
            timeout=10,
        )
        if not r.ok:
            log.warning(
                f"_send_briefing_failure_alert: AgentMail HTTP {r.status_code}: {r.text[:200]}"
            )
        else:
            log.info(
                f"_send_briefing_failure_alert: notified {len(ALERT_RECIPIENTS)} recipients "
                f"about firm {firm_id[:8]} / briefing {briefing_id[:8]}"
            )
    except Exception as e:
        log.warning(f"_send_briefing_failure_alert (non-fatal): {e}")


def _firm_local_hhmm(now_utc: datetime, tz_name: str) -> str:
    """Return current HH:MM in the firm's local timezone. Falls back to
    America/Los_Angeles if the stored tz string is missing or unknown
    (e.g., typo, deprecated TZ name) so a bad value never silently
    suppresses a firm's briefings."""
    try:
        tz = ZoneInfo(tz_name or DEFAULT_TZ)
    except ZoneInfoNotFoundError:
        log.warning(f"Unknown timezone {tz_name!r}, falling back to {DEFAULT_TZ}")
        tz = ZoneInfo(DEFAULT_TZ)
    return now_utc.astimezone(tz).strftime("%H:%M")


def main():
    now = datetime.now(timezone.utc)
    today_iso = now.strftime("%Y-%m-%d")

    # 1. Find opted-in firms with their timezones via PostgREST embedded
    #    select. We can't filter morning_briefing_time server-side because
    #    PostgREST's `like` operator doesn't apply to TIME columns (returns
    #    404). Pull all opted-in rows (small set — there's a hard ceiling
    #    on how many firms opt in at any given minute) and filter the
    #    HH:MM match per-firm in Python after timezone conversion.
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_preferences",
            headers=SB_HEADERS,
            params={
                "morning_briefing_enabled": "eq.true",
                # `firms(...)` is PostgREST embedded select via the FK
                # from firm_preferences.firm_id -> firms.id. We pull
                # display_name alongside timezone so the alert email (when
                # an SMS fails) can identify the firm by name.
                "select": "firm_id,morning_briefing_time,firms(timezone,display_name)",
            },
            timeout=10,
        )
        r.raise_for_status()
        opted_in = r.json()
    except Exception as e:
        log.error(f"Failed to query firm_preferences: {e}")
        sys.exit(1)

    # For each opted-in firm, compute current HH:MM in its local timezone
    # and compare against the configured morning_briefing_time.
    rows = []
    for row in opted_in:
        configured = (row.get("morning_briefing_time") or "")[:5]
        if not configured:
            continue
        firm_obj = row.get("firms") or {}
        tz_name = firm_obj.get("timezone") or DEFAULT_TZ
        if _firm_local_hhmm(now, tz_name) == configured:
            rows.append({**row, "_resolved_tz": tz_name})

    if not rows:
        # Quiet tick. Most minutes have no match; logging every minute would
        # flood the journal with 1440 lines/day per firm-time-bucket.
        return

    log.info(
        f"Tick {now.strftime('%H:%M')} UTC: {len(rows)} of {len(opted_in)} opted-in firm(s) match local time"
    )

    for row in rows:
        firm_id = row["firm_id"]
        tz_name = row.get("_resolved_tz") or DEFAULT_TZ
        try:
            # 2. Idempotency check
            er = requests.get(
                f"{SUPABASE_URL}/rest/v1/morning_briefings",
                headers=SB_HEADERS,
                params={
                    "firm_id":       f"eq.{firm_id}",
                    "briefing_date": f"eq.{today_iso}",
                    "select": "id,sent_sms",
                    "limit": "1",
                },
                timeout=10,
            )
            er.raise_for_status()
            existing = er.json()
            if existing:
                log.info(
                    f"Firm {firm_id[:8]} ({tz_name}): briefing for {today_iso} already exists "
                    f"(sent_sms={existing[0].get('sent_sms')}) — skipping"
                )
                continue

            # 3. Kick off generation. The plugin endpoint runs Hazel agent
            #    + persists row + sends SMS. We give it a generous timeout
            #    because Hazel turns can take 30-60s for a portfolio briefing.
            pr = requests.post(
                f"{PLUGIN_URL}/hazel/internal/generate-briefing",
                json={"firm_id": firm_id},
                timeout=180,
            )
            pr.raise_for_status()
            result = pr.json()
            log.info(
                f"Firm {firm_id[:8]} ({tz_name}): generated. "
                f"briefing_id={(result.get('briefing_id') or '')[:8]} "
                f"sent_sms={result.get('sent_sms')} "
                f"generated={result.get('generated')} "
                f"reason={result.get('reason')}"
            )

            # 4. Alert on silent SMS failure. We only fire when the plugin
            #    ACTUALLY tried to send (generated=true) and Telnyx came
            #    back unhappy (sent_sms=false). Idempotency-skip cases
            #    (generated=false) don't trigger the alert because there
            #    was no send attempt to fail. No deduplication needed —
            #    the scheduler can only reach this branch once per firm
            #    per UTC day (the morning_briefings idempotency check at
            #    step 2 blocks any second attempt).
            if result.get("generated") and not result.get("sent_sms"):
                firm_obj = row.get("firms") or {}
                firm_name = firm_obj.get("display_name") or "Unknown firm"
                _send_briefing_failure_alert(
                    firm_id=firm_id,
                    firm_name=firm_name,
                    briefing_id=result.get("briefing_id") or "",
                    today_iso=today_iso,
                )
        except Exception as e:
            log.error(f"Firm {firm_id[:8]} ({tz_name}): error - {e}")
            # Continue to the next firm; one bad firm shouldn't fail the tick.


if __name__ == "__main__":
    main()

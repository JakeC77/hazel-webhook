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

Time handling: morning_briefing_time is stored as Postgres TIME (HH:MM:SS).
The Settings UI saves whatever the user picked in the <input type="time">,
which is the BUILDER'S LOCAL TIME. We compare against UTC now. v1 known-
issue: a builder in Pacific Time picking 7:00 AM gets a briefing at 7:00
UTC = 11pm PT the night before. Timezone-aware scheduling is a follow-up
(would need a per-firm timezone column).

Logging is intentionally quiet on idle ticks — there's a tick every minute,
and at any given minute most firms won't match. We only log when there's
work to do or an error occurs.
"""

import os
import sys
import logging
import requests
from datetime import datetime, timezone

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

if not SUPABASE_KEY:
    log.error("Missing SUPABASE_SERVICE_KEY in environment")
    sys.exit(1)

SB_HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
}


def main():
    now = datetime.now(timezone.utc)
    current_hhmm = now.strftime("%H:%M")
    today_iso = now.strftime("%Y-%m-%d")

    # 1. Find opted-in firms. We can't filter on morning_briefing_time
    #    server-side because PostgREST's `like` operator doesn't apply to
    #    TIME columns (404). Pull all opted-in firms (small set — there's
    #    a hard ceiling on how many firms opt in at any given moment) and
    #    filter the HH:MM match in Python.
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/firm_preferences",
            headers=SB_HEADERS,
            params={
                "morning_briefing_enabled": "eq.true",
                "select": "firm_id,morning_briefing_time",
            },
            timeout=10,
        )
        r.raise_for_status()
        opted_in = r.json()
    except Exception as e:
        log.error(f"Failed to query firm_preferences: {e}")
        sys.exit(1)

    # Filter by HH:MM. morning_briefing_time comes back as "HH:MM:SS"
    # (Postgres TIME default representation). Compare the first 5 chars.
    rows = [
        row for row in opted_in
        if (row.get("morning_briefing_time") or "")[:5] == current_hhmm
    ]

    if not rows:
        # Quiet tick. Most minutes have no match; logging every minute would
        # flood the journal with 1440 lines/day per firm-time-bucket.
        return

    log.info(
        f"Tick {current_hhmm} UTC: {len(rows)} of {len(opted_in)} opted-in firm(s) match"
    )

    for row in rows:
        firm_id = row["firm_id"]
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
                    f"Firm {firm_id[:8]}: briefing for {today_iso} already exists "
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
                f"Firm {firm_id[:8]}: generated. "
                f"briefing_id={(result.get('briefing_id') or '')[:8]} "
                f"sent_sms={result.get('sent_sms')} "
                f"generated={result.get('generated')} "
                f"reason={result.get('reason')}"
            )
        except Exception as e:
            log.error(f"Firm {firm_id[:8]}: error - {e}")
            # Continue to the next firm; one bad firm shouldn't fail the tick.


if __name__ == "__main__":
    main()

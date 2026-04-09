#!/usr/bin/env python3
"""
deprovision_firm.py — Remove a Hazel agent instance for a firm.

This script reverses what provision_firm.py created:
  1. Removes the agent from openclaw.json
  2. Optionally archives (or deletes) the agent workspace
  3. Removes the agent auth/sessions directory
  4. Optionally releases the ClawdTalk phone number
  5. Optionally marks the firm as inactive in Supabase (does NOT delete data)
  6. Restarts OpenClaw

Usage:
  python3 deprovision_firm.py --firm-id <uuid> [--delete-workspace] [--release-phone] [--dry-run]

Safety:
  - Supabase data (projects, messages, files, queue items) is NEVER deleted.
    The firm row is marked inactive, not removed.
  - Workspace is archived by default (moved to .archived/), not deleted.
  - Pass --delete-workspace to permanently remove workspace files.
  - Pass --release-phone to release the ClawdTalk number back to the pool.
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Configuration ─────────────────────────────────────────────────────────────

OPENCLAW_HOME = Path(os.getenv("OPENCLAW_HOME", "/home/openclaw/.openclaw"))
OPENCLAW_CONFIG = OPENCLAW_HOME / "openclaw.json"
WORKSPACE_BASE = OPENCLAW_HOME / "workspace" / "hazel" / "builders"
AGENTS_BASE = OPENCLAW_HOME / "agents"
ARCHIVE_BASE = OPENCLAW_HOME / "workspace" / "hazel" / ".archived"

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://zrolyrtaaaiauigrvusl.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
SB_HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
}


def load_env(path):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                os.environ.setdefault(key.strip(), val.strip())


def find_agent_for_firm(firm_id):
    """Look up the agent_id for a firm from openclaw.json or Supabase."""
    # Try Supabase first
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers=SB_HEADERS,
        params={"id": f"eq.{firm_id}", "select": "agent_id,display_name", "limit": "1"},
        timeout=5,
    )
    if r.ok and r.json():
        row = r.json()[0]
        agent_id = row.get("agent_id")
        display_name = row.get("display_name", "")
        if agent_id:
            return agent_id, display_name

    # Fall back to scanning openclaw.json
    with open(OPENCLAW_CONFIG) as f:
        config = json.load(f)
    for a in config.get("agents", {}).get("list", []):
        aid = a.get("id", "")
        if aid.startswith("hazel-"):
            # Check if workspace contains this firm_id
            ws = Path(a.get("workspace", ""))
            user_md = ws / "USER.md"
            if user_md.exists() and firm_id in user_md.read_text():
                return aid, ""

    return None, ""


# ── Step 1: Remove from openclaw.json ─────────────────────────────────────────

def unregister_agent(agent_id, dry_run=False):
    """Remove the agent from openclaw.json."""
    with open(OPENCLAW_CONFIG) as f:
        config = json.load(f)

    agents = config.get("agents", {}).get("list", [])
    original_count = len(agents)
    config["agents"]["list"] = [a for a in agents if a.get("id") != agent_id]

    if len(config["agents"]["list"]) == original_count:
        print(f"  Agent {agent_id} not found in openclaw.json")
        return

    if dry_run:
        print(f"  [DRY RUN] Would remove agent {agent_id} from openclaw.json")
        return

    shutil.copy(OPENCLAW_CONFIG, str(OPENCLAW_CONFIG) + ".bak")
    with open(OPENCLAW_CONFIG, "w") as f:
        json.dump(config, f, indent=2)
    print(f"  Removed agent {agent_id} from openclaw.json")


# ── Step 2: Archive or delete workspace ───────────────────────────────────────

def archive_workspace(agent_id, delete=False, dry_run=False):
    """Archive or delete the agent's workspace."""
    slug = agent_id.replace("hazel-", "")
    workspace = WORKSPACE_BASE / slug

    if not workspace.exists():
        print(f"  Workspace not found: {workspace}")
        return

    if delete:
        if dry_run:
            print(f"  [DRY RUN] Would DELETE workspace: {workspace}")
        else:
            shutil.rmtree(workspace)
            print(f"  Deleted workspace: {workspace}")
    else:
        ARCHIVE_BASE.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        archive_dest = ARCHIVE_BASE / f"{slug}-{timestamp}"
        if dry_run:
            print(f"  [DRY RUN] Would archive workspace: {workspace} → {archive_dest}")
        else:
            shutil.move(str(workspace), str(archive_dest))
            print(f"  Archived workspace: {workspace} → {archive_dest}")


# ── Step 3: Remove agent auth/sessions directory ─────────────────────────────

def remove_agent_dir(agent_id, dry_run=False):
    """Remove the agent's auth and sessions directory."""
    agent_dir = AGENTS_BASE / agent_id

    if not agent_dir.exists():
        print(f"  Agent directory not found: {agent_dir}")
        return

    if dry_run:
        print(f"  [DRY RUN] Would remove agent directory: {agent_dir}")
    else:
        shutil.rmtree(agent_dir)
        print(f"  Removed agent directory: {agent_dir}")


# ── Step 4: Remove Docker sandbox container ───────────────────────────────────

def remove_sandbox(agent_id, dry_run=False):
    """Remove the agent's sandbox container if it exists."""
    import subprocess
    container_name = f"openclaw-sbx-agent-{agent_id}"
    # Find containers matching this agent
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
        capture_output=True, text=True,
    )
    containers = [c.strip() for c in result.stdout.strip().split("\n") if c.strip()]

    if not containers:
        print(f"  No sandbox containers found for {agent_id}")
        return

    for c in containers:
        if dry_run:
            print(f"  [DRY RUN] Would remove container: {c}")
        else:
            subprocess.run(["docker", "rm", "-f", c], capture_output=True)
            print(f"  Removed container: {c}")


# ── Step 5: Mark firm inactive in Supabase ────────────────────────────────────

def deactivate_firm(firm_id, dry_run=False):
    """Mark the firm as inactive. Does NOT delete any data."""
    if dry_run:
        print(f"  [DRY RUN] Would mark firm {firm_id} as inactive")
        return

    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers=SB_HEADERS,
        params={"id": f"eq.{firm_id}"},
        json={"agent_id": None, "deactivated_at": datetime.now(timezone.utc).isoformat()},
        timeout=5,
    )
    if r.ok:
        print(f"  Marked firm {firm_id} as inactive")
    else:
        print(f"  WARNING: Failed to update firm: {r.status_code}")


# ── Step 6: Restart OpenClaw ──────────────────────────────────────────────────

def restart_openclaw(dry_run=False):
    if dry_run:
        print("  [DRY RUN] Would restart OpenClaw")
        return
    os.system("systemctl restart openclaw")
    print("  OpenClaw restarted")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Deprovision a Hazel agent for a firm")
    parser.add_argument("--firm-id", required=True, help="Firm UUID to deprovision")
    parser.add_argument("--delete-workspace", action="store_true",
                        help="Permanently delete workspace (default: archive)")
    parser.add_argument("--release-phone", action="store_true",
                        help="Release the ClawdTalk phone number")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would happen without doing it")
    args = parser.parse_args()

    load_env("/home/openclaw/hazel-chat-webhook/.env")
    load_env("/home/openclaw/.openclaw/.env")

    global SUPABASE_KEY, SB_HEADERS
    SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", SUPABASE_KEY)
    SB_HEADERS["apikey"] = SUPABASE_KEY
    SB_HEADERS["Authorization"] = f"Bearer {SUPABASE_KEY}"

    firm_id = args.firm_id
    print(f"\nDeprovisioning Hazel for firm: {firm_id}")
    print(f"{'=' * 60}")

    # Resolve agent_id
    agent_id, display_name = find_agent_for_firm(firm_id)
    if not agent_id:
        print(f"\n  ERROR: No agent found for firm {firm_id}")
        sys.exit(1)
    print(f"  Found agent: {agent_id}" + (f" ({display_name})" if display_name else ""))

    print("\n1. Removing from OpenClaw config...")
    unregister_agent(agent_id, args.dry_run)

    print(f"\n2. {'Deleting' if args.delete_workspace else 'Archiving'} workspace...")
    archive_workspace(agent_id, delete=args.delete_workspace, dry_run=args.dry_run)

    print("\n3. Removing agent auth/sessions directory...")
    remove_agent_dir(agent_id, args.dry_run)

    print("\n4. Removing sandbox container...")
    remove_sandbox(agent_id, args.dry_run)

    print("\n5. Marking firm as inactive in Supabase...")
    deactivate_firm(firm_id, args.dry_run)

    if args.release_phone:
        print("\n6. Phone release not yet implemented — do manually in ClawdTalk dashboard")

    print("\n7. Restarting OpenClaw...")
    restart_openclaw(args.dry_run)

    print(f"\n{'=' * 60}")
    print("Deprovisioning complete.")
    print("  Supabase data (projects, messages, files) is preserved.")
    if not args.delete_workspace:
        print(f"  Workspace archived to: {ARCHIVE_BASE}/")
    print("  To fully remove Supabase data, delete the firm row manually.")


if __name__ == "__main__":
    main()

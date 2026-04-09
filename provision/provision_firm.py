#!/usr/bin/env python3
"""
provision_firm.py — Provision a new Hazel agent instance for a firm.

This script:
  1. Creates the firm in Supabase (if not exists)
  2. Creates an OpenClaw agent workspace from the Hazel template
  3. Registers the agent in openclaw.json
  4. Provisions a ClawdTalk phone number (optional)
  5. Creates the Supabase Home project for the firm
  6. Restarts OpenClaw to load the new agent

Usage:
  python3 provision_firm.py \
    --firm-name "Smith Construction" \
    --owner-email "john@smithconstruction.com" \
    --owner-name "John Smith" \
    --timezone "America/New_York" \
    [--provision-phone]    # Also provision a ClawdTalk number
    [--dry-run]            # Show what would happen without doing it

Requires:
  - Root or openclaw user on the OpenClaw host
  - SUPABASE_URL, SUPABASE_SERVICE_KEY in environment or .env
  - ANTHROPIC_API_KEY for the new agent's auth profile
  - CLAWDTALK_API_KEY for phone provisioning (optional)
"""

import argparse
import json
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Configuration ─────────────────────────────────────────────────────────────

OPENCLAW_HOME = Path(os.getenv("OPENCLAW_HOME", "/home/openclaw/.openclaw"))
OPENCLAW_CONFIG = OPENCLAW_HOME / "openclaw.json"
WORKSPACE_BASE = OPENCLAW_HOME / "workspace" / "hazel" / "builders"
AGENTS_BASE = OPENCLAW_HOME / "agents"
TEMPLATE_DIR = Path(__file__).parent / "template"

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://zrolyrtaaaiauigrvusl.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
SB_HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
}

CLAWDTALK_URL = os.getenv("CLAWDTALK_URL", "https://clawdtalk.com")
CLAWDTALK_KEY = os.getenv("CLAWDTALK_API_KEY", "")

HOME_PROJECT_ID = "a0000000-0000-0000-0000-000000000000"


def slugify(name):
    """Convert a firm name to a filesystem-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug


def load_env(path):
    """Load a .env file into os.environ."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                os.environ.setdefault(key.strip(), val.strip())


# ── Step 1: Create Firm in Supabase ───────────────────────────────────────────

def create_firm(firm_name, owner_email, timezone_str, dry_run=False):
    """Create firm and return firm_id. If firm exists by name, return existing."""
    # Check if firm exists
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers=SB_HEADERS,
        params={"display_name": f"eq.{firm_name}", "select": "id", "limit": "1"},
    )
    if r.ok and r.json():
        firm_id = r.json()[0]["id"]
        print(f"  Firm already exists: {firm_id}")
        return firm_id

    firm_id = str(uuid.uuid4())
    if dry_run:
        print(f"  [DRY RUN] Would create firm: {firm_name} ({firm_id})")
        return firm_id

    row = {
        "id": firm_id,
        "display_name": firm_name,
        "timezone": timezone_str,
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/firms",
        headers={**SB_HEADERS, "Prefer": "return=representation"},
        json=row,
    )
    if not r.ok:
        print(f"  ERROR creating firm: {r.status_code} {r.text[:200]}")
        sys.exit(1)
    print(f"  Created firm: {firm_id}")
    return firm_id


def create_home_project(firm_id, dry_run=False):
    """Create the Home project for a firm."""
    home_id = str(uuid.uuid4()).replace(str(uuid.uuid4())[:8], "a0000000", 1)
    # Use a deterministic home project ID per firm
    home_id = f"a0{firm_id[2:8]}00-0000-0000-0000-{firm_id[-12:]}"

    if dry_run:
        print(f"  [DRY RUN] Would create Home project: {home_id}")
        return home_id

    row = {
        "id": home_id,
        "name": "Home",
        "firm_id": firm_id,
        "status": "on-track",
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/projects",
        headers={**SB_HEADERS, "Prefer": "return=representation"},
        json=row,
    )
    if r.ok:
        print(f"  Created Home project: {home_id}")
    elif "duplicate" in r.text.lower() or r.status_code == 409:
        print(f"  Home project already exists")
        home_id = None
    else:
        print(f"  WARNING: Home project creation failed: {r.status_code}")
        home_id = None
    return home_id


# ── Step 2: Create Agent Workspace ────────────────────────────────────────────

def create_workspace(slug, firm_name, owner_name, timezone_str, firm_id, dry_run=False):
    """Create a Hazel workspace from the template."""
    workspace = WORKSPACE_BASE / slug

    if workspace.exists():
        print(f"  Workspace already exists: {workspace}")
        return workspace

    if dry_run:
        print(f"  [DRY RUN] Would create workspace: {workspace}")
        return workspace

    # Copy template (exclude skills — we'll symlink those)
    shutil.copytree(
        TEMPLATE_DIR / "workspace", workspace,
        ignore=shutil.ignore_patterns("skills"),
    )

    # Symlink shared skills directory so all agents use the same scripts
    shared_skills = OPENCLAW_HOME / "workspace" / "hazel" / "shared-skills"
    skills_link = workspace / "skills"
    if shared_skills.exists():
        os.symlink(shared_skills, skills_link)
        print(f"  Symlinked skills → {shared_skills}")
    else:
        # Fall back to copying from the first agent (ridgeline)
        ridgeline_skills = WORKSPACE_BASE / "ridgeline" / "skills"
        if ridgeline_skills.exists():
            shutil.copytree(ridgeline_skills, skills_link)
            print(f"  Copied skills from ridgeline (consider setting up shared-skills)")
        else:
            skills_link.mkdir(parents=True)
            print(f"  WARNING: No skills source found, created empty skills/")

    # Substitute variables in template files
    substitutions = {
        "{{FIRM_NAME}}": firm_name,
        "{{OWNER_NAME}}": owner_name,
        "{{TIMEZONE}}": timezone_str,
        "{{FIRM_ID}}": firm_id,
        "{{SLUG}}": slug,
        "{{SUPABASE_URL}}": SUPABASE_URL,
    }

    for md_file in workspace.rglob("*.md"):
        if md_file.is_symlink():
            continue
        content = md_file.read_text()
        for key, val in substitutions.items():
            content = content.replace(key, val)
        md_file.write_text(content)

    # Also substitute in .env
    env_file = workspace / ".env"
    if env_file.exists():
        content = env_file.read_text()
        for key, val in substitutions.items():
            content = content.replace(key, val)
        env_file.write_text(content)

    print(f"  Created workspace: {workspace}")
    return workspace


def create_agent_dir(slug, anthropic_key, dry_run=False):
    """Create the agent auth directory."""
    agent_id = f"hazel-{slug}"
    agent_dir = AGENTS_BASE / agent_id / "agent"

    if agent_dir.exists():
        print(f"  Agent dir already exists: {agent_dir}")
        return agent_dir

    if dry_run:
        print(f"  [DRY RUN] Would create agent dir: {agent_dir}")
        return agent_dir

    agent_dir.mkdir(parents=True, exist_ok=True)

    # Auth profiles
    auth = {
        "version": 1,
        "profiles": {
            "anthropic:default": {
                "type": "api_key",
                "provider": "anthropic",
                "key": anthropic_key,
            }
        },
        "lastGood": {
            "anthropic": "anthropic:default",
        },
    }
    (agent_dir / "auth-profiles.json").write_text(json.dumps(auth, indent=2))
    (agent_dir / "auth.json").write_text("{}")

    # Sessions directory
    sessions_dir = agent_dir.parent / "sessions"
    sessions_dir.mkdir(exist_ok=True)
    (sessions_dir / "sessions.json").write_text("{}")

    print(f"  Created agent dir: {agent_dir}")
    return agent_dir


# ── Step 3: Register Agent in openclaw.json ───────────────────────────────────

def register_agent(slug, workspace, agent_dir, dry_run=False):
    """Add the agent to openclaw.json."""
    agent_id = f"hazel-{slug}"

    with open(OPENCLAW_CONFIG) as f:
        config = json.load(f)

    # Check if already registered
    for a in config.get("agents", {}).get("list", []):
        if a.get("id") == agent_id:
            print(f"  Agent already registered: {agent_id}")
            return agent_id

    if dry_run:
        print(f"  [DRY RUN] Would register agent: {agent_id}")
        return agent_id

    agent_entry = {
        "id": agent_id,
        "name": agent_id,
        "workspace": str(workspace),
        "agentDir": str(agent_dir),
        "identity": {
            "name": "Hazel",
            "theme": "AI right hand — part assistant, part co-conspirator, part rubber duck with opinions",
            "emoji": "\ud83c\udfd7\ufe0f",
        },
        "sandbox": {
            "mode": "all",
            "workspaceAccess": "rw",
            "docker": {
                "network": "bridge",
                "binds": [],
            },
        },
    }

    config["agents"]["list"].append(agent_entry)

    # Backup and write
    shutil.copy(OPENCLAW_CONFIG, str(OPENCLAW_CONFIG) + ".bak")
    with open(OPENCLAW_CONFIG, "w") as f:
        json.dump(config, f, indent=2)

    print(f"  Registered agent: {agent_id}")
    return agent_id


# ── Step 4: Provision ClawdTalk Phone Number ──────────────────────────────────

def provision_phone(firm_name, dry_run=False):
    """Provision a ClawdTalk phone number for the firm."""
    if not CLAWDTALK_KEY:
        print("  Skipping phone provisioning (no CLAWDTALK_API_KEY)")
        return None

    if dry_run:
        print(f"  [DRY RUN] Would provision ClawdTalk number for {firm_name}")
        return "+1XXXXXXXXXX"

    # List available numbers
    r = requests.get(
        f"{CLAWDTALK_URL}/v1/available-numbers",
        headers={"Authorization": f"Bearer {CLAWDTALK_KEY}"},
        params={"limit": 1},
    )
    if not r.ok:
        print(f"  WARNING: Could not list available numbers: {r.status_code}")
        return None

    numbers = r.json().get("data", [])
    if not numbers:
        print("  WARNING: No available numbers")
        return None

    # Provision the number
    number = numbers[0].get("phone_number")
    r = requests.post(
        f"{CLAWDTALK_URL}/v1/provision",
        headers={
            "Authorization": f"Bearer {CLAWDTALK_KEY}",
            "Content-Type": "application/json",
        },
        json={"phone_number": number, "label": firm_name},
    )
    if r.ok:
        print(f"  Provisioned phone: {number}")
        return number
    else:
        print(f"  WARNING: Phone provisioning failed: {r.status_code}")
        return None


# ── Step 5: Restart OpenClaw ──────────────────────────────────────────────────

def restart_openclaw(dry_run=False):
    """Restart OpenClaw to load the new agent."""
    if dry_run:
        print("  [DRY RUN] Would restart OpenClaw")
        return

    os.system("systemctl restart openclaw")
    print("  OpenClaw restarted")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Provision a new Hazel agent for a firm")
    parser.add_argument("--firm-name", required=True, help="Company name")
    parser.add_argument("--owner-email", required=True, help="Owner's email address")
    parser.add_argument("--owner-name", required=True, help="Owner's name")
    parser.add_argument("--timezone", default="America/New_York", help="Timezone (default: America/New_York)")
    parser.add_argument("--anthropic-key", help="Anthropic API key (or set ANTHROPIC_API_KEY env)")
    parser.add_argument("--provision-phone", action="store_true", help="Also provision a ClawdTalk number")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without doing it")
    args = parser.parse_args()

    # Load .env
    load_env("/home/openclaw/hazel-chat-webhook/.env")
    load_env("/home/openclaw/.openclaw/.env")

    # Reload after .env
    global SUPABASE_KEY, SB_HEADERS, CLAWDTALK_KEY
    SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", SUPABASE_KEY)
    SB_HEADERS["apikey"] = SUPABASE_KEY
    SB_HEADERS["Authorization"] = f"Bearer {SUPABASE_KEY}"
    CLAWDTALK_KEY = os.getenv("CLAWDTALK_API_KEY", CLAWDTALK_KEY)

    anthropic_key = args.anthropic_key or os.getenv("ANTHROPIC_API_KEY", "")
    if not anthropic_key and not args.dry_run:
        print("ERROR: --anthropic-key or ANTHROPIC_API_KEY required")
        sys.exit(1)

    slug = slugify(args.firm_name)
    print(f"\nProvisioning Hazel for: {args.firm_name} (slug: {slug})")
    print(f"{'=' * 60}")

    # Step 1: Supabase
    print("\n1. Creating firm in Supabase...")
    firm_id = create_firm(args.firm_name, args.owner_email, args.timezone, args.dry_run)

    print("\n   Creating Home project...")
    create_home_project(firm_id, args.dry_run)

    # Step 2: Workspace
    print("\n2. Creating agent workspace...")
    workspace = create_workspace(slug, args.firm_name, args.owner_name, args.timezone, firm_id, args.dry_run)

    print("\n   Creating agent auth directory...")
    agent_dir = create_agent_dir(slug, anthropic_key, args.dry_run)

    # Step 3: Register
    print("\n3. Registering agent in OpenClaw...")
    agent_id = register_agent(slug, workspace, agent_dir, args.dry_run)

    # Step 4: Phone (optional)
    phone = None
    if args.provision_phone:
        print("\n4. Provisioning ClawdTalk number...")
        phone = provision_phone(args.firm_name, args.dry_run)

    # Step 5: Restart
    print("\n5. Restarting OpenClaw...")
    restart_openclaw(args.dry_run)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Provisioning complete!")
    print(f"  Firm:      {args.firm_name} ({firm_id})")
    print(f"  Agent:     {agent_id}")
    print(f"  Workspace: {workspace}")
    print(f"  Phone:     {phone or 'not provisioned'}")
    print(f"\nNext steps:")
    print(f"  1. Owner signs up on dashboard with {args.owner_email}")
    print(f"  2. Connect Gmail in Settings")
    print(f"  3. Set preferences and add contacts")
    if not phone:
        print(f"  4. Manually assign ClawdTalk number to agent {agent_id}")


if __name__ == "__main__":
    main()

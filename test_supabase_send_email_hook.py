"""
Local sanity test for /webhook/supabase-send-email.

Runs the Flask app with a mocked AgentMail backend + a fixed hook secret,
then fires a signed request at the endpoint and a few rejection cases.
"""
import base64, hmac, hashlib, json, os, secrets, time
from unittest.mock import patch

os.environ["SUPABASE_SEND_EMAIL_HOOK_SECRET"] = "v1,whsec_" + base64.b64encode(b"unit-test-secret-bytes-not-real").decode()
os.environ["AGENTMAIL_KEY"] = "test-agentmail-key"
os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "svc")
os.environ.setdefault("HAZEL_WEBHOOK_SECRET", "x")

import server  # noqa: E402

SECRET = os.environ["SUPABASE_SEND_EMAIL_HOOK_SECRET"]


def sign(body_bytes, wh_id=None, wh_ts=None):
    wh_id = wh_id or "msg_" + secrets.token_hex(8)
    wh_ts = wh_ts or str(int(time.time()))
    key = server._decode_hook_secret(SECRET)
    signed = f"{wh_id}.{wh_ts}.".encode() + body_bytes
    sig = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return {
        "webhook-id": wh_id,
        "webhook-timestamp": wh_ts,
        "webhook-signature": f"v1,{sig}",
        "Content-Type": "application/json",
    }


def make_payload(action="signup", email="user@example.com"):
    return {
        "user": {"id": "uid-1", "email": email},
        "email_data": {
            "token": "123456",
            "token_hash": "hash_abc",
            "redirect_to": "https://hazel.haventechsolutions.com/",
            "email_action_type": action,
            "site_url": "https://hazel.haventechsolutions.com",
        },
    }


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.ok = 200 <= status < 300
        self.text = text


def run():
    client = server.app.test_client()

    # 1. happy path
    sent = {}
    def fake_post(url, headers=None, json=None, timeout=None):
        sent["url"] = url
        sent["headers"] = headers
        sent["json"] = json
        return FakeResp(200)

    payload = make_payload("signup")
    body = json.dumps(payload).encode()
    with patch("server.requests.post", side_effect=fake_post):
        r = client.post("/webhook/supabase-send-email", data=body, headers=sign(body))
    assert r.status_code == 200, r.data
    assert sent["json"]["to"] == ["user@example.com"]
    assert "Confirm your email" in sent["json"]["subject"]
    assert "token=hash_abc" in sent["json"]["text"]
    assert sent["url"].endswith("/messages/send")
    print("[OK] happy path: signup email sent")

    # 2. each action type renders
    actions = ["signup", "invite", "magiclink", "recovery", "email_change", "reauthentication"]
    for a in actions:
        p = make_payload(a)
        b = json.dumps(p).encode()
        with patch("server.requests.post", side_effect=fake_post):
            r = client.post("/webhook/supabase-send-email", data=b, headers=sign(b))
        assert r.status_code == 200, (a, r.data)
        if a == "reauthentication":
            assert "Your code: 123456" in sent["json"]["text"]
        else:
            assert "token=hash_abc" in sent["json"]["text"]
    print(f"[OK] all action types render: {actions}")

    # 3. bad signature
    b = json.dumps(payload).encode()
    h = sign(b)
    h["webhook-signature"] = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    r = client.post("/webhook/supabase-send-email", data=b, headers=h)
    assert r.status_code == 401, r.data
    print("[OK] bad signature → 401")

    # 4. stale timestamp (> 5 min)
    old_ts = str(int(time.time()) - 3600)
    h = sign(b, wh_ts=old_ts)
    r = client.post("/webhook/supabase-send-email", data=b, headers=h)
    assert r.status_code == 401, r.data
    print("[OK] stale timestamp → 401")

    # 5. missing signature headers
    r = client.post("/webhook/supabase-send-email", data=b,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 401, r.data
    print("[OK] missing headers → 401")

    # 6. invalid JSON with valid sig
    bad = b"not json{"
    r = client.post("/webhook/supabase-send-email", data=bad, headers=sign(bad))
    assert r.status_code == 400, r.data
    print("[OK] invalid JSON → 400")

    # 7. AgentMail failure surfaces 502
    def fail_post(*a, **k):
        return FakeResp(500, "upstream boom")
    with patch("server.requests.post", side_effect=fail_post):
        r = client.post("/webhook/supabase-send-email", data=body, headers=sign(body))
    assert r.status_code == 502, r.data
    print("[OK] AgentMail 5xx → 502")

    print("\nAll tests passed.")


if __name__ == "__main__":
    run()

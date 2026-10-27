import time
import pytest
from app.crypto_utils import create_session_token

def test_missing_auth_header(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 401

    res = client.get("/api/requests/pending")
    assert res.status_code == 401

    res = client.get("/api/messages/offline")
    assert res.status_code == 401

def test_forged_token_rejected(client):
    valid_token = create_session_token("alice", "0" * 64)
    # Alter payload part
    payload_part, sig_part = valid_token.split(".")
    forged_token = f"eyJzdWIiOiJhZG1pbiJ9.{sig_part}"
    
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged_token}"})
    assert res.status_code == 401

def test_challenge_replay_attack_rejected(client, keypair_factory):
    keys = keypair_factory()
    now = int(time.time())
    
    # Register user Dave
    msg = f"register:dave:{now}".encode("utf-8")
    sig = keys["sign_key"].sign(msg).signature.hex()
    client.post("/api/auth/register", json={
        "username": "dave",
        "identityPublicKey": keys["identity_pub"],
        "preKey": keys["box_pub"],
        "signature": sig,
        "timestamp": now
    })
    
    # Get challenge
    res = client.get("/api/auth/challenge?username=dave")
    nonce = res.json()["nonce"]
    sig_nonce = keys["sign_key"].sign(nonce.encode("utf-8")).signature.hex()
    
    # First verify succeeds
    res1 = client.post("/api/auth/verify", json={
        "username": "dave",
        "nonce": nonce,
        "signature": sig_nonce
    })
    assert res1.status_code == 200
    
    # Replay same challenge again -> must be rejected (single-use nonce)
    res2 = client.post("/api/auth/verify", json={
        "username": "dave",
        "nonce": nonce,
        "signature": sig_nonce
    })
    assert res2.status_code == 400
    assert "expired" in res2.json()["detail"].lower()

def test_isolated_offline_messages(client, keypair_factory):
    """User B cannot access offline messages addressed to User A."""
    token_alice = create_session_token("alice", "0" * 64)
    token_bob = create_session_token("bob", "0" * 64)
    
    # Directly query offline messages as bob
    res = client.get("/api/messages/offline", headers={"Authorization": f"Bearer {token_bob}"})
    assert res.status_code == 200
    # Bob must receive an empty list or only messages addressed to Bob
    for msg in res.json():
        assert msg["to"] == "bob"

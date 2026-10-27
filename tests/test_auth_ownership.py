import time
import pytest
import nacl.signing

def test_register_and_proof_of_ownership(client, keypair_factory):
    alice_keys = keypair_factory()
    now = int(time.time())
    
    # Sign register:alice:<timestamp>
    msg = f"register:alice:{now}".encode("utf-8")
    sig = alice_keys["sign_key"].sign(msg).signature.hex()
    
    res = client.post("/api/auth/register", json={
        "username": "alice",
        "identityPublicKey": alice_keys["identity_pub"],
        "preKey": alice_keys["box_pub"],
        "signature": sig,
        "timestamp": now
    })
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["success"] is True
    assert data["username"] == "alice"
    assert "token" in data

def test_duplicate_username_rejected(client, keypair_factory):
    bob_keys = keypair_factory()
    now = int(time.time())
    
    # Try to register 'alice' with Bob's keys
    msg = f"register:alice:{now}".encode("utf-8")
    sig = bob_keys["sign_key"].sign(msg).signature.hex()
    
    res = client.post("/api/auth/register", json={
        "username": "alice",
        "identityPublicKey": bob_keys["identity_pub"],
        "preKey": bob_keys["box_pub"],
        "signature": sig,
        "timestamp": now
    })
    # Must fail with 409 Conflict
    assert res.status_code == 409
    assert "already claimed" in res.json()["detail"].lower()

def test_reconnect_challenge_response_authentication(client, keypair_factory):
    # Alice reconnects: requests challenge and signs it
    res = client.get("/api/auth/challenge?username=alice")
    assert res.status_code == 200
    nonce = res.json()["nonce"]
    
    # Look up registered Alice keys from test 1
    # Retrieve challenge and sign with Alice's registered key
    # Let's register a dedicated user 'carol'
    carol_keys = keypair_factory()
    now = int(time.time())
    msg = f"register:carol:{now}".encode("utf-8")
    sig = carol_keys["sign_key"].sign(msg).signature.hex()
    res = client.post("/api/auth/register", json={
        "username": "carol",
        "identityPublicKey": carol_keys["identity_pub"],
        "preKey": carol_keys["box_pub"],
        "signature": sig,
        "timestamp": now
    })
    assert res.status_code == 200
    
    # Carol asks for challenge
    res = client.get("/api/auth/challenge?username=carol")
    nonce = res.json()["nonce"]
    
    # Carol signs nonce with her secret key
    sig_challenge = carol_keys["sign_key"].sign(nonce.encode("utf-8")).signature.hex()
    
    # Verify challenge
    res = client.post("/api/auth/verify", json={
        "username": "carol",
        "nonce": nonce,
        "signature": sig_challenge
    })
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert "token" in res.json()

def test_impersonator_cannot_claim_username_without_private_key(client, keypair_factory):
    """Crucial requirement: Never allow someone to claim an existing username simply by typing it."""
    # Attacker types 'carol' and attempts to authenticate using attacker's own private key
    attacker_keys = keypair_factory()
    
    res = client.get("/api/auth/challenge?username=carol")
    nonce = res.json()["nonce"]
    
    attacker_sig = attacker_keys["sign_key"].sign(nonce.encode("utf-8")).signature.hex()
    
    res = client.post("/api/auth/verify", json={
        "username": "carol",
        "nonce": nonce,
        "signature": attacker_sig
    })
    # Must fail with 401 Unauthorized
    assert res.status_code == 401
    assert "proof of ownership failed" in res.json()["detail"].lower()

def test_invalid_username_format_rejected(client, keypair_factory):
    keys = keypair_factory()
    now = int(time.time())
    
    invalid_usernames = ["a", "ab", "user!name", "space in name", "a" * 25]
    for bad_name in invalid_usernames:
        msg = f"register:{bad_name}:{now}".encode("utf-8")
        sig = keys["sign_key"].sign(msg).signature.hex()
        res = client.post("/api/auth/register", json={
            "username": bad_name,
            "identityPublicKey": keys["identity_pub"],
            "preKey": keys["box_pub"],
            "signature": sig,
            "timestamp": now
        })
        assert res.status_code in (400, 422)

import time
import pytest
from app.crypto_utils import create_session_token

def test_chat_requests_lifecycle_and_acceptance(client, keypair_factory):
    keys_user1 = keypair_factory()
    keys_user2 = keypair_factory()
    now = int(time.time())
    
    # 1. Register user_one
    msg1 = f"register:user_one:{now}".encode("utf-8")
    sig1 = keys_user1["sign_key"].sign(msg1).signature.hex()
    res1 = client.post("/api/auth/register", json={
        "username": "user_one",
        "identityPublicKey": keys_user1["identity_pub"],
        "preKey": keys_user1["box_pub"],
        "signature": sig1,
        "timestamp": now
    })
    token1 = res1.json()["token"]
    
    # 2. Register user_two
    msg2 = f"register:user_two:{now}".encode("utf-8")
    sig2 = keys_user2["sign_key"].sign(msg2).signature.hex()
    res2 = client.post("/api/auth/register", json={
        "username": "user_two",
        "identityPublicKey": keys_user2["identity_pub"],
        "preKey": keys_user2["box_pub"],
        "signature": sig2,
        "timestamp": now
    })
    token2 = res2.json()["token"]
    
    # 3. User One attempts to send message to User Two BEFORE acceptance
    # Requirement: "Messaging starts only after the recipient accepts."
    res_premature = client.post("/api/messages/send", headers={"Authorization": f"Bearer {token1}"}, json={
        "messageId": "msg_premature_123456",
        "toUsername": "user_two",
        "ciphertext": "aabbccdd",
        "header": {"ivHex": "11223344", "counter": 0}
    })
    assert res_premature.status_code == 403
    assert "accepted contact request" in res_premature.json()["detail"].lower()
    
    # 4. User One sends chat request to User Two
    res_req = client.post("/api/requests/send", headers={"Authorization": f"Bearer {token1}"}, json={
        "toUsername": "user_two",
        "encryptedIntro": "Hey user_two, let's chat securely!"
    })
    assert res_req.status_code == 200
    request_id = res_req.json()["requestId"]
    
    # 5. User Two views pending requests
    res_pending = client.get("/api/requests/pending", headers={"Authorization": f"Bearer {token2}"})
    assert res_pending.status_code == 200
    pending_list = res_pending.json()
    assert any(r["id"] == request_id for r in pending_list)
    
    # 6. User Two accepts request
    res_accept = client.post("/api/requests/respond", headers={"Authorization": f"Bearer {token2}"}, json={
        "requestId": request_id,
        "action": "accept"
    })
    assert res_accept.status_code == 200
    
    # 7. Check contacts list for both users
    contacts_1 = client.get("/api/requests/contacts", headers={"Authorization": f"Bearer {token1}"}).json()
    assert any(c["username"] == "user_two" for c in contacts_1)
    
    contacts_2 = client.get("/api/requests/contacts", headers={"Authorization": f"Bearer {token2}"}).json()
    assert any(c["username"] == "user_one" for c in contacts_2)
    
    # 8. User One can now successfully send encrypted message!
    res_msg = client.post("/api/messages/send", headers={"Authorization": f"Bearer {token1}"}, json={
        "messageId": "msg_valid_after_accept_123",
        "toUsername": "user_two",
        "ciphertext": "deadbeef12345678",
        "header": {"ivHex": "aabbccddee", "counter": 0}
    })
    assert res_msg.status_code == 200
    assert res_msg.json()["status"] in ["delivered_server", "delivered_device"]
    
    # 9. User Two blocks User One
    res_block = client.post("/api/requests/block", headers={"Authorization": f"Bearer {token2}"}, json={
        "targetUsername": "user_one"
    })
    assert res_block.status_code == 200
    
    # 10. Message from blocked user is not delivered
    res_blocked_msg = client.post("/api/messages/send", headers={"Authorization": f"Bearer {token1}"}, json={
        "messageId": "msg_blocked_attempt_456",
        "toUsername": "user_two",
        "ciphertext": "0011223344",
        "header": {"ivHex": "112233", "counter": 1}
    })
    assert res_blocked_msg.json()["status"] == "blocked"

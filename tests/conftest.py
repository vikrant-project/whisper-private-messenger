import os
import pytest
from starlette.testclient import TestClient
import nacl.signing
import nacl.public

# Override DATABASE_PATH to use isolated test DB
TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "test_whisper.db")
os.environ["DATABASE_PATH"] = TEST_DB_PATH

import app.config
app.config.DATABASE_PATH = TEST_DB_PATH

from app.database import init_db, get_connection
from app.main import app

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass
    init_db()
    yield
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def keypair_factory():
    def create_user_keys():
        signing_key = nacl.signing.SigningKey.generate()
        verify_key = signing_key.verify_key
        box_key = nacl.public.PrivateKey.generate()
        return {
            "sign_key": signing_key,
            "verify_key": verify_key,
            "identity_pub": verify_key.encode().hex(),
            "identity_sec": signing_key.encode().hex() + verify_key.encode().hex(),
            "box_sec": box_key.encode().hex(),
            "box_pub": box_key.public_key.encode().hex()
        }
    return create_user_keys

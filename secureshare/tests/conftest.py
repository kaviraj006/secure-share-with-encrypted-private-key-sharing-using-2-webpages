import sys
from pathlib import Path
import shutil
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.config import TestConfig
from app.extensions import db

@pytest.fixture
def app():
    app = create_app(TestConfig)
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()
        
    # Clean up test storage directory
    test_storage = app.config["CIPHERTEXT_STORAGE_DIR"]
    if test_storage.exists():
        shutil.rmtree(test_storage, ignore_errors=True)

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

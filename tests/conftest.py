import os
import tempfile

os.environ["REDTEAM_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["LLM_BACKEND"] = "mock"

from app import db  # noqa: E402

db.init()

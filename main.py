import os
import time
import hashlib
import secrets
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RegisterRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class GoogleAuthRequest(BaseModel):
    id_token: str


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _find_user_by_email(email: str) -> Optional[dict]:
    users = get_documents("authuser", {"email": _normalize_email(email)}, limit=1)
    return users[0] if users else None


def _find_user_by_id(user_id: str) -> Optional[dict]:
    users = get_documents("authuser", {"_id": user_id}, limit=1)
    return users[0] if users else None


def _create_token(user_id: str, ttl_seconds: int = 60 * 60 * 24) -> dict:
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + ttl_seconds
    doc = {"user_id": user_id, "token": token, "expires_at": expires_at}
    created = create_document("authtoken", doc)
    return {"token": token, "expires_at": expires_at, "_id": created.get("_id")}


def _validate_token(token: str) -> Optional[dict]:
    toks = get_documents("authtoken", {"token": token}, limit=1)
    if not toks:
        return None
    tok = toks[0]
    if int(time.time()) > int(tok.get("expires_at", 0)):
        return None
    return tok


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        # Try to import database module
        from database import db as _db

        if _db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = _db.name if hasattr(_db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            # Try to list collections to verify connectivity
            try:
                collections = _db.list_collection_names()
                response["collections"] = collections[:10]  # Show first 10 collections
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except ImportError:
        response["database"] = "❌ Database module not found (run enable-database first)"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    # Check environment variables
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


@app.post("/auth/register")
def register(req: RegisterRequest):
    email = _normalize_email(req.email)
    existing = _find_user_by_email(email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(req.password, salt)
    user_doc = {
        "email": email,
        "name": req.name or "",
        "password_hash": pw_hash,
        "salt": salt,
        "is_active": True,
        "auth_provider": "password",
    }
    created = create_document("authuser", user_doc)
    token = _create_token(created.get("_id"))
    return {
        "user": {"id": created.get("_id"), "email": created.get("email"), "name": created.get("name")},
        "token": token["token"],
        "expires_at": token["expires_at"],
    }


@app.post("/auth/login")
def login(req: LoginRequest):
    email = _normalize_email(req.email)
    user = _find_user_by_email(email)
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expected = _hash_password(req.password, user.get("salt", ""))
    if expected != user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = _create_token(user.get("_id"))
    return {
        "user": {"id": user.get("_id"), "email": user.get("email"), "name": user.get("name")},
        "token": token["token"],
        "expires_at": token["expires_at"],
    }


@app.post("/auth/google")
async def auth_google(req: GoogleAuthRequest):
    # Verify the Google ID token using Google's tokeninfo endpoint
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": req.id_token},
            )
            if r.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid Google token")
            info = r.json()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    email = _normalize_email(info.get("email", ""))
    if not email:
        raise HTTPException(status_code=400, detail="Google account email not available")

    name = info.get("name") or info.get("given_name") or ""

    user = _find_user_by_email(email)
    if not user:
        # Create a new user without password
        user_doc = {
            "email": email,
            "name": name,
            "password_hash": "",
            "salt": "",
            "is_active": True,
            "auth_provider": "google",
        }
        created = create_document("authuser", user_doc)
        user_id = created.get("_id")
        profile = {"id": user_id, "email": email, "name": name}
    else:
        user_id = user.get("_id")
        profile = {"id": user_id, "email": user.get("email"), "name": user.get("name")}

    token = _create_token(user_id)
    return {"user": profile, "token": token["token"], "expires_at": token["expires_at"]}


@app.get("/auth/me")
def me(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    tok = _validate_token(token)
    if not tok:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = _find_user_by_id(tok.get("user_id"))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.get("_id"), "email": user.get("email"), "name": user.get("name")}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

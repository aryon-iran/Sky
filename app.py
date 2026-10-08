# ==========================================
#   Sky Messenger - نسخه ساده MVP
#   Backend: Python + FastAPI + SQLite
# ==========================================

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from passlib.hash import bcrypt
import sqlite3
import secrets
from datetime import datetime

# ---------- تنظیمات اولیه ----------
app = FastAPI(title="Sky Messenger")
templates = Jinja2Templates(directory="templates")

DB_PATH = "sky.db"
TOKENS = {}  # توکن -> user_id  (ساده، بدون JWT)

# ---------- دیتابیس ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- مدلها ----------
class AuthData(BaseModel):
    username: str
    password: str

class MessageData(BaseModel):
    token: str
    receiver_id: int
    content: str

# ---------- ابزار ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def user_from_token(token: str):
    user_id = TOKENS.get(token)
    if not user_id:
        return None
    conn = get_db()
    user = conn.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

# ---------- صفحات ----------
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

# ---------- API احراز هویت ----------
@app.post("/api/register")
async def register(data: AuthData):
    username = data.username.strip().lower()
    if len(username) < 3:
        raise HTTPException(400, "یوزرنیم حداقل ۳ کاراکتر باشه")
    if len(data.password) < 4:
        raise HTTPException(400, "پسورد حداقل ۴ کاراکتر باشه")

    conn = get_db()
    exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if exists:
        conn.close()
        raise HTTPException(400, "این یوزرنیم قبلاً گرفته شده")

    hashed = bcrypt.hash(data.password)
    conn.execute(
        "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
        (username, hashed, datetime.now().isoformat())
    )
    conn.commit()
    user = conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    token = secrets.token_urlsafe(32)
    TOKENS[token] = user["id"]
    return {"token": token, "user": dict(user)}


@app.post("/api/login")
async def login(data: AuthData):
    username = data.username.strip().lower()
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not user or not bcrypt.verify(data.password, user["password"]):
        raise HTTPException(401, "یوزرنیم یا پسورد اشتباهه")

    token = secrets.token_urlsafe(32)
    TOKENS[token] = user["id"]
    return {"token": token, "user": {"id": user["id"], "username": user["username"]}}


@app.post("/api/logout")
async def logout(payload: dict):
    token = payload.get("token")
    if token in TOKENS:
        del TOKENS[token]
    return {"ok": True}

# ---------- API کاربران ----------
@app.get("/api/users")
async def get_users(token: str):
    me = user_from_token(token)
    if not me:
        raise HTTPException(401, "لاگین نیستی")

    conn = get_db()
    users = conn.execute(
        "SELECT id, username FROM users WHERE id != ? ORDER BY username",
        (me["id"],)
    ).fetchall()
    conn.close()
    return [dict(u) for u in users]

# ---------- API پیامها ----------
@app.post("/api/send")
async def send_message(data: MessageData):
    me = user_from_token(data.token)
    if not me:
        raise HTTPException(401, "لاگین نیستی")
    if not data.content.strip():
        raise HTTPException(400, "پیام خالیه")

    conn = get_db()
    conn.execute(
        "INSERT INTO messages (sender_id, receiver_id, content, created_at) VALUES (?, ?, ?, ?)",
        (me["id"], data.receiver_id, data.content.strip(), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/messages/{other_id}")
async def get_messages(other_id: int, token: str, last_id: int = 0):
    me = user_from_token(token)
    if not me:
        raise HTTPException(401, "لاگین نیستی")

    conn = get_db()
    rows = conn.execute("""
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.created_at, u.username AS sender_name
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.id > ?
          AND ((m.sender_id = ? AND m.receiver_id = ?)
            OR (m.sender_id = ? AND m.receiver_id = ?))
        ORDER BY m.id ASC
    """, (last_id, me["id"], other_id, other_id, me["id"])).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------- اجرا ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

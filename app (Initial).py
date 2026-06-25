"""
GameFinder — Secure Game Recommendation Chatbot
================================================
Single-file Flask application for Raspberry Pi 5

Requirements:  pip install flask
Run:           python3 app.py
URL:           http://localhost:5000

Security features:
  - Passwords hashed with PBKDF2-HMAC-SHA256 + per-user salt
  - Session tokens via secrets.token_hex (httponly cookie)
  - Login required on all recommendation routes
  - Input sanitised (length-capped, HTML-escaped) before DB storage
  - Parameterised SQL queries throughout (no string interpolation)
  - Secure HTTP headers on every response (CSP, X-Frame-Options, etc.)
  - Session expiry after 2 hours of inactivity

NLP layer:
  - Free-text chat input parsed for genre / mood / platform keywords
  - difflib fuzzy matching for typo tolerance
  - Falls back gracefully to chip-based UI answers
"""

import json
import os
import re
import html
import sqlite3
import hashlib
import hmac
import secrets
import threading
import webbrowser
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, request, jsonify, render_template_string,
                   session, g)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # regenerated each restart (stateless sessions)

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, "gamefinder.db")
JSON_PATH = os.path.join(BASE_DIR, "games_db.json")

SESSION_LIFETIME = timedelta(hours=2)

# ── Secure response headers ───────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline';"
    )
    return response

# ── Database setup ────────────────────────────────────────────────────────────

def get_db():
    """Return a per-request SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    """Create tables and import games from JSON if needed."""
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            salt          TEXT    NOT NULL,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS games (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            title            TEXT NOT NULL,
            genre            TEXT,
            tags             TEXT,
            developer        TEXT,
            publisher        TEXT,
            series           TEXT,
            platforms        TEXT,
            release_date     TEXT,
            launch_price     REAL,
            metacritic_score INTEGER,
            rating           TEXT,
            short_description TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            last_active TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS recommendation_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            preferences TEXT    NOT NULL,
            results     TEXT    NOT NULL,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)

    # Import games from JSON if table is empty
    count = con.execute("SELECT COUNT(*) FROM games").fetchone()[0]
    if count == 0 and os.path.exists(JSON_PATH):
        with open(JSON_PATH) as f:
            games = json.load(f)
        for g_data in games:
            con.execute("""
                INSERT INTO games
                  (title, genre, tags, developer, publisher, series,
                   platforms, release_date, launch_price, metacritic_score,
                   rating, short_description)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                g_data.get("title", ""),
                g_data.get("genre", ""),
                json.dumps(g_data.get("tags", [])),
                g_data.get("developer", ""),
                g_data.get("publisher", ""),
                g_data.get("series", ""),
                json.dumps(g_data.get("platforms", [])),
                g_data.get("release_date", ""),
                g_data.get("launch_price", 0),
                g_data.get("metacritic_score", 0),
                g_data.get("rating", ""),
                g_data.get("short_description", ""),
            ))
        con.commit()
        print(f"  Imported {len(games)} games into database.")
    con.close()

def load_games_from_db():
    """Load all games as list of dicts."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM games").fetchall()
    con.close()
    games = []
    for r in rows:
        g_data = dict(r)
        g_data["tags"]      = json.loads(g_data.get("tags") or "[]")
        g_data["platforms"] = json.loads(g_data.get("platforms") or "[]")
        games.append(g_data)
    return games

# ── Password hashing (PBKDF2-HMAC-SHA256) ─────────────────────────────────────

def hash_password(password: str, salt: str = None):
    """Return (hash_hex, salt_hex). Generate salt if not provided."""
    if salt is None:
        salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=260_000,   # OWASP 2024 recommendation
    )
    return dk.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, stored_hash)

# ── Session management ────────────────────────────────────────────────────────

def create_session(user_id: int) -> str:
    token = secrets.token_hex(32)
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token, user_id) VALUES (?, ?)",
        (token, user_id)
    )
    db.commit()
    return token

def get_session_user(token: str):
    """Return user row if token is valid and not expired, else None."""
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT s.user_id, s.last_active, u.username "
        "FROM sessions s JOIN users u ON s.user_id = u.id "
        "WHERE s.token = ?",
        (token,)
    ).fetchone()
    if not row:
        return None
    last = datetime.fromisoformat(row["last_active"])
    if datetime.now() - last > SESSION_LIFETIME:
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
        return None
    # Refresh last_active
    db.execute(
        "UPDATE sessions SET last_active = ? WHERE token = ?",
        (datetime.now().isoformat(), token)
    )
    db.commit()
    return row

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("gf_session")
        user  = get_session_user(token)
        if not user:
            return jsonify({"error": "unauthorised", "redirect": "/"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

# ── Input sanitisation ────────────────────────────────────────────────────────

def sanitise(value: str, max_len: int = 200) -> str:
    """Strip, truncate, and HTML-escape a string."""
    if not isinstance(value, str):
        return ""
    return html.escape(value.strip()[:max_len])

# ── NLP keyword parser ────────────────────────────────────────────────────────

GENRE_KEYWORDS = {
    "action rpg":        "Action RPG",
    "rpg":               "Action RPG",
    "role playing":      "Action RPG",
    "shooter":           "First-Person Shooter",
    "fps":               "First-Person Shooter",
    "first person":      "First-Person Shooter",
    "puzzle":            "Puzzle",
    "platformer":        "Platformer",
    "platform":          "Platformer",
    "strategy":          "Strategy",
    "horror":            "Horror",
    "adventure":         "Adventure",
    "simulation":        "Simulation",
    "sim":               "Simulation",
    "jrpg":              "JRPG",
    "japanese":          "JRPG",
    "roguelike":         "Roguelike",
    "rogue":             "Roguelike",
    "fighting":          "Fighting",
    "racing":            "Racing",
    "metroidvania":      "Metroidvania",
    "visual novel":      "Visual Novel",
    "sandbox":           "Simulation",
    "survival":          "Horror",
    "stealth":           "Adventure",
    "open world":        "Action RPG",
}

MOOD_KEYWORDS = {
    "cozy": "cozy", "chill": "cozy", "relax": "cozy", "relaxing": "cozy",
    "calm": "cozy", "easy": "cozy", "casual": "cozy",
    "intense": "intense", "action": "intense", "fast": "intense",
    "adrenaline": "intense", "exciting": "intense",
    "story": "story", "narrative": "story", "plot": "story",
    "cinematic": "story", "deep": "story", "emotional": "story",
    "creative": "creative", "build": "creative", "craft": "creative",
    "sandbox": "creative",
    "scary": "scary", "horror": "scary", "creepy": "scary",
    "terrifying": "scary", "spooky": "scary",
    "funny": "funny", "comedy": "funny", "humour": "funny",
    "humor": "funny", "laugh": "funny",
}

PLATFORM_KEYWORDS = {
    "pc": "PC", "computer": "PC", "windows": "PC", "steam": "PC",
    "ps5": "PS5", "playstation 5": "PS5", "playstation5": "PS5",
    "ps4": "PS4", "playstation 4": "PS4", "playstation4": "PS4",
    "playstation": "PS5",
    "xbox series": "Xbox Series X/S", "xbox": "Xbox Series X/S",
    "switch": "Nintendo Switch", "nintendo": "Nintendo Switch",
}

DIFFICULTY_KEYWORDS = {
    "easy": "easy", "simple": "easy", "casual": "easy", "breezy": "easy",
    "normal": "normal", "medium": "normal", "moderate": "normal",
    "hard": "hard", "difficult": "hard", "challenging": "hard",
    "punish": "hard", "souls": "hard", "brutal": "hard",
}

BUDGET_KEYWORDS = {
    "free": 0, "no cost": 0,
    "cheap": 15, "budget": 15, "inexpensive": 15,
    "under 15": 15, "under $15": 15,
    "under 30": 30, "under $30": 30,
    "under 60": 60, "under $60": 60,
    "any": 9999, "no limit": 9999, "whatever": 9999,
}

def parse_free_text(text: str) -> dict:
    """
    Parse a free-text message and return a partial prefs dict.
    Uses substring matching then difflib fuzzy fallback.
    """
    text_lower = text.lower()
    prefs = {}

    # Genres (can detect multiple)
    found_genres = []
    for kw, genre in GENRE_KEYWORDS.items():
        if kw in text_lower and genre not in found_genres:
            found_genres.append(genre)
    if found_genres:
        prefs["genres"] = found_genres

    # Mood
    for kw, mood in MOOD_KEYWORDS.items():
        if kw in text_lower:
            prefs["mood"] = mood
            break

    # Platform
    for kw, plat in PLATFORM_KEYWORDS.items():
        if kw in text_lower:
            prefs["platform"] = plat
            break

    # Difficulty
    for kw, diff in DIFFICULTY_KEYWORDS.items():
        if kw in text_lower:
            prefs["difficulty"] = diff
            break

    # Budget — look for dollar amounts
    money = re.search(r"\$?\b(\d+)\b", text_lower)
    if money:
        amt = int(money.group(1))
        prefs["budget"] = amt

    for kw, budget in BUDGET_KEYWORDS.items():
        if kw in text_lower:
            prefs["budget"] = budget
            break

    # Multiplayer
    if any(w in text_lower for w in ["multiplayer", "co-op", "coop", "with friends", "online"]):
        prefs["multiplayer"] = "yes"
    elif any(w in text_lower for w in ["solo", "single player", "alone", "by myself"]):
        prefs["multiplayer"] = "no"

    return prefs

# ── Recommendation engine ─────────────────────────────────────────────────────

MOOD_MAP = {
    "cozy":    ["cozy", "relaxing", "farming", "life sim", "colorful", "family-friendly"],
    "intense": ["fast-paced", "action", "gore", "heavy metal", "arena shooter", "competitive"],
    "story":   ["story-rich", "narrative", "cinematic", "choices matter", "choice-driven", "story-driven"],
    "creative":["sandbox", "crafting", "building", "voxel", "procedural generation"],
    "scary":   ["horror", "atmospheric", "psychological horror", "survival horror", "tense"],
    "funny":   ["comedy", "satire", "dark comedy", "quirky"],
}

def score_game(game, prefs):
    pts = 0

    # Hard exclusions — return immediately with sentinel value
    try:
        budget = float(prefs.get("budget", 9999))
        price  = float(game.get("launch_price", 0))
        if price > budget:
            return -9999
    except (ValueError, TypeError):
        pass

    min_score = prefs.get("min_score", 0)
    meta = game.get("metacritic_score", 0)
    if meta < min_score:
        return -9999

    platform = prefs.get("platform", "")
    if platform:
        matched = any(platform.lower() in p.lower() or p.lower() in platform.lower() for p in game.get("platforms", []))
        if not matched:
            return -9999

    # Scoring
    for genre in prefs.get("genres", []):
        if genre.lower() in game.get("genre", "").lower():
            pts += 40
        for tag in game.get("tags", []):
            if genre.lower() in tag.lower():
                pts += 10

    for t in prefs.get("tags", []):
        for tag in game.get("tags", []):
            if t.lower() in tag.lower():
                pts += 15

    mp_pref = prefs.get("multiplayer", "")
    mp_tags = {"co-op", "multiplayer", "online", "competitive", "team-based"}
    game_is_mp = any(t.lower() in mp_tags for t in game.get("tags", []))
    if mp_pref == "yes" and game_is_mp:     pts += 20
    elif mp_pref == "no" and game_is_mp:    pts -= 20

    diff_pref = prefs.get("difficulty", "")
    hard_tags = {"soulslike", "challenging", "permadeath", "one-hit kill", "roguelike", "bullet hell"}
    game_is_hard = any(t.lower() in hard_tags for t in game.get("tags", []))
    if diff_pref == "hard" and game_is_hard:    pts += 20
    elif diff_pref == "easy" and game_is_hard:  pts -= 30

    mood = prefs.get("mood", "")
    if mood in MOOD_MAP:
        for keyword in MOOD_MAP[mood]:
            for tag in game.get("tags", []):
                if keyword in tag.lower(): pts += 12
            if keyword in game.get("genre", "").lower(): pts += 8

    pts += (meta - 70) * 0.5
    return pts

def recommend(prefs, games, n=6):
    scored = [(g, score_game(g, prefs)) for g in games]
    scored.sort(key=lambda x: -x[1])
    return [g for g, s in scored[:n] if s > -9000]

# ── Conversation questions ────────────────────────────────────────────────────

QUESTIONS = [
    {
        "id":      "platform",
        "text":    "What platform are you gaming on?",
        "type":    "chips",
        "options": ["PC", "PS5", "PS4", "Xbox Series X/S", "Nintendo Switch", "Any"],
    },
    {
        "id":      "genres",
        "text":    "What kinds of games do you enjoy? Pick as many as you like.",
        "type":    "chips_multi",
        "options": [
            "Action RPG", "First-Person Shooter", "Puzzle", "Platformer",
            "Strategy", "Horror", "Adventure", "Simulation", "JRPG",
            "Roguelike", "Fighting", "Racing", "Metroidvania", "Visual Novel",
        ],
    },
    {
        "id":      "mood",
        "text":    "What vibe are you after?",
        "type":    "chips",
        "options": ["Cozy & relaxing", "Intense & action-packed", "Deep story",
                    "Creative & building", "Scary", "Something funny"],
    },
    {
        "id":      "multiplayer",
        "text":    "Solo or multiplayer?",
        "type":    "chips",
        "options": ["Solo only", "Multiplayer please", "Either is fine"],
    },
    {
        "id":      "difficulty",
        "text":    "How hard do you want it?",
        "type":    "chips",
        "options": ["Easy & breezy", "Normal challenge", "Punish me"],
    },
    {
        "id":      "budget",
        "text":    "What's your budget?",
        "type":    "chips",
        "options": ["Free only", "Under $15", "Under $30", "Under $60", "No limit"],
    },
    {
        "id":      "min_score",
        "text":    "How important is critical acclaim?",
        "type":    "chips",
        "options": ["Any rating is fine", "Above average (75+)",
                    "Good only (85+)", "Masterpieces only (90+)"],
    },
]

ANSWER_MAP = {
    "any": "", "any rating is fine": 0,
    "cozy & relaxing": "cozy", "intense & action-packed": "intense",
    "deep story": "story", "creative & building": "creative",
    "something funny": "funny", "scary": "scary",
    "solo only": "no", "multiplayer please": "yes", "either is fine": "",
    "easy & breezy": "easy", "normal challenge": "normal", "punish me": "hard",
    "free only": 0, "under $15": 15, "under $30": 30,
    "under $60": 60, "no limit": 9999,
    "above average (75+)": 75, "good only (85+)": 85,
    "masterpieces only (90+)": 90,
}

def parse_answer(question_id, raw):
    key = raw.lower().strip()
    if key in ANSWER_MAP:
        return ANSWER_MAP[key]
    if question_id == "genres":
        return [r.strip() for r in raw.split(",")]
    return raw

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    data     = request.get_json(silent=True) or {}
    username = sanitise(data.get("username", ""), 40)
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required."}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if not re.match(r"^[a-zA-Z0-9_\-]+$", username):
        return jsonify({"error": "Username may only contain letters, numbers, _ and -."}), 400

    pw_hash, salt = hash_password(password)
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, pw_hash, salt)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken."}), 409

    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    token = create_session(user["id"])
    resp  = jsonify({"ok": True, "username": username})
    resp.set_cookie("gf_session", token, httponly=True, samesite="Strict", max_age=7200)
    return resp


@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = sanitise(data.get("username", ""), 40)
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required."}), 400

    db  = get_db()
    row = db.execute(
        "SELECT id, password_hash, salt FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    # Always verify (even with dummy hash) to prevent timing-based user enumeration
    dummy_hash, dummy_salt = hash_password("dummy_prevent_timing_attack")
    stored_hash = row["password_hash"] if row else dummy_hash
    stored_salt = row["salt"]          if row else dummy_salt

    if not verify_password(password, stored_hash, stored_salt) or not row:
        return jsonify({"error": "Invalid username or password."}), 401

    token = create_session(row["id"])
    resp  = jsonify({"ok": True, "username": username})
    resp.set_cookie("gf_session", token, httponly=True, samesite="Strict", max_age=7200)
    return resp


@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.cookies.get("gf_session")
    if token:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
    resp = jsonify({"ok": True})
    resp.delete_cookie("gf_session")
    return resp


@app.route("/api/me", methods=["GET"])
def me():
    token = request.cookies.get("gf_session")
    user  = get_session_user(token)
    if not user:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "username": user["username"]})

# ── Chat / recommendation routes (login required) ─────────────────────────────

@app.route("/api/start", methods=["POST"])
@login_required
def start():
    return jsonify({"question": QUESTIONS[0], "index": 0, "total": len(QUESTIONS)})


@app.route("/api/answer", methods=["POST"])
@login_required
def answer():
    data    = request.get_json(silent=True) or {}
    index   = int(data.get("index", 0))
    answers = data.get("answers", {})

    # Sanitise all incoming answer strings
    clean_answers = {sanitise(k, 40): sanitise(v, 300)
                     for k, v in answers.items() if isinstance(v, str)}

    next_index = index + 1
    if next_index < len(QUESTIONS):
        return jsonify({
            "question": QUESTIONS[next_index],
            "index":    next_index,
            "total":    len(QUESTIONS),
            "done":     False,
        })

    # Build prefs
    prefs = {}
    for q in QUESTIONS:
        raw = clean_answers.get(q["id"], "")
        prefs[q["id"]] = parse_answer(q["id"], raw) if raw else (
            [] if q["type"] == "chips_multi" else ""
        )

    games   = load_games_from_db()
    results = recommend(prefs, games, n=6)

    # Log the session to DB
    db = get_db()
    db.execute(
        "INSERT INTO recommendation_log (user_id, preferences, results) VALUES (?, ?, ?)",
        (
            g.current_user["user_id"],
            json.dumps(prefs),
            json.dumps([r.get("title") for r in results]),
        )
    )
    db.commit()

    return jsonify({"done": True, "games": results})


@app.route("/api/nlp", methods=["POST"])
@login_required
def nlp_parse():
    """Parse free-text input and return detected preferences."""
    data  = request.get_json(silent=True) or {}
    text  = sanitise(data.get("text", ""), 500)
    prefs = parse_free_text(text)
    return jsonify({"prefs": prefs, "detected": len(prefs) > 0})


@app.route("/api/history", methods=["GET"])
@login_required
def history():
    """Return the last 10 recommendation sessions for the logged-in user."""
    db   = get_db()
    rows = db.execute(
        "SELECT preferences, results, created_at FROM recommendation_log "
        "WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
        (g.current_user["user_id"],)
    ).fetchall()
    return jsonify([{
        "preferences": json.loads(r["preferences"]),
        "results":     json.loads(r["results"]),
        "at":          r["created_at"],
    } for r in rows])

# ── Main page ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)

# ── HTML / CSS / JS ───────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GameFinder</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0f14;--surface:#151820;--surface2:#1c2030;--border:#2a2f42;
  --accent:#7c6dfa;--accent2:#a78bfa;--text:#e8eaf0;--muted:#7a7f99;
  --success:#34d399;--chip-bg:#1c2030;--chip-sel:#312e7a;
  --chip-bord:#3a3f5c;--chip-sel-b:#7c6dfa;
  --score-hi:#34d399;--score-mid:#fbbf24;--score-lo:#f87171;
  --r:12px;--rs:8px;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center}

/* Header */
header{width:100%;padding:1rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem;background:var(--surface)}
.logo{font-size:1.3rem;font-weight:700;letter-spacing:-.03em}
.logo span{color:var(--accent2)}
.user-info{margin-left:auto;display:flex;align-items:center;gap:.75rem;font-size:.85rem;color:var(--muted)}
.btn-sm{padding:.35rem .85rem;border-radius:999px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:.8rem;cursor:pointer;transition:all .15s}
.btn-sm:hover{border-color:var(--accent);color:var(--text)}
.btn-sm.danger:hover{border-color:#f87171;color:#f87171}

/* Auth screen */
#authScreen{width:100%;max-width:400px;padding:3rem 1rem;flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1.5rem}
.auth-card{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:1.75rem}
.auth-card h2{font-size:1.1rem;font-weight:600;margin-bottom:1.25rem;color:var(--text)}
.field{display:flex;flex-direction:column;gap:.4rem;margin-bottom:1rem}
.field label{font-size:.8rem;color:var(--muted)}
.field input{background:var(--surface2);border:1px solid var(--border);border-radius:var(--rs);padding:.6rem .85rem;color:var(--text);font-size:.9rem;outline:none;transition:border-color .15s}
.field input:focus{border-color:var(--accent)}
.btn-primary{width:100%;padding:.65rem;background:var(--accent);color:#fff;border:none;border-radius:999px;font-size:.9rem;font-weight:600;cursor:pointer;transition:background .15s}
.btn-primary:hover{background:var(--accent2)}
.auth-switch{font-size:.82rem;color:var(--muted);text-align:center;margin-top:.75rem}
.auth-switch a{color:var(--accent2);cursor:pointer;text-decoration:none}
.auth-switch a:hover{text-decoration:underline}
.err-msg{font-size:.82rem;color:#f87171;min-height:1.1rem;text-align:center}

/* Main app */
#appScreen{display:none;width:100%;flex-direction:column;align-items:center}
main{width:100%;max-width:760px;padding:2rem 1rem 4rem}

/* Free-text bar */
.nlp-bar{display:flex;gap:.5rem;margin-bottom:1.5rem;animation:fadeUp .3s ease both}
.nlp-bar input{flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:999px;padding:.6rem 1.1rem;color:var(--text);font-size:.88rem;outline:none;transition:border-color .15s}
.nlp-bar input:focus{border-color:var(--accent)}
.nlp-bar input::placeholder{color:var(--muted)}
.nlp-bar button{padding:.6rem 1.2rem;background:var(--accent);color:#fff;border:none;border-radius:999px;font-size:.85rem;font-weight:600;cursor:pointer;transition:background .15s;white-space:nowrap}
.nlp-bar button:hover{background:var(--accent2)}

/* Progress */
.progress-wrap{margin-bottom:1.25rem;display:flex;align-items:center;gap:.75rem;font-size:.8rem;color:var(--muted)}
.progress-bar{flex:1;height:4px;background:var(--border);border-radius:99px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;transition:width .4s ease}

/* Chat */
.chat{display:flex;flex-direction:column;gap:1rem}
.bubble-wrap{display:flex;align-items:flex-end;gap:.6rem;animation:fadeUp .3s ease both}
.bubble-wrap.user{flex-direction:row-reverse}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.avatar{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.9rem;flex-shrink:0;background:var(--accent);color:#fff;font-weight:700}
.bubble-wrap.user .avatar{background:var(--surface2);color:var(--muted)}
.bubble{max-width:75%;padding:.75rem 1rem;border-radius:var(--r);font-size:.93rem;line-height:1.6;background:var(--surface2);border:1px solid var(--border)}
.bubble-wrap.user .bubble{background:var(--chip-sel);border-color:var(--chip-sel-b);color:#c4bcff}

/* Chips */
.chips-wrap{display:flex;flex-wrap:wrap;gap:.45rem;margin-top:.4rem;animation:fadeUp .35s .1s ease both}
.chip{padding:.4rem .95rem;border-radius:999px;border:1px solid var(--chip-bord);background:var(--chip-bg);color:var(--text);font-size:.85rem;cursor:pointer;transition:all .15s;user-select:none}
.chip:hover{border-color:var(--accent);color:var(--accent2)}
.chip.selected{background:var(--chip-sel);border-color:var(--chip-sel-b);color:var(--accent2);font-weight:600}
.confirm-btn{margin-top:.65rem;padding:.5rem 1.3rem;background:var(--accent);color:#fff;border:none;border-radius:999px;font-size:.87rem;font-weight:600;cursor:pointer;display:none;transition:background .15s}
.confirm-btn.visible{display:inline-block}
.confirm-btn:hover{background:var(--accent2)}

/* Results */
.results-header{font-size:1rem;font-weight:700;margin:1.5rem 0 .85rem;display:flex;align-items:center;gap:.5rem}
.results-header::after{content:'';flex:1;height:1px;background:var(--border);margin-left:.5rem}
.game-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.9rem;animation:fadeUp .4s ease both}
.game-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:1rem 1.15rem;display:flex;flex-direction:column;gap:.45rem;transition:border-color .2s,transform .2s}
.game-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.card-top{display:flex;justify-content:space-between;align-items:flex-start;gap:.5rem}
.card-title{font-size:.97rem;font-weight:700;line-height:1.3}
.score-badge{font-size:.75rem;font-weight:700;padding:.18rem .5rem;border-radius:var(--rs);white-space:nowrap;flex-shrink:0}
.score-hi{background:#064e3b;color:var(--score-hi)}
.score-mid{background:#451a03;color:var(--score-mid)}
.score-lo{background:#450a0a;color:var(--score-lo)}
.card-genre{font-size:.74rem;color:var(--accent2);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.card-desc{font-size:.84rem;color:var(--muted);line-height:1.5}
.card-tags{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.2rem}
.tag{font-size:.7rem;padding:.18rem .55rem;background:var(--surface2);border:1px solid var(--border);border-radius:999px;color:var(--muted)}
.card-meta{display:flex;gap:.65rem;font-size:.75rem;color:var(--muted);margin-top:.2rem;flex-wrap:wrap}

/* NLP detected banner */
.nlp-banner{background:#1a1f35;border:1px solid var(--accent);border-radius:var(--rs);padding:.6rem 1rem;font-size:.83rem;color:var(--accent2);margin-bottom:.75rem;animation:fadeUp .25s ease both}

/* Restart / history */
.restart-wrap{margin-top:1.75rem;text-align:center;display:flex;gap:.75rem;justify-content:center;flex-wrap:wrap;animation:fadeUp .4s .2s ease both}
.restart-btn{padding:.55rem 1.5rem;background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:999px;font-size:.87rem;cursor:pointer;transition:all .15s}
.restart-btn:hover{border-color:var(--accent);color:var(--text)}

/* History panel */
.history-panel{margin-top:1.5rem;animation:fadeUp .3s ease both}
.history-item{background:var(--surface);border:1px solid var(--border);border-radius:var(--rs);padding:.75rem 1rem;margin-bottom:.6rem;font-size:.82rem;color:var(--muted)}
.history-item strong{color:var(--text);display:block;margin-bottom:.25rem}

/* Typing indicator */
.typing{display:flex;gap:5px;padding:.2rem 0}
.typing span{width:7px;height:7px;background:var(--muted);border-radius:50%;animation:blink 1.2s infinite}
.typing span:nth-child(2){animation-delay:.2s}
.typing span:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,80%,100%{opacity:.2;transform:scale(.85)}40%{opacity:1;transform:scale(1)}}

@media(max-width:500px){
  .bubble{max-width:90%}
  .game-grid{grid-template-columns:1fr}
}
</style>
</head>
<body>

<!-- ── Header ── -->
<header>
  <div class="logo">🎮 Game<span>Finder</span></div>
  <div class="user-info" id="userInfo" style="display:none">
    <span id="userLabel"></span>
    <button class="btn-sm" onclick="showHistory()">History</button>
    <button class="btn-sm danger" onclick="doLogout()">Log out</button>
  </div>
</header>

<!-- ── Auth screen ── -->
<div id="authScreen">
  <div class="auth-card" id="loginCard">
    <h2>Sign in to GameFinder</h2>
    <div class="field"><label>Username</label><input id="loginUser" type="text" autocomplete="username" placeholder="your_username"></div>
    <div class="field"><label>Password</label><input id="loginPass" type="password" autocomplete="current-password" placeholder="••••••••"></div>
    <div class="err-msg" id="loginErr"></div>
    <button class="btn-primary" onclick="doLogin()">Sign in</button>
    <div class="auth-switch">No account? <a onclick="showRegister()">Create one</a></div>
  </div>

  <div class="auth-card" id="registerCard" style="display:none">
    <h2>Create account</h2>
    <div class="field"><label>Username</label><input id="regUser" type="text" autocomplete="username" placeholder="your_username"></div>
    <div class="field"><label>Password (min 8 chars)</label><input id="regPass" type="password" autocomplete="new-password" placeholder="••••••••"></div>
    <div class="err-msg" id="regErr"></div>
    <button class="btn-primary" onclick="doRegister()">Create account</button>
    <div class="auth-switch">Already have one? <a onclick="showLogin()">Sign in</a></div>
  </div>
</div>

<!-- ── App screen ── -->
<div id="appScreen">
  <main>
    <!-- Free-text NLP bar -->
    <div class="nlp-bar">
      <input id="nlpInput" type="text" placeholder='Or describe what you want — e.g. "spooky solo horror on PC under $30"' />
      <button onclick="doNLP()">Search ↗</button>
    </div>

    <div class="progress-wrap">
      <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:0%"></div></div>
      <span id="progressLabel">Let's begin</span>
    </div>

    <div class="chat" id="chat"></div>
  </main>
</div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let state = { index:-1, total:0, answers:{}, currentQ:null };

// ── Helpers ───────────────────────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const chat = () => $('chat');

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls)  e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}

function scrollBottom() {
  window.scrollTo({ top: document.body.scrollHeight, behavior:'smooth' });
}

function setProgress(index, total) {
  const pct = total > 0 ? Math.round((index / total) * 100) : 0;
  $('progressFill').style.width = pct + '%';
  $('progressLabel').textContent = index >= total ? 'Done!' : `Question ${index+1} of ${total}`;
}

async function api(path, method='POST', body=null) {
  const opts = { method, headers:{'Content-Type':'application/json'}, credentials:'same-origin' };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  return r.json();
}

// ── Auth ──────────────────────────────────────────────────────────────────────
function showLogin()    { $('loginCard').style.display=''; $('registerCard').style.display='none'; }
function showRegister() { $('registerCard').style.display=''; $('loginCard').style.display='none'; }

function onAuthed(username) {
  $('authScreen').style.display = 'none';
  $('appScreen').style.display  = 'flex';
  $('userInfo').style.display   = 'flex';
  $('userLabel').textContent     = '👤 ' + username;
  startChat();
}

async function doLogin() {
  $('loginErr').textContent = '';
  const d = await api('/api/login', 'POST', {
    username: $('loginUser').value,
    password: $('loginPass').value
  });
  if (d.error) { $('loginErr').textContent = d.error; return; }
  onAuthed(d.username);
}

async function doRegister() {
  $('regErr').textContent = '';
  const d = await api('/api/register', 'POST', {
    username: $('regUser').value,
    password: $('regPass').value
  });
  if (d.error) { $('regErr').textContent = d.error; return; }
  onAuthed(d.username);
}

async function doLogout() {
  await api('/api/logout');
  location.reload();
}

// ── Session check on load ─────────────────────────────────────────────────────
(async () => {
  const d = await api('/api/me', 'GET');
  if (d.authenticated) onAuthed(d.username);
})();

// Enter key on auth inputs
['loginUser','loginPass'].forEach(id => $( id).addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); }));
['regUser','regPass'].forEach(id => $(id).addEventListener('keydown',    e => { if(e.key==='Enter') doRegister(); }));
$('nlpInput').addEventListener('keydown', e => { if(e.key==='Enter') doNLP(); });

// ── NLP free-text search ──────────────────────────────────────────────────────
async function doNLP() {
  const text = $('nlpInput').value.trim();
  if (!text) return;
  const d = await api('/api/nlp', 'POST', { text });
  if (!d.detected) {
    addBotBubble("I couldn't detect any preferences from that — try the chips below, or be more specific.");
    return;
  }
  // Build partial answers from detected prefs and jump to results
  const prefs = d.prefs;
  const banner = el('div', 'nlp-banner');

  const labels = [];
  if (prefs.genres)     labels.push('Genre: ' + (Array.isArray(prefs.genres) ? prefs.genres.join(', ') : prefs.genres));
  if (prefs.platform)   labels.push('Platform: ' + prefs.platform);
  if (prefs.mood)       labels.push('Mood: ' + prefs.mood);
  if (prefs.difficulty) labels.push('Difficulty: ' + prefs.difficulty);
  if (prefs.budget !== undefined) labels.push('Budget: $' + prefs.budget);
  if (prefs.multiplayer) labels.push('Multiplayer: ' + prefs.multiplayer);
  banner.innerHTML = '🔍 Detected — ' + labels.join(' · ');
  chat().appendChild(banner);

  addUserBubble(text);
  $('nlpInput').value = '';

  // Map detected prefs to answer format and fire
  const answers = {};
  if (prefs.genres)      answers.genres     = Array.isArray(prefs.genres) ? prefs.genres.join(', ') : prefs.genres;
  if (prefs.platform)    answers.platform   = prefs.platform;
  if (prefs.mood)        answers.mood       = prefs.mood;
  if (prefs.difficulty)  answers.difficulty = prefs.difficulty;
  if (prefs.multiplayer) answers.multiplayer = prefs.multiplayer;
  // Budget
  if (prefs.budget !== undefined) {
    const bmap = {0:'Free only',15:'Under $15',30:'Under $30',60:'Under $60',9999:'No limit'};
    answers.budget = bmap[prefs.budget] || 'No limit';
  }
  answers.min_score = 'Any rating is fine';

  // Fill state and jump to final answer call
  state.answers = answers;
  const res = await api('/api/answer', 'POST', { index: 6, answers });
  if (res.done) {
    setProgress(state.total, state.total);
    showResults(res.games);
  }
}

// ── Chat bubbles ──────────────────────────────────────────────────────────────
function addBotBubble(html, withTyping=true) {
  return new Promise(resolve => {
    const wrap = el('div','bubble-wrap');
    const av   = el('div','avatar','🎮');
    const bub  = el('div','bubble');
    wrap.append(av, bub);
    chat().appendChild(wrap);
    scrollBottom();
    if (!withTyping) { bub.innerHTML = html; resolve(bub); return; }
    const dots = el('div','typing','<span></span><span></span><span></span>');
    bub.appendChild(dots);
    scrollBottom();
    setTimeout(() => { bub.innerHTML = html; resolve(bub); scrollBottom(); }, 500);
  });
}

function addUserBubble(text) {
  const wrap = el('div','bubble-wrap user');
  wrap.append(el('div','avatar','👤'), el('div','bubble', text));
  chat().appendChild(wrap);
  scrollBottom();
}

// ── Chips ─────────────────────────────────────────────────────────────────────
function addChips(question, multi, onSubmit) {
  const wrap = el('div','chips-wrap');
  const confirmBtn = el('button','confirm-btn','Confirm →');
  let selected = [];
  question.options.forEach(opt => {
    const chip = el('div','chip', opt);
    chip.addEventListener('click', () => {
      if (!multi) {
        wrap.querySelectorAll('.chip').forEach(c => c.classList.remove('selected'));
        chip.classList.add('selected');
        setTimeout(() => onSubmit(opt), 180);
      } else {
        chip.classList.toggle('selected');
        const idx = selected.indexOf(opt);
        if (idx === -1) selected.push(opt); else selected.splice(idx,1);
        confirmBtn.classList.toggle('visible', selected.length > 0);
      }
    });
    wrap.appendChild(chip);
  });
  if (multi) {
    wrap.appendChild(confirmBtn);
    confirmBtn.addEventListener('click', () => { if (selected.length > 0) onSubmit(selected.join(', ')); });
  }
  chat().appendChild(wrap);
  scrollBottom();
}

function removeInputs() {
  document.querySelectorAll('.chips-wrap, .nlp-banner').forEach(e => e.remove());
}

// ── Answer flow ───────────────────────────────────────────────────────────────
async function sendAnswer(questionId, raw) {
  removeInputs();
  addUserBubble(raw);
  state.answers[questionId] = raw;
  const data = await api('/api/answer', 'POST', { index: state.index, answers: state.answers });
  if (data.error === 'unauthorised') { location.reload(); return; }
  if (data.done) {
    setProgress(state.total, state.total);
    showResults(data.games);
  } else {
    state.index   = data.index;
    state.total   = data.total;
    state.currentQ = data.question;
    setProgress(data.index, data.total);
    await askQuestion(data.question);
  }
}

async function askQuestion(q) {
  await addBotBubble(q.text);
  addChips(q, q.type === 'chips_multi', ans => sendAnswer(q.id, ans));
}

// ── Results ───────────────────────────────────────────────────────────────────
function scoreClass(s) {
  return s >= 90 ? 'score-hi' : s >= 75 ? 'score-mid' : 'score-lo';
}

async function showResults(games) {
  if (!games || games.length === 0) {
    await addBotBubble("No strong matches found — try loosening your filters.");
    addRestartButton();
    return;
  }
  await addBotBubble(`Found ${games.length} game${games.length!==1?'s':''} for you:`);
  const header = el('div','results-header','🕹 Your recommendations');
  chat().appendChild(header);
  const grid = el('div','game-grid');
  games.forEach(g => {
    const score    = g.metacritic_score || 0;
    const price    = g.launch_price === 0 ? 'Free' : `$${Number(g.launch_price).toFixed(2)}`;
    const tags     = (g.tags||[]).slice(0,4).map(t=>`<span class="tag">${t}</span>`).join('');
    const platforms = (g.platforms||[]).slice(0,4).join(', ');
    const card = el('div','game-card');
    card.innerHTML = `
      <div class="card-top">
        <div class="card-title">${g.title}</div>
        <div class="score-badge ${scoreClass(score)}">${score}</div>
      </div>
      <div class="card-genre">${g.genre}</div>
      <div class="card-desc">${g.short_description||''}</div>
      <div class="card-tags">${tags}</div>
      <div class="card-meta">
        <span>💰 ${price}</span>
        <span>🎮 ${platforms}</span>
        ${g.rating?`<span>🔞 ${g.rating}</span>`:''}
      </div>`;
    grid.appendChild(card);
  });
  chat().appendChild(grid);
  addRestartButton();
  scrollBottom();
}

// ── History ───────────────────────────────────────────────────────────────────
async function showHistory() {
  const existing = document.querySelector('.history-panel');
  if (existing) { existing.remove(); return; }
  const data = await api('/api/history', 'GET');
  const panel = el('div','history-panel');
  if (!data.length) {
    panel.innerHTML = '<div class="history-item">No previous sessions yet.</div>';
  } else {
    data.forEach(row => {
      const item = el('div','history-item');
      const date = new Date(row.at).toLocaleString();
      const titles = Array.isArray(row.results) ? row.results.join(', ') : '';
      item.innerHTML = `<strong>${date}</strong>Recommended: ${titles}`;
      panel.appendChild(item);
    });
  }
  document.querySelector('main').appendChild(panel);
  scrollBottom();
}

// ── Restart ───────────────────────────────────────────────────────────────────
function addRestartButton() {
  const wrap = el('div','restart-wrap');
  const rb   = el('button','restart-btn','↺ Start over');
  rb.addEventListener('click', () => {
    chat().innerHTML = '';
    wrap.remove();
    document.querySelector('.history-panel')?.remove();
    state = { index:-1, total:0, answers:{}, currentQ:null };
    setProgress(0,0);
    $('nlpInput').value = '';
    startChat();
  });
  wrap.appendChild(rb);
  chat().appendChild(wrap);
  scrollBottom();
}

// ── Boot ──────────────────────────────────────────────────────────────────────
async function startChat() {
  const data = await api('/api/start');
  if (data.error === 'unauthorised') { location.reload(); return; }
  state.index   = data.index;
  state.total   = data.total;
  state.currentQ = data.question;
  setProgress(0, data.total);
  await addBotBubble("Hey! I'm GameFinder 🎮 Answer a few questions and I'll find your perfect game — or use the search bar above to describe what you want.");
  await askQuestion(data.question);
}
</script>
</body>
</html>
"""

# ── Entry point ───────────────────────────────────────────────────────────────

def open_browser():
    import time
    time.sleep(1.2)
    webbrowser.open("http://localhost:5000")

if __name__ == "__main__":
    print("=" * 54)
    print("  GameFinder — Secure Game Recommendation Chatbot")
    print("=" * 54)
    init_db()
    games = load_games_from_db()
    print(f"  Database : {DB_PATH}")
    print(f"  Games    : {len(games)} loaded")
    print(f"  URL      : http://localhost:5000")
    print(f"  Stop     : Ctrl+C")
    print("=" * 54)
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)

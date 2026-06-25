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


def get_request_session_token():
  """Read the session token from either the cookie or an auth header."""
  data = request.get_json(silent=True) or {}
  return (
      request.cookies.get("gf_session")
      or request.headers.get("X-GameFinder-Session")
      or data.get("session_token")
      or request.args.get("session_token")
  )

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
    if datetime.utcnow() - last > SESSION_LIFETIME:
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
        return None
    # Refresh last_active
    db.execute(
        "UPDATE sessions SET last_active = ? WHERE token = ?",
      (datetime.utcnow().isoformat(sep=" "), token)
    )
    db.commit()
    return row

def login_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    token = get_request_session_token()
    user = get_session_user(token)
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

def parse_free_text(text: str, games=None) -> dict:
    """
    Parse a free-text message and return a partial prefs dict.
    Uses keyword matching plus metadata patterns for titles, series,
    developers, publishers, and niche / similarity requests.
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

    # Strong metadata matches
    dev_match = re.search(
        r"\b(?:developed by|made by|created by)\s+([a-z0-9& .'-]+?)(?=\s+(?:in|from|for|and|,|;|\.|$))",
        text_lower,
    )
    if dev_match:
        prefs["developer"] = dev_match.group(1).strip().title()

    pub_match = re.search(
        r"\b(?:published by|publisher)\s+([a-z0-9& .'-]+?)(?=\s+(?:in|from|for|and|,|;|\.|$))",
        text_lower,
    )
    if pub_match:
        prefs["publisher"] = pub_match.group(1).strip().title()

    series_match = re.search(
        r"\b(?:in the|from the|from|of the)\s+([a-z0-9& .'-]+?)\s+series\b",
        text_lower,
    )
    if series_match:
        prefs["series"] = series_match.group(1).strip().title()

    similarity_request = any(w in text_lower for w in ["game like", "games like", "similar to", "something like", "recommend me something like", "recommend something like"])
    seed_titles = []
    if similarity_request:
        prefs["similarity_mode"] = "yes"
        for game in games or []:
            title = game.get("title", "")
            if title.lower() in text_lower or title.lower().split(":")[0] in text_lower:
                seed_titles.append(title)
    else:
        for game in games or []:
            title = game.get("title", "")
            if title.lower() in text_lower:
                seed_titles.append(title)

    if seed_titles:
        prefs["seed_games"] = seed_titles

    if any(w in text_lower for w in ["hidden gem", "obscure", "underrated", "less known", "niche", "unknown"]):
        prefs["niche"] = "yes"

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

    seed_profiles = prefs.get("_seed_profiles", [])
    if prefs.get("similarity_mode") == "yes":
        for seed in seed_profiles:
            if game.get("title", "") == seed.get("title", ""):
                return -9999

    for seed in seed_profiles:
        if game.get("title", "") == seed.get("title", ""):
            pts += 90
        if game.get("series", "") and seed.get("series", "") and game.get("series", "").lower() == seed.get("series", "").lower():
            pts += 35
        if game.get("developer", "") and seed.get("developer", "") and game.get("developer", "").lower() == seed.get("developer", "").lower():
            pts += 28
        if game.get("publisher", "") and seed.get("publisher", "") and game.get("publisher", "").lower() == seed.get("publisher", "").lower():
            pts += 18

        shared_tags = set(seed.get("tags", [])) & set(game.get("tags", []))
        pts += len(shared_tags) * 12
        if seed.get("genre", "") == game.get("genre", ""):
            pts += 18

    if prefs.get("developer"):
        if prefs["developer"].lower() in game.get("developer", "").lower():
            pts += 45
    if prefs.get("publisher"):
        if prefs["publisher"].lower() in game.get("publisher", "").lower():
            pts += 25
    if prefs.get("series"):
        if prefs["series"].lower() in game.get("series", "").lower():
            pts += 40

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

    knownness = game.get("knownness_score", 50)
    if prefs.get("niche") == "yes":
        pts += max(0, 100 - float(knownness)) * 0.35
    else:
        pts += max(0, 50 - abs(float(knownness) - 50)) * 0.2

    pts += (meta - 70) * 0.5
    return pts

def recommend(prefs, games, n=6):
    seed_titles = [t for t in prefs.get("seed_games", []) if t]
    seed_profiles = []
    for g in games:
        if g.get("title") in seed_titles:
            seed_profiles.append(g)
    prefs_with_seed = dict(prefs)
    prefs_with_seed["_seed_profiles"] = seed_profiles

    scored = []
    for g in games:
        s = score_game(g, prefs_with_seed)
        if s > -9000:
            match = calculate_match_percent(g, prefs_with_seed)
            scored.append((g, s, match))

    scored.sort(key=lambda x: -x[1])
    results = []
    for game, _, match in scored[:n]:
        game_copy = dict(game)
        game_copy["match_percent"] = match
        results.append(game_copy)
    return results

def calculate_match_percent(game, prefs):
    raw = score_game(game, prefs)
    if raw <= -9000:
        return 0
    return max(0, min(99, int((raw / 130) * 100)))

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
    resp  = jsonify({"ok": True, "username": username, "token": token})
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
    resp  = jsonify({"ok": True, "username": username, "token": token})
    resp.set_cookie("gf_session", token, httponly=True, samesite="Strict", max_age=7200)
    return resp


@app.route("/api/logout", methods=["POST"])
def logout():
    token = get_request_session_token()
    if token:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
    resp = jsonify({"ok": True})
    resp.delete_cookie("gf_session")
    return resp


@app.route("/api/me", methods=["GET"])
def me():
    token = get_request_session_token()
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
    search_text = sanitise(data.get("search_text", ""), 500)

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

    if search_text:
        games = load_games_from_db()
        prefs.update(parse_free_text(search_text, games))

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
    games = load_games_from_db()
    prefs = parse_free_text(text, games)
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
<title>Game Finder</title>
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

/* GameCube-inspired startup menu theme */
:root{
  --bg:#030406;
  --surface:#0b1018;
  --surface2:#111a26;
  --border:rgba(160,220,255,.16);
  --accent:#7ef7df;
  --accent2:#79a7ff;
  --text:#f3fbff;
  --muted:#9ab0c7;
  --chip-bg:rgba(255,255,255,.04);
  --chip-sel:rgba(114,160,255,.22);
  --chip-bord:rgba(160,220,255,.16);
  --chip-sel-b:rgba(126,247,223,.55);
  --r:24px;
  --rs:16px;
}

body{
  position:relative;
  overflow-x:hidden;
  background:
    radial-gradient(circle at 50% 10%, rgba(126,247,223,.16), transparent 24%),
    radial-gradient(circle at 18% 18%, rgba(121,167,255,.18), transparent 28%),
    radial-gradient(circle at 82% 82%, rgba(121,167,255,.12), transparent 24%),
    linear-gradient(180deg, #05070b 0%, #060b12 45%, #030406 100%);
  color:var(--text);
  font-family:"Trebuchet MS","Segoe UI",sans-serif;
}

body::before{
  content:"";
  position:fixed;
  inset:0;
  pointer-events:none;
  background:linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px);
  background-size:100% 4px;
  opacity:.08;
  mix-blend-mode:screen;
}

body::after{
  content:"";
  position:fixed;
  inset:-10%;
  pointer-events:none;
  background:radial-gradient(circle at center, transparent 35%, rgba(3,4,6,.68) 78%);
}

header{
  position:sticky;
  top:0;
  z-index:30;
  width:100%;
  padding:1rem 1.25rem;
  border-bottom:1px solid rgba(160,220,255,.12);
  background:rgba(5,7,11,.78);
  backdrop-filter:blur(16px) saturate(120%);
  box-shadow:0 12px 30px rgba(0,0,0,.28);
}

.logo{
  position:relative;
  display:flex;
  align-items:center;
  gap:.8rem;
  font-size:.76rem;
  font-weight:700;
  letter-spacing:.28em;
  text-transform:uppercase;
  color:var(--muted);
}

.logo::before{
  content:"";
  width:42px;
  height:42px;
  border-radius:15px;
  background:
    radial-gradient(circle at 35% 30%, rgba(255,255,255,.95) 0 9%, transparent 10%),
    linear-gradient(145deg, rgba(126,247,223,.98), rgba(121,167,255,.92));
  box-shadow:0 0 0 1px rgba(255,255,255,.12), 0 10px 24px rgba(121,167,255,.25), inset 0 1px 0 rgba(255,255,255,.45);
  transform:rotate(45deg);
}

.logo span{color:var(--accent)}

.user-info{
  margin-left:auto;
  display:flex;
  align-items:center;
  gap:.6rem;
  color:var(--muted);
}

.btn-sm,
.btn-primary,
.nlp-bar button,
.confirm-btn,
.restart-btn{
  border-radius:999px;
  border:1px solid rgba(160,220,255,.16);
  background:linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.03));
  box-shadow:0 6px 18px rgba(0,0,0,.24), inset 0 1px 0 rgba(255,255,255,.12);
}

.btn-sm:hover,
.btn-primary:hover,
.nlp-bar button:hover,
.confirm-btn:hover,
.restart-btn:hover{
  border-color:rgba(126,247,223,.5);
}

#authScreen{
  width:100%;
  max-width:1180px;
  padding:2rem 1rem 4rem;
  margin:0 auto;
  display:grid;
  grid-template-columns:minmax(280px,1fr) minmax(320px,420px);
  gap:1.5rem;
  align-items:stretch;
}

#authScreen::before{
  content:"";
  position:absolute;
  inset:0;
  pointer-events:none;
}

.boot-hero,
.session-hero,
#authScreen .auth-card,
main{
  position:relative;
  overflow:hidden;
  border:1px solid rgba(160,220,255,.16);
  background:linear-gradient(180deg, rgba(17,26,38,.88), rgba(8,12,19,.88));
  box-shadow:0 26px 60px rgba(0,0,0,.36), inset 0 1px 0 rgba(255,255,255,.06);
  backdrop-filter:blur(18px) saturate(120%);
}

.boot-hero{
  border-radius:30px;
  padding:1.5rem;
  display:flex;
  flex-direction:column;
  justify-content:space-between;
  gap:1.25rem;
}

.boot-hero::before,
.session-hero::before,
#authScreen .auth-card::before,
main::before{
  content:"";
  position:absolute;
  inset:0;
  background:linear-gradient(135deg, rgba(126,247,223,.08), transparent 42%, rgba(121,167,255,.05));
  pointer-events:none;
}

.boot-kicker{
  font-size:.72rem;
  text-transform:uppercase;
  letter-spacing:.34em;
  color:var(--muted);
}

.boot-hero h1,
.session-hero h1{
  margin:.3rem 0 .65rem;
  font-size:clamp(2rem, 4vw, 3.5rem);
  line-height:.92;
  letter-spacing:-.05em;
  color:var(--text);
}

.boot-hero p,
.session-hero p{
  max-width:34rem;
  color:var(--muted);
  line-height:1.6;
}

.boot-orb{
  width:min(100%, 290px);
  aspect-ratio:1;
  margin:auto;
  border-radius:50%;
  background:
    radial-gradient(circle at 38% 32%, rgba(255,255,255,.95) 0 9%, rgba(255,255,255,.5) 9% 11%, transparent 12%),
    radial-gradient(circle at 50% 50%, rgba(126,247,223,.45), rgba(121,167,255,.22) 28%, rgba(5,7,11,.02) 64%, rgba(5,7,11,.98) 100%);
  box-shadow:0 0 0 1px rgba(255,255,255,.1), 0 0 42px rgba(126,247,223,.14), 0 0 84px rgba(121,167,255,.08), inset 0 0 80px rgba(255,255,255,.05);
  position:relative;
}

.boot-orb::before{
  content:"";
  position:absolute;
  inset:22%;
  border-radius:22px;
  transform:rotate(45deg);
  background:linear-gradient(145deg, rgba(255,255,255,.9), rgba(126,247,223,.95));
  box-shadow:0 0 0 1px rgba(255,255,255,.2), 0 14px 22px rgba(0,0,0,.22);
}

.boot-orb::after{
  content:"";
  position:absolute;
  inset:14%;
  border:1px solid rgba(255,255,255,.12);
  border-radius:50%;
}

.boot-ports,
.menu-pips{
  display:flex;
  justify-content:center;
  gap:.45rem;
}

.boot-ports span,
.menu-pips span{
  width:12px;
  height:12px;
  border-radius:50%;
  background:linear-gradient(180deg, rgba(126,247,223,.95), rgba(121,167,255,.7));
  box-shadow:0 0 14px rgba(126,247,223,.16);
}

#authScreen .auth-card{
  width:100%;
  border-radius:30px;
  padding:1.8rem;
}

#authScreen .auth-card h2,
.results-header,
.card-title,
.card-genre,
.history-item strong{
  letter-spacing:.04em;
}

.field label,
.auth-switch,
.err-msg,
.card-desc,
.card-meta,
.history-item,
.progress-wrap,
.session-hero p{
  color:var(--muted);
}

.field input,
.nlp-bar input{
  border-radius:999px;
  border:1px solid rgba(160,220,255,.16);
  background:rgba(255,255,255,.04);
  color:var(--text);
}

.field input:focus,
.nlp-bar input:focus{
  border-color:rgba(126,247,223,.6);
  box-shadow:0 0 0 3px rgba(126,247,223,.12);
}

.btn-primary,
.nlp-bar button,
.confirm-btn{
  background:linear-gradient(180deg, rgba(126,247,223,.92), rgba(121,167,255,.88));
  color:#061018;
  font-weight:700;
}

.btn-primary:hover,
.nlp-bar button:hover,
.confirm-btn:hover{
  background:linear-gradient(180deg, rgba(145,255,233,.98), rgba(132,177,255,.94));
}

#appScreen{
  width:100%;
  padding:0 1rem 3rem;
}

main{
  width:100%;
  max-width:1180px;
  margin:1.5rem auto 0;
  padding:1.2rem;
  border-radius:34px;
}

.session-hero{
  border-radius:26px;
  padding:1.15rem 1.2rem;
  margin-bottom:1rem;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:1rem;
}

.session-hero h1{
  font-size:1.35rem;
  margin:.25rem 0 .3rem;
}

.session-hero p{
  max-width:42rem;
  font-size:.88rem;
}

.nlp-bar{
  padding:.55rem;
  border-radius:999px;
  border:1px solid rgba(160,220,255,.16);
  background:rgba(255,255,255,.03);
  box-shadow:0 10px 28px rgba(0,0,0,.18);
}

.nlp-bar input{
  padding:.78rem 1rem;
  font-size:.92rem;
  background:transparent;
  border:none;
  box-shadow:none;
}

.nlp-bar button{
  min-width:130px;
}

.progress-wrap{
  margin:1rem 0 1.25rem;
  padding:.8rem 1rem;
  border-radius:20px;
  border:1px solid rgba(160,220,255,.12);
  background:rgba(255,255,255,.03);
}

.progress-bar{
  height:6px;
  background:rgba(255,255,255,.06);
}

.progress-fill{
  background:linear-gradient(90deg, rgba(126,247,223,.95), rgba(121,167,255,.95));
}

.chat{
  gap:1.1rem;
}

.bubble-wrap{
  gap:.7rem;
}

.avatar{
  background:linear-gradient(145deg, rgba(126,247,223,.95), rgba(121,167,255,.92));
  color:#08111a;
  box-shadow:0 8px 20px rgba(0,0,0,.18);
}

.bubble,
.game-card,
.history-item,
.nlp-banner{
  border-radius:24px;
  background:rgba(255,255,255,.04);
  border:1px solid rgba(160,220,255,.14);
}

.bubble-wrap.user .bubble{
  background:linear-gradient(180deg, rgba(121,167,255,.18), rgba(126,247,223,.1));
  color:var(--text);
}

.chip{
  background:rgba(255,255,255,.04);
  border-radius:999px;
  border-color:rgba(160,220,255,.14);
}

.chip.selected{
  background:rgba(121,167,255,.2);
  color:var(--text);
}

.game-grid{
  grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
}

.game-card:hover,
.chip:hover,
.restart-btn:hover,
.btn-sm:hover{
  transform:translateY(-2px);
}

.score-hi,
.score-mid,
.score-lo{
  border:1px solid rgba(255,255,255,.08);
}

.score-hi{background:rgba(16,185,129,.12);color:#7ef7df}
.score-mid{background:rgba(245,158,11,.12);color:#ffd58b}
.score-lo{background:rgba(248,113,113,.12);color:#ff9c9c}

.restart-wrap{
  margin-top:2rem;
}

.history-panel{
  margin-top:1.2rem;
}

.history-item{
  padding:.9rem 1rem;
}

@media(max-width:900px){
  #authScreen{grid-template-columns:1fr;}
  main{padding:1rem;}
}

@media(max-width:500px){
  .session-hero,
  .boot-hero{padding:1rem;}
  .nlp-bar{border-radius:26px;}
  .nlp-bar button{min-width:auto;}
  .game-grid{grid-template-columns:1fr}
}
</style>
</head>
<body>

<!-- ── Header ── -->
<header>
  <div class="logo">Game Finder</div>
  <div class="user-info" id="userInfo" style="display:none">
    <span id="userLabel"></span>
    <button class="btn-sm" onclick="showHistory()">History</button>
    <button class="btn-sm danger" onclick="doLogout()">Log out</button>
  </div>
</header>

<!-- ── Auth screen ── -->
<div id="authScreen">
  <section class="boot-hero">
    <div>
      <div class="boot-kicker">Startup Menu</div>
      <h1>Game Finder</h1>
      <p>Discover your next favorite game with the help of personalized recommendations.</p>
    </div>
    <div class="boot-orb" aria-hidden="true"></div>
    <div class="boot-ports" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
  </section>

  <div class="auth-card" id="loginCard">
    <h2>Press Start</h2>
    <div class="field"><label>Username</label><input id="loginUser" type="text" autocomplete="username" placeholder="your_username"></div>
    <div class="field"><label>Password</label><input id="loginPass" type="password" autocomplete="current-password" placeholder="••••••••"></div>
    <div class="err-msg" id="loginErr"></div>
    <button class="btn-primary" onclick="doLogin()">Sign in</button>
    <div class="auth-switch">No profile yet? <a onclick="showRegister()">Create one</a></div>
  </div>

  <div class="auth-card" id="registerCard" style="display:none">
    <h2>Load a Profile</h2>
    <div class="field"><label>Username</label><input id="regUser" type="text" autocomplete="username" placeholder="your_username"></div>
    <div class="field"><label>Password (min 8 chars)</label><input id="regPass" type="password" autocomplete="new-password" placeholder="••••••••"></div>
    <div class="err-msg" id="regErr"></div>
    <button class="btn-primary" onclick="doRegister()">Create account</button>
    <div class="auth-switch">Already set up? <a onclick="showLogin()">Return to sign in</a></div>
  </div>
</div>

<!-- ── App screen ── -->
<div id="appScreen">
  <main>
    <section class="session-hero">
      <div>
        <div class="boot-kicker">Session Active</div>
        <h1>Game Finder</h1>
        <p>Use the search bar to quickly find games that match your preferences, or chat with Game Finder for a more personalized experience.</p>
      </div>
      <div class="menu-pips" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
    </section>

    <!-- Free-text NLP bar -->
    <div class="nlp-bar">
      <input id="nlpInput" type="text" placeholder='Describe what you are looking for — e.g. "spooky solo horror on PC under $30"' />
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
  const headers = {'Content-Type':'application/json'};
  if (window.sessionToken) {
    headers['X-GameFinder-Session'] = window.sessionToken;
  }
  const opts = { method, headers, credentials:'same-origin' };
  if (method !== 'GET' && window.sessionToken) {
    body = body || {};
    body.session_token = window.sessionToken;
  }
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
  setTimeout(startChat, 0);
}

function showAuthScreen(message='') {
  $('authScreen').style.display = 'flex';
  $('appScreen').style.display  = 'none';
  $('userInfo').style.display   = 'none';
  if (message) {
    $('loginErr').textContent = message;
  }
}

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function apiWithRetry(path, method='POST', body=null, attempts=3, pauseMs=120) {
  let last = null;
  for (let i = 0; i < attempts; i++) {
    const data = await api(path, method, body);
    if (data.error !== 'unauthorised') return data;
    last = data;
    if (i < attempts - 1) await delay(pauseMs * (i + 1));
  }
  return last;
}

async function doLogin() {
  $('loginErr').textContent = '';
  const d = await api('/api/login', 'POST', {
    username: $('loginUser').value,
    password: $('loginPass').value
  });
  if (d.error) { $('loginErr').textContent = d.error; return; }
  window.sessionToken = d.token || '';
  onAuthed(d.username);
}

async function doRegister() {
  $('regErr').textContent = '';
  const d = await api('/api/register', 'POST', {
    username: $('regUser').value,
    password: $('regPass').value
  });
  if (d.error) { $('regErr').textContent = d.error; return; }
  window.sessionToken = d.token || '';
  onAuthed(d.username);
}

async function doLogout() {
  window.sessionToken = '';
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
  if (prefs.developer)  labels.push('Developer: ' + prefs.developer);
  if (prefs.publisher) labels.push('Publisher: ' + prefs.publisher);
  if (prefs.series)     labels.push('Series: ' + prefs.series);
  if (prefs.seed_games) labels.push('Seed game: ' + prefs.seed_games.join(', '));
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
  const res = await api('/api/answer', 'POST', { index: 6, answers, search_text: text });
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
  const data = await apiWithRetry('/api/answer', 'POST', { index: state.index, answers: state.answers });
  if (data.error === 'unauthorised') { showAuthScreen('Your session expired. Please sign in again.'); return; }
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
    const score = g.metacritic_score || 0;
    const match = Math.max(0, Math.min(99, g.match_percent || 0));
    const price = g.launch_price === 0 ? 'Free' : `$${Number(g.launch_price).toFixed(2)}`;
    const tags = (g.tags||[]).slice(0,4).map(t=>`<span class="tag">${t}</span>`).join('');
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
        <span>🎯 ${match}% match</span>
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
  const data = await apiWithRetry('/api/start', 'POST', null, 3, 150);
  if (data.error === 'unauthorised') {
    showAuthScreen('Your session is not ready yet. Please sign in again.');
    return;
  }
  state.index   = data.index;
  state.total   = data.total;
  state.currentQ = data.question;
  setProgress(0, data.total);
  await addBotBubble("Hey! I'm Game Finder 🎮 Answer a few questions and I'll find your perfect game — or use the search bar above to describe what you want.");
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
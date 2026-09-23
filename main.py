# bot.py
import asyncio
import logging
import os
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque

import aiosqlite
from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode, ChatMemberStatus
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError
from aiogram.filters import BaseFilter, Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    ChatMemberUpdated,
    FSInputFile,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    Message,
)

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ==========================================================
# КОНФИГ
# ==========================================================
BOT_TOKEN = os.getenv("BOT_TOKEN")
SUPER_ADMIN_ID = int(os.getenv("SUPER_ADMIN_ID", "0"))

LOG_GROUP_ID = int(os.getenv("LOG_GROUP_ID", "0")) or None
LOG_GROUP_URL = os.getenv("LOG_GROUP_URL", "")

EVIDENCE_GROUP_ID = int(os.getenv("EVIDENCE_GROUP_ID", "0")) or None
EVIDENCE_GROUP_URL = os.getenv("EVIDENCE_GROUP_URL", "")

DB_PATH = os.getenv("DB_PATH", "data/antiscam.db")
TEMPLATES_DIR = os.getenv("TEMPLATES_DIR", "templates")
TEMPLATES_CACHE_DIR = os.path.join(TEMPLATES_DIR, "_cache")

if not BOT_TOKEN:
    raise SystemExit("Не задана переменная окружения BOT_TOKEN")
if not SUPER_ADMIN_ID:
    raise SystemExit("Не задана переменная окружения SUPER_ADMIN_ID")

os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(TEMPLATES_CACHE_DIR, exist_ok=True)

BOT_NAME = "Скам база XkeyO"
MAX_CAPTION = 1024

RESOLVED_LOG_ID = LOG_GROUP_ID
RESOLVED_EVIDENCE_ID = EVIDENCE_GROUP_ID

# ==========================================================
# СТАТУСЫ
# ==========================================================
STATUS_SCAM = "scam"
STATUS_SUSPICIOUS = "suspicious"
STATUS_NORMAL = "normal"
STATUS_VERIFIED = "verified"
STATUS_BANNED = "banned"

STATUS_LABELS = {
    STATUS_SCAM: "🚨 Скамер",
    STATUS_SUSPICIOUS: "⚠️ Подозрительный",
    STATUS_NORMAL: "✅ Обычный",
    STATUS_VERIFIED: "🛡 Проверенный",
    STATUS_BANNED: "⛔ Забанен везде",
}

STATUS_IMAGES = {
    STATUS_SCAM: "scam.png",
    STATUS_SUSPICIOUS: "sus.png",
    STATUS_NORMAL: "def.png",
    STATUS_VERIFIED: "proof.png",
    STATUS_BANNED: "scam.png",
}

# ==========================================================
# РОЛИ
# ==========================================================
ROLE_SUPER = "super"
ROLE_ADMIN = "admin"
ROLE_MODERATOR = "moderator"
ROLE_USER = "user"

ROLE_LABELS = {
    ROLE_SUPER: "👑 Главный админ",
    ROLE_ADMIN: "🛠 Админ",
    ROLE_MODERATOR: "🛡 Модератор",
    ROLE_USER: "👤 Пользователь",
}

ROLE_IMAGES = {
    ROLE_SUPER: "admin.png",
    ROLE_ADMIN: "admin.png",
    ROLE_MODERATOR: "moderator.png",
    ROLE_USER: "def.png",
}

IMAGE_START = "start.png"
IMAGE_HELLO = "hello.png"
IMAGE_NORMAL_FALLBACK = "def.png"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("antiscam")


# ==========================================================
# АНТИСПАМ
# ==========================================================
LINK_REGEX = re.compile(r"(https?://\S+|t\.me/\S+|www\.\S+)", re.IGNORECASE)
USERNAME_ONLY_REGEX = re.compile(r"^@[A-Za-z0-9_]{5,32}$")
CAPS_MIN_LEN = 10
CAPS_RATIO = 0.7
FLOOD_WINDOW = 60
FLOOD_LIMIT = 10
FLOOD_MUTE_SECONDS = 300

flood_store = defaultdict(lambda: defaultdict(deque))


# ==========================================================
# КЕШ
# ==========================================================
_REQ_CACHE = {}
_REQ_CACHE_TTL = 120
_ADMIN_CACHE = {}
_ADMIN_CACHE_TTL = 60


def _cache_get(store, key, ttl):
    v = store.get(key)
    if not v:
        return None
    ts, val = v
    if (time.time() - ts) > ttl:
        return None
    return val


def _cache_set(store, key, val):
    store[key] = (time.time(), val)


def invalidate_admin_cache(chat_id=None):
    if chat_id is None:
        _ADMIN_CACHE.clear()
    else:
        for k in list(_ADMIN_CACHE.keys()):
            if k[0] == chat_id:
                _ADMIN_CACHE.pop(k, None)


def invalidate_req_cache(chat_id=None):
    if chat_id is None:
        _REQ_CACHE.clear()
    else:
        _REQ_CACHE.pop(chat_id, None)


# ==========================================================
# ЛОКАЛЬНЫЕ ПРОВЕРКИ
# ==========================================================
def has_link(text):
    if not text:
        return False
    cleaned = re.sub(r"@[A-Za-z0-9_]{5,32}", "", text)
    return bool(LINK_REGEX.search(cleaned))


def is_caps(text):
    if not text:
        return False
    letters = [c for c in text if c.isalpha()]
    if len(letters) < CAPS_MIN_LEN:
        return False
    upper = sum(1 for c in letters if c.isupper())
    return (upper / len(letters)) >= CAPS_RATIO


def normalize_text(text):
    if not text:
        return ""
    return re.sub(r"\s+", " ", text.strip().lower())


def message_fingerprint(message):
    text = message.text or message.caption
    if text:
        return "t:" + normalize_text(text)
    if message.photo:
        return "photo:" + message.photo[-1].file_unique_id
    if message.video:
        return "video:" + message.video.file_unique_id
    if message.animation:
        return "anim:" + message.animation.file_unique_id
    if message.sticker:
        return "sticker:" + message.sticker.file_unique_id
    if message.voice:
        return "voice:" + message.voice.file_unique_id
    if message.video_note:
        return "vnote:" + message.video_note.file_unique_id
    if message.audio:
        return "audio:" + message.audio.file_unique_id
    if message.document:
        return "doc:" + message.document.file_unique_id
    if message.contact:
        return "contact:" + (message.contact.phone_number or "")
    if message.location:
        return "loc:{}:{}".format(message.location.latitude, message.location.longitude)
    if message.venue:
        return "venue:" + message.venue.title
    if message.poll:
        return "poll:" + message.poll.question
    if message.dice:
        return "dice:{}:{}".format(message.dice.emoji, message.dice.value)
    return "unknown"


def is_flood(chat_id, user_id, fingerprint):
    now = time.time()
    bucket = flood_store[chat_id][user_id]
    while bucket and (now - bucket[0][0]) > FLOOD_WINDOW:
        bucket.popleft()
    same = sum(1 for ts, t in bucket if t == fingerprint)
    bucket.append((now, fingerprint))
    return same >= FLOOD_LIMIT


def clear_flood(chat_id, user_id):
    flood_store[chat_id].pop(user_id, None)


def is_command(message):
    text = message.text or message.caption or ""
    if text.startswith("/"):
        return True
    entities = message.entities or message.caption_entities or []
    for ent in entities:
        if ent.type == "bot_command" and ent.offset == 0:
            return True
    return False


# ==========================================================
# БЕЗОПАСНЫЙ ANSWER
# ==========================================================
async def safe_answer(cb: CallbackQuery, text: str = None, alert: bool = False):
    try:
        if text:
            await cb.answer(text, show_alert=alert)
        else:
            await cb.answer()
    except TelegramBadRequest as e:
        log.debug("safe_answer: %s", e)


# ==========================================================
# КАРТИНКИ
# ==========================================================
def template_path(filename):
    return os.path.join(TEMPLATES_DIR, filename)


def template_exists(filename):
    return os.path.isfile(template_path(filename))


def compressed_template_path(filename):
    return os.path.join(TEMPLATES_CACHE_DIR, filename)


def compress_image(src, dst, max_side=1280, quality=85):
    if not HAS_PIL:
        return src
    try:
        img = Image.open(src).convert("RGB")
        w, h = img.size
        if max(w, h) > max_side:
            if w >= h:
                new_size = (max_side, int(h * max_side / w))
            else:
                new_size = (int(w * max_side / h), max_side)
            img = img.resize(new_size, Image.LANCZOS)
        img.save(dst, "JPEG", quality=quality, optimize=True)
        return dst
    except Exception as e:
        log.warning("Не смог сжать %s: %s", src, e)
        return src


def prepare_image(filename):
    src = template_path(filename)
    if not os.path.isfile(src):
        log.warning("Шаблон не найден: %s", src)
        return None
    dst = compressed_template_path(filename)
    if not os.path.isfile(dst) or os.path.getmtime(src) > os.path.getmtime(dst):
        return compress_image(src, dst)
    return dst


def _cut_caption(text):
    if len(text) <= MAX_CAPTION:
        return text
    return text[:MAX_CAPTION - 20] + "\n\n<i>…(сокращено)</i>"


# ==========================================================
# ФИЛЬТРЫ
# ==========================================================
class IsPrivateChat(BaseFilter):
    async def __call__(self, event):
        chat = getattr(event, "chat", None)
        if chat is None and hasattr(event, "message"):
            chat = event.message.chat
        return bool(chat and chat.type == "private")


class IsGroupChat(BaseFilter):
    async def __call__(self, event):
        chat = getattr(event, "chat", None)
        if chat is None and hasattr(event, "message"):
            chat = event.message.chat
        return bool(chat and chat.type in ("group", "supergroup"))


# ==========================================================
# БАЗА ДАННЫХ
# ==========================================================
async def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id      INTEGER PRIMARY KEY,
            username     TEXT,
            full_name    TEXT,
            status       TEXT DEFAULT 'normal',
            role         TEXT DEFAULT 'user',
            reason       TEXT,
            evidence_url TEXT,
            updated_at   TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS username_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            username   TEXT NOT NULL,
            seen_at    TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS appeals (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            text       TEXT,
            photo_id   TEXT,
            video_id   TEXT,
            status     TEXT DEFAULT 'pending',
            handled_by INTEGER,
            created_at TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS action_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER,
            action     TEXT,
            target_id  INTEGER,
            payload    TEXT,
            created_at TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            chat_id   INTEGER PRIMARY KEY,
            title     TEXT,
            added_at  TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS media_cache (
            key      TEXT PRIMARY KEY,
            file_id  TEXT,
            added_at TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS chat_settings (
            chat_id          INTEGER PRIMARY KEY,
            welcome_text     TEXT,
            welcome_enabled  INTEGER DEFAULT 1,
            welcome_image    TEXT,
            antispam_links   INTEGER DEFAULT 1,
            antispam_caps    INTEGER DEFAULT 1,
            antispam_flood   INTEGER DEFAULT 1,
            updated_at       TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS required_chats (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id      INTEGER NOT NULL,
            req_chat_id  INTEGER,
            req_username TEXT,
            title        TEXT,
            link         TEXT,
            expire_at    TEXT,
            added_at     TEXT,
            added_by     INTEGER
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id  INTEGER,
            target_id    INTEGER,
            text         TEXT,
            photo_id     TEXT,
            video_id     TEXT,
            status       TEXT DEFAULT 'pending',
            handled_by   INTEGER,
            created_at   TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            kind         TEXT NOT NULL,
            ref_id       INTEGER NOT NULL,
            user_id      INTEGER NOT NULL,
            moderator_id INTEGER,
            status       TEXT DEFAULT 'open',
            created_at   TEXT
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS conv_messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            conv_id    INTEGER NOT NULL,
            from_id    INTEGER NOT NULL,
            is_mod     INTEGER DEFAULT 0,
            text       TEXT,
            photo_id   TEXT,
            video_id   TEXT,
            created_at TEXT
        )
        """)
        await db.commit()
        await _migrate_db(db)
    log.info("База данных готова: %s", DB_PATH)


async def _table_columns(db, table_name):
    cur = await db.execute("PRAGMA table_info({})".format(table_name))
    rows = await cur.fetchall()
    return {row[1] for row in rows}


async def _add_column_if_missing(db, table, column, definition):
    cols = await _table_columns(db, table)
    if column not in cols:
        log.info("Миграция: %s.%s", table, column)
        await db.execute(
            "ALTER TABLE {} ADD COLUMN {} {}".format(table, column, definition)
        )


async def _migrate_db(db):
    # users
    await _add_column_if_missing(db, "users", "username", "TEXT")
    await _add_column_if_missing(db, "users", "full_name", "TEXT")
    await _add_column_if_missing(db, "users", "status", "TEXT DEFAULT 'normal'")
    await _add_column_if_missing(db, "users", "role", "TEXT DEFAULT 'user'")
    await _add_column_if_missing(db, "users", "reason", "TEXT")
    await _add_column_if_missing(db, "users", "evidence_url", "TEXT")
    await _add_column_if_missing(db, "users", "updated_at", "TEXT")

    # appeals
    await _add_column_if_missing(db, "appeals", "user_id", "INTEGER")
    await _add_column_if_missing(db, "appeals", "text", "TEXT")
    await _add_column_if_missing(db, "appeals", "photo_id", "TEXT")
    await _add_column_if_missing(db, "appeals", "video_id", "TEXT")
    await _add_column_if_missing(db, "appeals", "status", "TEXT DEFAULT 'pending'")
    await _add_column_if_missing(db, "appeals", "handled_by", "INTEGER")
    await _add_column_if_missing(db, "appeals", "created_at", "TEXT")

    # reports
    await _add_column_if_missing(db, "reports", "reporter_id", "INTEGER")
    await _add_column_if_missing(db, "reports", "target_id", "INTEGER")
    await _add_column_if_missing(db, "reports", "text", "TEXT")
    await _add_column_if_missing(db, "reports", "photo_id", "TEXT")
    await _add_column_if_missing(db, "reports", "video_id", "TEXT")
    await _add_column_if_missing(db, "reports", "status", "TEXT DEFAULT 'pending'")
    await _add_column_if_missing(db, "reports", "handled_by", "INTEGER")
    await _add_column_if_missing(db, "reports", "created_at", "TEXT")

    # chat_settings — расширение
    await _add_column_if_missing(db, "chat_settings", "welcome_text", "TEXT")
    await _add_column_if_missing(db, "chat_settings", "welcome_enabled", "INTEGER DEFAULT 1")
    await _add_column_if_missing(db, "chat_settings", "welcome_image", "TEXT")
    await _add_column_if_missing(db, "chat_settings", "antispam_links", "INTEGER DEFAULT 1")
    await _add_column_if_missing(db, "chat_settings", "antispam_caps", "INTEGER DEFAULT 1")
    await _add_column_if_missing(db, "chat_settings", "antispam_flood", "INTEGER DEFAULT 1")
    await _add_column_if_missing(db, "chat_settings", "updated_at", "TEXT")

    # required_chats
    await _add_column_if_missing(db, "required_chats", "chat_id", "INTEGER")
    await _add_column_if_missing(db, "required_chats", "req_chat_id", "INTEGER")
    await _add_column_if_missing(db, "required_chats", "req_username", "TEXT")
    await _add_column_if_missing(db, "required_chats", "title", "TEXT")
    await _add_column_if_missing(db, "required_chats", "link", "TEXT")
    await _add_column_if_missing(db, "required_chats", "expire_at", "TEXT")
    await _add_column_if_missing(db, "required_chats", "added_at", "TEXT")
    await _add_column_if_missing(db, "required_chats", "added_by", "INTEGER")

    # conversations
    await _add_column_if_missing(db, "conversations", "kind", "TEXT")
    await _add_column_if_missing(db, "conversations", "ref_id", "INTEGER")
    await _add_column_if_missing(db, "conversations", "user_id", "INTEGER")
    await _add_column_if_missing(db, "conversations", "moderator_id", "INTEGER")
    await _add_column_if_missing(db, "conversations", "status", "TEXT DEFAULT 'open'")
    await _add_column_if_missing(db, "conversations", "created_at", "TEXT")

    # conv_messages
    await _add_column_if_missing(db, "conv_messages", "conv_id", "INTEGER")
    await _add_column_if_missing(db, "conv_messages", "from_id", "INTEGER")
    await _add_column_if_missing(db, "conv_messages", "is_mod", "INTEGER DEFAULT 0")
    await _add_column_if_missing(db, "conv_messages", "text", "TEXT")
    await _add_column_if_missing(db, "conv_messages", "photo_id", "TEXT")
    await _add_column_if_missing(db, "conv_messages", "video_id", "TEXT")
    await _add_column_if_missing(db, "conv_messages", "created_at", "TEXT")

    await db.execute("UPDATE users SET role='user' WHERE role IS NULL")
    await db.execute("UPDATE users SET role='super' WHERE user_id=?",
                     (SUPER_ADMIN_ID,))
    await db.commit()


# ---------- USERS ----------
async def upsert_user(user_id, username=None, full_name=None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT role, username FROM users WHERE user_id=?", (user_id,))
        existing = await cur.fetchone()
        if existing and existing["role"]:
            role = existing["role"]
            if user_id == SUPER_ADMIN_ID:
                role = ROLE_SUPER
        else:
            role = ROLE_SUPER if user_id == SUPER_ADMIN_ID else ROLE_USER

        old_username = existing["username"] if existing else None

        await db.execute("""
            INSERT INTO users (user_id, username, full_name, status, role, updated_at)
            VALUES (?, ?, ?, 'normal', ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username=COALESCE(excluded.username, users.username),
                full_name=COALESCE(excluded.full_name, users.full_name),
                role=excluded.role,
                updated_at=excluded.updated_at
        """, (user_id, username, full_name, role, datetime.utcnow().isoformat()))

        # Запоминаем историю username
        if username and username != old_username:
            await db.execute("""
                INSERT INTO username_history (user_id, username, seen_at)
                VALUES (?, ?, ?)
            """, (user_id, username, datetime.utcnow().isoformat()))

        await db.commit()


async def get_user(user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def get_user_by_username(username):
    if not username:
        return None
    username = username.lstrip("@")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # сначала ищем в текущих
        cur = await db.execute(
            "SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (username,))
        row = await cur.fetchone()
        if row:
            return dict(row)
        # потом в истории — это позволяет находить юзера после смены @username
        cur = await db.execute("""
            SELECT u.* FROM users u
            JOIN username_history h ON h.user_id = u.user_id
            WHERE LOWER(h.username)=LOWER(?)
            ORDER BY h.seen_at DESC
            LIMIT 1
        """, (username,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def get_user_role(user_id):
    if user_id == SUPER_ADMIN_ID:
        return ROLE_SUPER
    u = await get_user(user_id)
    return u["role"] if u and u.get("role") else ROLE_USER


async def set_user_role(user_id, role):
    if user_id == SUPER_ADMIN_ID:
        role = ROLE_SUPER
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO users (user_id, role, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                role=excluded.role,
                updated_at=excluded.updated_at
        """, (user_id, role, datetime.utcnow().isoformat()))
        await db.commit()


async def list_staff():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT user_id, role FROM users WHERE role IN ('super','admin','moderator')")
        return [dict(r) for r in await cur.fetchall()]


async def list_all_chats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT chat_id, title FROM chats")
        return [dict(r) for r in await cur.fetchall()]


async def set_status(user_id, status, reason=None, evidence_url=None,
                     username=None, full_name=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO users (user_id, username, full_name, status,
                               reason, evidence_url, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                status=excluded.status,
                reason=excluded.reason,
                evidence_url=excluded.evidence_url,
                username=COALESCE(excluded.username, users.username),
                full_name=COALESCE(excluded.full_name, users.full_name),
                updated_at=excluded.updated_at
        """, (user_id, username, full_name, status, reason, evidence_url,
              datetime.utcnow().isoformat()))
        await db.commit()


# ---------- APPEALS ----------
async def add_appeal(user_id, text, photo_id, video_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            INSERT INTO appeals (user_id, text, photo_id, video_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, text, photo_id, video_id, datetime.utcnow().isoformat()))
        await db.commit()
        return cur.lastrowid


async def get_appeal(appeal_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM appeals WHERE id=?", (appeal_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def set_appeal_status(appeal_id, status, handled_by=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE appeals SET status=?, handled_by=COALESCE(?, handled_by) WHERE id=?",
            (status, handled_by, appeal_id))
        await db.commit()


# ---------- REPORTS ----------
async def add_report(reporter_id, target_id, text, photo_id, video_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            INSERT INTO reports (reporter_id, target_id, text,
                                 photo_id, video_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (reporter_id, target_id, text, photo_id, video_id,
              datetime.utcnow().isoformat()))
        await db.commit()
        return cur.lastrowid


async def get_report(report_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM reports WHERE id=?", (report_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def set_report_status(report_id, status, handled_by=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE reports SET status=?, handled_by=COALESCE(?, handled_by) WHERE id=?",
            (status, handled_by, report_id))
        await db.commit()


# ---------- CONVERSATIONS ----------
async def create_conversation(kind, ref_id, user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            INSERT INTO conversations (kind, ref_id, user_id, created_at)
            VALUES (?, ?, ?, ?)
        """, (kind, ref_id, user_id, datetime.utcnow().isoformat()))
        await db.commit()
        return cur.lastrowid


async def get_conversation_by_ref(kind, ref_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM conversations WHERE kind=? AND ref_id=?",
            (kind, ref_id))
        row = await cur.fetchone()
        return dict(row) if row else None


async def get_conversation(conv_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM conversations WHERE id=?", (conv_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def claim_conversation(conv_id, moderator_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            UPDATE conversations SET moderator_id=?, status='open'
            WHERE id=? AND (moderator_id IS NULL OR moderator_id=?)
        """, (moderator_id, conv_id, moderator_id))
        await db.commit()
        return cur.rowcount > 0


async def close_conversation(conv_id):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE conversations SET status='closed' WHERE id=?",
                         (conv_id,))
        await db.commit()


async def add_conv_message(conv_id, from_id, is_mod, text, photo_id, video_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            INSERT INTO conv_messages (conv_id, from_id, is_mod, text,
                                       photo_id, video_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (conv_id, from_id, 1 if is_mod else 0, text, photo_id, video_id,
              datetime.utcnow().isoformat()))
        await db.commit()
        return cur.lastrowid


# ---------- LOG ----------
async def log_action(admin_id, action, target_id=None, payload=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO action_log (admin_id, action, target_id, payload, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (admin_id, action, target_id, payload,
              datetime.utcnow().isoformat()))
        await db.commit()


async def _resolve_group_id(bot: Bot, url_or_id, current):
    if current:
        return current
    if not url_or_id:
        return None
    m = re.search(r"t\.me/([A-Za-z0-9_]+)", url_or_id)
    if not m:
        return None
    username = m.group(1)
    try:
        chat = await bot.get_chat("@" + username)
        return chat.id
    except Exception as e:
        log.warning("Не смог получить chat_id по %s: %s", username, e)
        return None


async def send_log(bot: Bot, text: str):
    global RESOLVED_LOG_ID
    if not RESOLVED_LOG_ID:
        RESOLVED_LOG_ID = await _resolve_group_id(bot, LOG_GROUP_URL, None)
    if not RESOLVED_LOG_ID:
        return
    try:
        await bot.send_message(RESOLVED_LOG_ID, text,
                                disable_web_page_preview=True)
    except Exception as e:
        log.warning("send_log: %s", e)


async def send_evidence(bot: Bot, report: dict, target: dict, status: str):
    global RESOLVED_EVIDENCE_ID
    if not RESOLVED_EVIDENCE_ID:
        RESOLVED_EVIDENCE_ID = await _resolve_group_id(bot, EVIDENCE_GROUP_URL, None)
    if not RESOLVED_EVIDENCE_ID:
        log.warning("Evidence channel не задан")
        return

    tid = target.get("user_id") or report.get("target_id")
    username = target.get("username")
    full_name = target.get("full_name") or "—"

    if username:
        profile_link = "https://t.me/" + username
    else:
        profile_link = "tg://user?id={}".format(tid)

    header = (
        STATUS_LABELS[status] + "\n"
        "👤 Имя: <b>" + str(full_name) + "</b>\n"
        "🆔 ID: <code>" + str(tid) + "</code>\n"
        "🔗 Юзернейм: @" + (username or "—") + "\n"
        "👤 Профиль: <a href=\"" + profile_link + "\">открыть</a>\n"
        "📝 Жалоба от: <code>" + str(report.get("reporter_id")) + "</code>\n"
        "💬 Текст: " + (report.get("text") or "—")
    )

    try:
        if report.get("photo_id"):
            await bot.send_photo(RESOLVED_EVIDENCE_ID, report["photo_id"],
                                  caption=header)
        elif report.get("video_id"):
            await bot.send_video(RESOLVED_EVIDENCE_ID, report["video_id"],
                                  caption=header)
        else:
            await bot.send_message(RESOLVED_EVIDENCE_ID, header,
                                    disable_web_page_preview=True)
    except Exception as e:
        log.warning("send_evidence: %s", e)


# ---------- CHATS / SETTINGS ----------
async def register_chat(chat_id, title):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO chats (chat_id, title, added_at) VALUES (?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET title=excluded.title
        """, (chat_id, title, datetime.utcnow().isoformat()))
        await db.commit()


async def get_chat_settings(chat_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM chat_settings WHERE chat_id=?",
                                (chat_id,))
        row = await cur.fetchone()
        if row:
            d = dict(row)
            # Значения по умолчанию для старых записей
            for k, v in (("antispam_links", 1), ("antispam_caps", 1),
                          ("antispam_flood", 1), ("welcome_enabled", 1)):
                if d.get(k) is None:
                    d[k] = v
            return d
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO chat_settings
                (chat_id, welcome_text, welcome_enabled,
                 antispam_links, antispam_caps, antispam_flood, updated_at)
            VALUES (?, NULL, 1, 1, 1, 1, ?)
        """, (chat_id, datetime.utcnow().isoformat()))
        await db.commit()
    return {
        "chat_id": chat_id, "welcome_text": None, "welcome_enabled": 1,
        "welcome_image": None,
        "antispam_links": 1, "antispam_caps": 1, "antispam_flood": 1,
    }


async def set_welcome_text(chat_id, text):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO chat_settings (chat_id, welcome_text, welcome_enabled, updated_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                welcome_text=excluded.welcome_text,
                updated_at=excluded.updated_at
        """, (chat_id, text, datetime.utcnow().isoformat()))
        await db.commit()


async def set_welcome_image(chat_id, file_id):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO chat_settings (chat_id, welcome_image, welcome_enabled, updated_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                welcome_image=excluded.welcome_image,
                updated_at=excluded.updated_at
        """, (chat_id, file_id, datetime.utcnow().isoformat()))
        await db.commit()


async def toggle_chat_setting(chat_id, key):
    """key in: welcome_enabled, antispam_links, antispam_caps, antispam_flood."""
    if key not in ("welcome_enabled", "antispam_links",
                   "antispam_caps", "antispam_flood"):
        return None
    s = await get_chat_settings(chat_id)
    new_val = 0 if s.get(key) else 1
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE chat_settings SET {}=?, updated_at=? WHERE chat_id=?".format(key),
            (new_val, datetime.utcnow().isoformat(), chat_id))
        await db.commit()
    return new_val


# ---------- MEDIA CACHE ----------
async def get_cached_file_id(key):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT file_id FROM media_cache WHERE key=?", (key,))
        row = await cur.fetchone()
        return row[0] if row else None


async def cache_file_id(key, file_id):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO media_cache (key, file_id, added_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET file_id=excluded.file_id
        """, (key, file_id, datetime.utcnow().isoformat()))
        await db.commit()


async def delete_cached_file_id(key):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM media_cache WHERE key=?", (key,))
        await db.commit()


# ---------- REQUIRED CHATS ----------
async def add_required_chat(chat_id, req_chat_id, req_username, title,
                            link, expire_at, added_by):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO required_chats
                (chat_id, req_chat_id, req_username, title, link,
                 expire_at, added_at, added_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (chat_id, req_chat_id, req_username, title, link,
              expire_at, datetime.utcnow().isoformat(), added_by))
        await db.commit()
    invalidate_req_cache(chat_id)


async def list_required_chats_db(chat_id):
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT * FROM required_chats
            WHERE chat_id = ? AND (expire_at IS NULL OR expire_at > ?)
            ORDER BY id ASC
        """, (chat_id, now))
        return [dict(r) for r in await cur.fetchall()]


async def list_required_chats(chat_id):
    cached = _cache_get(_REQ_CACHE, chat_id, _REQ_CACHE_TTL)
    if cached is not None:
        return cached
    reqs = await list_required_chats_db(chat_id)
    _cache_set(_REQ_CACHE, chat_id, reqs)
    return reqs


async def delete_required_chat(req_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT chat_id FROM required_chats WHERE id=?", (req_id,))
        row = await cur.fetchone()
        chat_id = row[0] if row else None
        await db.execute("DELETE FROM required_chats WHERE id=?", (req_id,))
        await db.commit()
    if chat_id is not None:
        invalidate_req_cache(chat_id)


async def cleanup_expired_required_chats():
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM required_chats WHERE expire_at IS NOT NULL AND expire_at <= ?",
            (now,))
        await db.commit()
    invalidate_req_cache()


# ==========================================================
# УТИЛИТЫ
# ==========================================================
def parse_duration(raw):
    raw = raw.strip().lower()
    if raw == "0":
        return None
    m = re.fullmatch(r"(\d+)([mhd]?)", raw)
    if not m:
        return None
    value = int(m.group(1))
    unit = m.group(2) or "h"
    if unit == "m":
        delta = timedelta(minutes=value)
    elif unit == "h":
        delta = timedelta(hours=value)
    elif unit == "d":
        delta = timedelta(days=value)
    else:
        return None
    return datetime.utcnow() + delta


def parse_link(raw):
    raw = raw.strip()
    if raw.startswith("@"):
        username = raw[1:]
        return username, "https://t.me/" + username
    m = re.fullmatch(r"(?:https?://)?t\.me/([A-Za-z0-9_]+)/?", raw)
    if m:
        username = m.group(1)
        return username, "https://t.me/" + username
    return None, None


async def get_chat_title(bot, username):
    try:
        chat = await bot.get_chat("@" + username)
        return chat.title or chat.full_name or ("@" + username)
    except Exception:
        return "@" + username


async def is_user_subscribed(bot, user_id, req):
    try:
        member = await bot.get_chat_member(
            req["req_chat_id"] or ("@" + req["req_username"]), user_id)
        return member.status in (ChatMemberStatus.CREATOR,
                                  ChatMemberStatus.ADMINISTRATOR,
                                  ChatMemberStatus.MEMBER)
    except TelegramBadRequest:
        return False
    except Exception as e:
        log.warning("Ошибка проверки подписки: %s", e)
        return False


async def check_user_all_subscriptions(bot, user_id, chat_id):
    reqs = await list_required_chats(chat_id)
    if not reqs:
        return []
    results = await asyncio.gather(
        *(is_user_subscribed(bot, user_id, r) for r in reqs),
        return_exceptions=False,
    )
    return [r for r, ok in zip(reqs, results) if not ok]


def user_mention(user):
    if user.username:
        return "@" + user.username
    return "<a href=\"tg://user?id=" + str(user.id) + "\">" + str(user.full_name) + "</a>"


def user_mention_by_id(user_id, username=None, full_name=None):
    if username:
        return "@" + username
    if full_name:
        return "<a href=\"tg://user?id=" + str(user_id) + "\">" + str(full_name) + "</a>"
    return "<a href=\"tg://user?id=" + str(user_id) + "\">ID " + str(user_id) + "</a>"


async def is_chat_admin(bot, chat_id, user_id):
    if user_id == SUPER_ADMIN_ID:
        return True
    key = (chat_id, user_id)
    cached = _cache_get(_ADMIN_CACHE, key, _ADMIN_CACHE_TTL)
    if cached is not None:
        return cached
    try:
        m = await bot.get_chat_member(chat_id, user_id)
        ok = m.status in (ChatMemberStatus.CREATOR, ChatMemberStatus.ADMINISTRATOR)
    except Exception:
        ok = False
    _cache_set(_ADMIN_CACHE, key, ok)
    return ok


# ==========================================================
# КАРТИНКИ С КЭШЕМ
# ==========================================================
async def send_photo_cached(
    bot_or_message, chat_id, img_name, caption,
    reply_markup=None, reply_to_message_id=None, cache_prefix="img",
):
    cache_key = cache_prefix + ":" + img_name
    safe_caption = _cut_caption(caption)

    kwargs = {}
    if reply_markup is not None:
        kwargs["reply_markup"] = reply_markup
    if reply_to_message_id is not None:
        kwargs["reply_to_message_id"] = reply_to_message_id

    async def _send_photo(file_or_id):
        if isinstance(bot_or_message, Message):
            return await bot_or_message.answer_photo(
                file_or_id, caption=safe_caption, **kwargs)
        return await bot_or_message.send_photo(
            chat_id, file_or_id, caption=safe_caption, **kwargs)

    async def _send_text():
        if isinstance(bot_or_message, Message):
            return await bot_or_message.answer(caption, **kwargs)
        return await bot_or_message.send_message(chat_id, caption, **kwargs)

    cached_id = await get_cached_file_id(cache_key)
    if cached_id:
        try:
            return await _send_photo(cached_id)
        except Exception as e:
            log.warning("Кэш %s не сработал — удаляю: %s", cache_key, e)
            await delete_cached_file_id(cache_key)

    img_full = prepare_image(img_name)
    if img_full is None:
        return await _send_text()

    try:
        msg = await _send_photo(FSInputFile(img_full))
    except Exception as e:
        log.warning("send_photo(%s) упал: %s — текстом", img_name, e)
        return await _send_text()

    if msg and getattr(msg, "photo", None):
        try:
            await cache_file_id(cache_key, msg.photo[-1].file_id)
        except Exception:
            pass
    return msg


# ==========================================================
# КАРТОЧКИ
# ==========================================================
async def send_status_card(target, user_data, extra_text="", reply_to=None):
    status = user_data.get("status", STATUS_NORMAL)
    label = STATUS_LABELS.get(status, status)
    img_name = STATUS_IMAGES.get(status, IMAGE_NORMAL_FALLBACK)

    text = (
        "📇 <b>Карточка</b>\n"
        "ID: <code>" + str(user_data.get("user_id", "—")) + "</code>\n"
        "Имя: " + (user_data.get("full_name") or "—") + "\n"
        "Юзернейм: @" + (user_data.get("username") or "—") + "\n"
        "Статус: " + label + "\n"
    )
    if user_data.get("reason"):
        text += "Причина: " + user_data["reason"] + "\n"
    if extra_text:
        text += "\n" + extra_text

    kb = profile_kb(user_data.get("user_id") or 0,
                    user_data.get("evidence_url"),
                    user_data.get("username"))
    reply_to_id = reply_to.message_id if reply_to else None

    return await send_photo_cached(target, None, img_name, text,
                                    reply_markup=kb,
                                    reply_to_message_id=reply_to_id,
                                    cache_prefix="status")


# ==========================================================
# АВТО-СОХРАНЕНИЕ
# ==========================================================
async def auto_save_from_message(message):
    saved = set()

    async def save(u):
        if not u or u.is_bot or u.id in saved:
            return
        saved.add(u.id)
        await upsert_user(u.id, u.username, u.full_name)

    if message.from_user:
        await save(message.from_user)
    if message.reply_to_message and message.reply_to_message.from_user:
        await save(message.reply_to_message.from_user)
    if message.forward_from:
        await save(message.forward_from)
    if message.entities:
        for ent in message.entities:
            if ent.type == "text_mention" and ent.user:
                await save(ent.user)
    if message.caption_entities:
        for ent in message.caption_entities:
            if ent.type == "text_mention" and ent.user:
                await save(ent.user)


class AutoRegisterMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):
        try:
            if isinstance(event, Message):
                await auto_save_from_message(event)
            elif isinstance(event, CallbackQuery) and event.from_user:
                await upsert_user(event.from_user.id,
                                  event.from_user.username,
                                  event.from_user.full_name)
            elif isinstance(event, ChatMemberUpdated):
                u = event.new_chat_member.user
                await upsert_user(u.id, u.username, u.full_name)
        except Exception as e:
            log.warning("AutoRegister: %s", e)
        return await handler(event, data)


# ==========================================================
# СЛУЖЕБНЫЕ
# ==========================================================
def _is_service_message(event):
    return bool(
        event.new_chat_members or event.left_chat_member
        or event.new_chat_title or event.new_chat_photo
        or event.delete_chat_photo or event.pinned_message
        or event.group_chat_created or event.supergroup_chat_created
        or event.channel_chat_created or event.migrate_to_chat_id
        or event.migrate_from_chat_id
    )


# ==========================================================
# ГЕЙТ ПОДПИСКИ
# ==========================================================
class SubscriptionGateMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):
        if not isinstance(event, Message):
            return await handler(event, data)

        chat = event.chat
        if chat.type not in ("group", "supergroup"):
            return await handler(event, data)
        if _is_service_message(event):
            return await handler(event, data)

        user = event.from_user
        if not user or user.is_bot:
            return await handler(event, data)
        if user.id == SUPER_ADMIN_ID:
            return await handler(event, data)

        try:
            reqs = await list_required_chats(chat.id)
        except Exception:
            return await handler(event, data)
        if not reqs:
            return await handler(event, data)

        try:
            if await is_chat_admin(event.bot, chat.id, user.id):
                return await handler(event, data)
        except Exception:
            pass

        if is_command(event):
            return await handler(event, data)

        try:
            missing = await check_user_all_subscriptions(event.bot, user.id, chat.id)
        except Exception:
            return await handler(event, data)
        if not missing:
            return await handler(event, data)

        try:
            await event.bot.delete_message(chat.id, event.message_id)
        except Exception as e:
            log.warning("Gate: не смог удалить: %s", e)

        mention = user_mention(user)
        lines = [mention + ", 🚫 <b>чтобы писать в этом чате, нужно подписаться на:</b>\n"]
        kb_rows = []
        for r in missing:
            title = r["title"] or ("@" + r["req_username"])
            lines.append("• <a href=\"" + r["link"] + "\">" + title + "</a>")
            kb_rows.append([InlineKeyboardButton(text="📎 " + title, url=r["link"])])
        text_out = "\n".join(lines) + "\n\n<i>После подписки напиши снова.</i>"
        kb = InlineKeyboardMarkup(inline_keyboard=kb_rows) if kb_rows else None
        try:
            await event.bot.send_message(chat.id, text_out, reply_markup=kb,
                                          disable_web_page_preview=True)
        except Exception:
            pass
        return


# ==========================================================
# АНТИСПАМ
# ==========================================================
class AntiSpamMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):
        if not isinstance(event, Message):
            return await handler(event, data)

        chat = event.chat
        if chat.type not in ("group", "supergroup"):
            return await handler(event, data)
        if _is_service_message(event):
            return await handler(event, data)

        user = event.from_user
        if not user or user.is_bot:
            return await handler(event, data)
        if user.id == SUPER_ADMIN_ID:
            return await handler(event, data)
        if is_command(event):
            return await handler(event, data)

        s = await get_chat_settings(chat.id)

        text = event.text or event.caption or ""
        reason = None
        if text:
            if USERNAME_ONLY_REGEX.match(text.strip()):
                pass
            elif s.get("antispam_links", 1) and has_link(text):
                reason = "ссылка"
            if reason is None and s.get("antispam_caps", 1) and is_caps(text):
                reason = "капс"
        if reason is None and s.get("antispam_flood", 1):
            fp = message_fingerprint(event)
            if fp != "unknown" and is_flood(chat.id, user.id, fp):
                reason = "флуд"
        if reason is None:
            return await handler(event, data)

        try:
            if await is_chat_admin(event.bot, chat.id, user.id):
                return await handler(event, data)
        except Exception:
            pass

        try:
            await event.bot.delete_message(chat.id, event.message_id)
            log.info("AntiSpam: удалено msg=%s reason=%s", event.message_id, reason)
        except Exception as e:
            log.warning("AntiSpam: ошибка удаления: %s", e)

        mention = user_mention(user)
        if reason == "ссылка":
            warn = mention + ", 🚫 ссылки запрещены."
        elif reason == "капс":
            warn = mention + ", 🚫 не пиши капсом."
        elif reason == "флуд":
            warn = mention + ", 🚫 прекрати флудить."
            async def mute():
                try:
                    await event.bot.restrict_chat_member(
                        chat.id, user.id,
                        until_date=datetime.utcnow() + timedelta(seconds=FLOOD_MUTE_SECONDS),
                        can_send_messages=False)
                    clear_flood(chat.id, user.id)
                except Exception:
                    pass
            asyncio.create_task(mute())
            warn += "\nЗаглушен на " + str(FLOOD_MUTE_SECONDS // 60) + " мин."
        else:
            warn = mention + ", 🚫 сообщение удалено."
        try:
            await event.bot.send_message(chat.id, warn)
        except Exception:
            pass
        return


# ==========================================================
# КЛАВИАТУРЫ
# ==========================================================
def user_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚨 Пожаловаться", callback_data="report_start")],
        [InlineKeyboardButton(text="🔎 Проверить себя", callback_data="check_me")],
        [InlineKeyboardButton(text="👤 Проверить пользователя",
                              callback_data="user_check_start")],
        [InlineKeyboardButton(text="⚖️ Обжаловать решение", callback_data="appeal_start")],
    ])


def staff_menu(role: str):
    rows = [
        [InlineKeyboardButton(text="📨 Жалобы", callback_data="staff:reports")],
        [InlineKeyboardButton(text="⚖️ Апелляции", callback_data="staff:appeals")],
        [InlineKeyboardButton(text="🔎 Проверить пользователя",
                              callback_data="user_check_start")],
        [InlineKeyboardButton(text="➕ Изменить статус", callback_data="admin_set_status")],
        [InlineKeyboardButton(text="⛔ Забанить везде", callback_data="admin_ban_anywhere")],
        [InlineKeyboardButton(text="🔁 Сбросить статус", callback_data="admin_reset_status")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="admin_stats")],
        [InlineKeyboardButton(text="⚙️ Мои группы", callback_data="staff:settings_list")],
    ]
    if role in (ROLE_SUPER, ROLE_ADMIN):
        rows.append([InlineKeyboardButton(text="🎭 Управление ролями",
                                           callback_data="admin_roles")])
    if role in (ROLE_SUPER, ROLE_ADMIN):
        rows.append([InlineKeyboardButton(text="📢 Рассылка",
                                           callback_data="broadcast_start")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def roles_menu(actor_role: str):
    rows = []
    if actor_role == ROLE_SUPER:
        rows.append([InlineKeyboardButton(text="👑 Сделать главным админом",
                                           callback_data="role_set:super")])
    if actor_role in (ROLE_SUPER, ROLE_ADMIN):
        rows.append([InlineKeyboardButton(text="🛠 Сделать админом",
                                           callback_data="role_set:admin")])
        rows.append([InlineKeyboardButton(text="🛡 Сделать модератором",
                                           callback_data="role_set:moderator")])
        rows.append([InlineKeyboardButton(text="👤 Снять роль",
                                           callback_data="role_set:user")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def status_choice_kb(prefix):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_SCAM],
                              callback_data=prefix + ":" + STATUS_SCAM)],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_SUSPICIOUS],
                              callback_data=prefix + ":" + STATUS_SUSPICIOUS)],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_NORMAL],
                              callback_data=prefix + ":" + STATUS_NORMAL)],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_VERIFIED],
                              callback_data=prefix + ":" + STATUS_VERIFIED)],
    ])


def profile_kb(user_id, evidence_url, username):
    rows = []
    link = ("https://t.me/" + username) if username else ("tg://user?id=" + str(user_id))
    rows.append([InlineKeyboardButton(text="👤 Открыть профиль", url=link)])
    if evidence_url:
        rows.append([InlineKeyboardButton(text="📎 Доказательства", url=evidence_url)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def report_review_kb(report_id):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Принять",
                              callback_data="report_accept:" + str(report_id))],
        [InlineKeyboardButton(text="❌ Отклонить",
                              callback_data="report_reject:" + str(report_id))],
        [InlineKeyboardButton(text="💬 Написать автору",
                              callback_data="report_msg:" + str(report_id))],
    ])


def report_status_kb(report_id):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_SCAM],
                              callback_data="report_apply:{}:{}".format(report_id, STATUS_SCAM))],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_SUSPICIOUS],
                              callback_data="report_apply:{}:{}".format(report_id, STATUS_SUSPICIOUS))],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_NORMAL],
                              callback_data="report_apply:{}:{}".format(report_id, STATUS_NORMAL))],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_VERIFIED],
                              callback_data="report_apply:{}:{}".format(report_id, STATUS_VERIFIED))],
    ])


def appeal_review_kb(appeal_id):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Поменять решение",
                              callback_data="appeal_change:" + str(appeal_id))],
        [InlineKeyboardButton(text="❌ Отказать",
                              callback_data="appeal_reject:" + str(appeal_id))],
        [InlineKeyboardButton(text="💬 Написать автору",
                              callback_data="appeal_msg:" + str(appeal_id))],
    ])


def conv_reply_kb(kind, ref_id, user_id):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✍️ Ответить",
                              callback_data="conv_reply:{}:{}".format(kind, ref_id))],
    ])


def conv_staff_reply_kb(kind, ref_id, conv_id):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✍️ Ответить",
                              callback_data="conv_staff_reply:" + str(conv_id))],
        [InlineKeyboardButton(text="🔒 Закрыть диалог",
                              callback_data="conv_close:" + str(conv_id))],
    ])


def settings_menu(chat_id, s: dict):
    w_on = "✅" if s.get("welcome_enabled") else "❌"
    a_links = "✅" if s.get("antispam_links") else "❌"
    a_caps = "✅" if s.get("antispam_caps") else "❌"
    a_flood = "✅" if s.get("antispam_flood") else "❌"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✏️ Текст приветствия",
                              callback_data="settings:welcome:" + str(chat_id))],
        [InlineKeyboardButton(text="🖼 Картинка приветствия",
                              callback_data="settings:welcome_img:" + str(chat_id))],
        [InlineKeyboardButton(text=w_on + " Приветствие",
                              callback_data="settings:toggle:welcome_enabled:" + str(chat_id))],
        [InlineKeyboardButton(text=a_links + " Блок ссылок",
                              callback_data="settings:toggle:antispam_links:" + str(chat_id))],
        [InlineKeyboardButton(text=a_caps + " Блок капса",
                              callback_data="settings:toggle:antispam_caps:" + str(chat_id))],
        [InlineKeyboardButton(text=a_flood + " Блок флуда",
                              callback_data="settings:toggle:antispam_flood:" + str(chat_id))],
        [InlineKeyboardButton(text="🔒 Добавить обязательную подписку",
                              callback_data="settings:required:" + str(chat_id))],
        [InlineKeyboardButton(text="📋 Список обязательных подписок",
                              callback_data="settings:list:" + str(chat_id))],
    ])


def settings_chats_kb(chats):
    rows = []
    for c in chats:
        rows.append([InlineKeyboardButton(
            text=("⚙️ " + (c["title"] or str(c["chat_id"])))[:60],
            callback_data="settings:open:" + str(c["chat_id"]))])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def remgroup_kb(chat_id, reqs):
    rows = []
    for r in reqs:
        title = r["title"] or ("@" + r["req_username"])
        rows.append([InlineKeyboardButton(
            text=("🗑 " + title)[:60],
            callback_data="remgroup:{}:{}".format(chat_id, r["id"]))])
    return InlineKeyboardMarkup(inline_keyboard=rows) if rows else None


def broadcast_confirm_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Отправить", callback_data="broadcast_send")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="broadcast_cancel")],
    ])


# ==========================================================
# FSM
# ==========================================================
class ReportFSM(StatesGroup):
    waiting_evidence = State()


class UserCheckFSM(StatesGroup):
    waiting_target = State()


class AppealFSM(StatesGroup):
    waiting_evidence = State()


class ConvFSM(StatesGroup):
    waiting_message = State()
    waiting_staff_message = State()


class StaffFSM(StatesGroup):
    waiting_target = State()
    waiting_reason = State()
    waiting_evidence = State()
    waiting_role_target = State()


class SettingsFSM(StatesGroup):
    waiting_welcome = State()
    waiting_welcome_img = State()
    waiting_req_chat = State()
    waiting_req_time = State()


class BroadcastFSM(StatesGroup):
    waiting_content = State()
    waiting_confirm = State()


# ==========================================================
# РОУТЕРЫ
# ==========================================================
router_staff = Router()
router_user = Router()
router_group = Router()

router_user.message.outer_middleware(AutoRegisterMiddleware())
router_user.callback_query.outer_middleware(AutoRegisterMiddleware())
router_group.message.outer_middleware(AutoRegisterMiddleware())
router_group.callback_query.outer_middleware(AutoRegisterMiddleware())
router_group.chat_member.outer_middleware(AutoRegisterMiddleware())

router_group.message.outer_middleware(AntiSpamMiddleware())
router_group.message.outer_middleware(SubscriptionGateMiddleware())


# ==========================================================
# РОЛИ — ХЕЛПЕРЫ
# ==========================================================
async def role_can_set_status(role):
    return role in (ROLE_SUPER, ROLE_ADMIN, ROLE_MODERATOR)


async def role_can_assign(actor_role, target_role):
    if actor_role == ROLE_SUPER:
        return True
    if actor_role == ROLE_ADMIN:
        return target_role == ROLE_MODERATOR
    return False


async def broadcast_staff(bot: Bot, text: str, kb=None, exclude_id: int = None):
    for row in await list_staff():
        uid = row["user_id"]
        if exclude_id and uid == exclude_id:
            continue
        try:
            await bot.send_message(uid, text, reply_markup=kb,
                                    disable_web_page_preview=True)
        except Exception:
            pass


# ==========================================================
# USER: /start
# ==========================================================
@router_user.message(CommandStart(), IsPrivateChat())
async def user_start(message: Message, state: FSMContext, bot: Bot):
    await state.clear()
    role = await get_user_role(message.from_user.id)

    text = "👋 Привет! Это <b>" + BOT_NAME + "</b>.\n"
    if role in (ROLE_SUPER, ROLE_ADMIN, ROLE_MODERATOR):
        text += "Твоя роль: " + ROLE_LABELS[role] + "\n"
        text += "Панель модератора: /admin\n\n"
    else:
        text += "\n"

    text += (
        "📌 Что я умею:\n"
        "• 🚨 <b>Пожаловаться</b> — пришли ID/@username и доказательства\n"
        "• 🔎 <b>Проверить себя</b> — узнать свой статус\n"
        "• 👤 <b>Проверить пользователя</b> — узнать статус любого\n"
        "• ⚖️ <b>Обжаловать решение</b> — если считаешь модерацию ошибкой\n"
        "• В группе: <code>/check</code>, <code>/report</code>, "
        "<code>/settings</code> (админ группы)\n\n"
        "🆔 Бот запоминает твой ID — даже если сменишь @username, "
        "тебя найдут по ID.\n\n"
        "Жалобы рассматривают модераторы. Они могут ответить тебе прямо в боте."
    )

    await send_photo_cached(message, None, IMAGE_START, text,
                            reply_markup=user_menu(),
                            cache_prefix="banner")


@router_user.message(Command("cancel"), IsPrivateChat())
@router_staff.message(Command("cancel"), IsPrivateChat())
@router_group.message(Command("cancel"), IsGroupChat())
async def cmd_cancel(message: Message, state: FSMContext):
    await state.clear()
    await message.answer("OK, отменил. Жми /start.")


@router_user.callback_query(F.data == "check_me", IsPrivateChat())
async def check_me(cb: CallbackQuery):
    u = await get_user(cb.from_user.id)
    if not u:
        await upsert_user(cb.from_user.id, cb.from_user.username,
                          cb.from_user.full_name)
        u = await get_user(cb.from_user.id)
    await safe_answer(cb)
    await send_status_card(cb.message, u)


# ==========================================================
# USER: ПРОВЕРКА ПОЛЬЗОВАТЕЛЯ ПРЯМО В БОТЕ# ==========================================================
@router_user.callback_query(F.data == "user_check_start")
async def user_check_start(cb: CallbackQuery, state: FSMContext):
    await safe_answer(cb)
    await state.set_state(UserCheckFSM.waiting_target)
    await cb.message.answer(
        "🔎 <b>Проверка пользователя</b>\n\n"
        "Отправь одно из:\n"
        "• <code>@username</code>\n"
        "• <code>123456789</code> (ID)\n"
        "• перешли мне любое его сообщение\n\n"
        "💡 <b>Важно:</b> бот запоминает ID — если человек сменил @username, "
        "то по старому @username или по ID я его найду."
    )


@router_user.message(UserCheckFSM.waiting_target, IsPrivateChat())
async def user_check_process(message: Message, state: FSMContext):
    # Пересланное сообщение
    if message.forward_from:
        u = message.forward_from
        await upsert_user(u.id, u.username, u.full_name)
        data = await get_user(u.id)
        await state.clear()
        await send_status_card(message, data or {
            "user_id": u.id, "username": u.username,
            "full_name": u.full_name, "status": STATUS_NORMAL,
            "reason": None, "evidence_url": None,
        })
        return

    if message.forward_from_chat:
        c = message.forward_from_chat
        await state.clear()
        await send_status_card(message, {
            "user_id": c.id, "username": c.username,
            "full_name": c.title, "status": STATUS_NORMAL,
            "reason": None, "evidence_url": None,
        })
        return

    text = (message.text or "").strip()
    if not text:
        await message.answer("❗ Отправь @username, ID или перешли сообщение.")
        return

    target_id = None
    target_username = None
    for p in text.split():
        if p.startswith("@"):
            target_username = p[1:]
        elif p.lstrip("-").isdigit():
            target_id = int(p)

    user = None
    if target_id:
        user = await get_user(target_id)
    if not user and target_username:
        user = await get_user_by_username(target_username)

    await state.clear()

    if user:
        await send_status_card(message, user)
    else:
        # Не нашли в базе — просто отдаём обычную карточку
        shown_id = target_id if target_id else "—"
        shown_username = target_username if target_username else "—"
        await message.answer(
            "📇 <b>Проверка</b>\n"
            "ID: <code>" + str(shown_id) + "</code>\n"
            "Юзернейм: @" + str(shown_username) + "\n"
            "Статус: " + STATUS_LABELS[STATUS_NORMAL] + "\n\n"
            "<i>Пользователь не найден в базе.</i>"
        )


# ==========================================================
# USER: ЖАЛОБА
# ==========================================================
@router_user.callback_query(F.data == "report_start", IsPrivateChat())
async def report_start(cb: CallbackQuery, state: FSMContext):
    await safe_answer(cb)
    await state.set_state(ReportFSM.waiting_evidence)
    await cb.message.answer(
        "🚨 <b>Жалоба</b>\n\n"
        "Отправь одним сообщением:\n"
        "1️⃣ ID или @username нарушителя\n"
        "2️⃣ Описание и доказательства (текст/фото/видео)\n\n"
        "Пример: <code>@scammer123 123456789 — кинул на 5000р</code>"
    )


def _extract_target_and_text(raw: str):
    target_id = None
    target_username = None
    rest = raw

    m = re.search(r"@([A-Za-z0-9_]{5,32})", raw)
    if m:
        target_username = m.group(1)
        rest = raw.replace(m.group(0), "", 1).strip()

    m2 = re.search(r"\b(\d{5,})\b", rest)
    if m2:
        target_id = int(m2.group(1))
        rest = rest.replace(m2.group(1), "", 1).strip()

    rest = re.sub(r"^[,\-\s]+", "", rest)
    return target_id, target_username, rest


@router_user.message(ReportFSM.waiting_evidence, IsPrivateChat())
async def report_evidence(message: Message, state: FSMContext, bot: Bot):
    text = message.caption or message.text or ""
    photo_id = message.photo[-1].file_id if message.photo else None
    video_id = message.video.file_id if message.video else None

    target_id, target_username, rest = _extract_target_and_text(text)

    if target_id is None and target_username:
        found = await get_user_by_username(target_username)
        if found:
            target_id = found["user_id"]
        else:
            await message.answer(
                "❗ @" + target_username + " ещё не в базе.\n"
                "Укажи его ID: <code>" + target_username + " 123456789 описание</code>"
            )
            return
    if target_id is None:
        await message.answer(
            "❗ Не понял, на кого жалоба. Укажи ID или @username в начале."
        )
        return
    if target_id == message.from_user.id:
        await message.answer("Нельзя жаловаться на себя.")
        return

    await upsert_user(target_id, target_username, None)
    report_id = await add_report(message.from_user.id, target_id,
                                  rest, photo_id, video_id)
    await create_conversation("report", report_id, message.from_user.id)

    target_user = await get_user(target_id) or {}
    target_mention = user_mention_by_id(
        target_id,
        target_user.get("username"),
        target_user.get("full_name"),
    )
    from_mention = user_mention(message.from_user)

    header = (
        "🚨 <b>Жалоба #" + str(report_id) + "</b>\n\n"
        "👤 От: " + from_mention + "\n"
        "🎯 На: " + target_mention + "\n"
        "🆔 ID цели: <code>" + str(target_id) + "</code>\n\n"
        "📝 Текст: " + (rest or "—")
    )

    await broadcast_staff(bot, header, kb=report_review_kb(report_id),
                           exclude_id=message.from_user.id)
    await send_log(bot,
        "🚨 Жалоба #" + str(report_id) +
        " от <code>" + str(message.from_user.id) + "</code>" +
        " на <code>" + str(target_id) + "</code>")

    await state.clear()
    await message.answer(
        "✅ Жалоба отправлена модераторам.\n"
        "Они рассмотрят её и могут написать тебе сюда."
    )


# ==========================================================
# USER: АПЕЛЛЯЦИЯ
# ==========================================================
@router_user.callback_query(F.data == "appeal_start", IsPrivateChat())
async def appeal_start(cb: CallbackQuery, state: FSMContext):
    await safe_answer(cb)
    await state.set_state(AppealFSM.waiting_evidence)
    await cb.message.answer(
        "⚖️ <b>Обжалование</b>\n\n"
        "Отправь одним сообщением доказательства, почему решение неверно: "
        "текст, фото или видео."
    )


@router_user.message(AppealFSM.waiting_evidence, IsPrivateChat())
async def appeal_evidence(message: Message, state: FSMContext, bot: Bot):
    photo_id = message.photo[-1].file_id if message.photo else None
    video_id = message.video.file_id if message.video else None
    text = message.caption or message.text or ""

    appeal_id = await add_appeal(message.from_user.id, text, photo_id, video_id)
    await create_conversation("appeal", appeal_id, message.from_user.id)

    from_mention = user_mention(message.from_user)
    header = (
        "⚖️ <b>Новая апелляция #" + str(appeal_id) + "</b>\n"
        "От: " + from_mention + "\n"
        "ID: <code>" + str(message.from_user.id) + "</code>\n\n"
        "📝 Текст: " + (text or "—")
    )
    await broadcast_staff(bot, header, kb=appeal_review_kb(appeal_id))
    await send_log(bot, "⚖️ Апелляция #" + str(appeal_id) +
                        " от <code>" + str(message.from_user.id) + "</code>")
    await state.clear()
    await message.answer("✅ Апелляция отправлена.")


# ==========================================================
# USER: ДИАЛОГ С МОДЕРАТОРОМ
# ==========================================================
@router_user.callback_query(F.data.startswith("conv_reply:"))
async def conv_reply_user(cb: CallbackQuery, state: FSMContext):
    _, kind, ref_id_str = cb.data.split(":")
    ref_id = int(ref_id_str)
    conv = await get_conversation_by_ref(kind, ref_id)
    if not conv or conv["status"] == "closed":
        await safe_answer(cb, "Диалог закрыт", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(ConvFSM.waiting_message)
    await state.update_data(kind=kind, ref_id=ref_id,
                            conv_id=conv["id"], as_staff=False)
    await cb.message.answer("✍️ Напиши сообщение модератору:")


@router_user.message(ConvFSM.waiting_message, IsPrivateChat())
async def conv_user_send(message: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    conv_id = data.get("conv_id")
    kind = data.get("kind")
    ref_id = data.get("ref_id")
    if not conv_id:
        await state.clear()
        return

    conv = await get_conversation(conv_id)
    if not conv or conv["status"] == "closed":
        await state.clear()
        await message.answer("Диалог закрыт.")
        return

    photo_id = message.photo[-1].file_id if message.photo else None
    video_id = message.video.file_id if message.video else None
    text = message.caption or message.text or ""

    await add_conv_message(conv_id, message.from_user.id, is_mod=False,
                            text=text, photo_id=photo_id, video_id=video_id)

    mod_id = conv.get("moderator_id")
    from_mention = user_mention(message.from_user)
    body = (
        "💬 <b>Сообщение по " + kind + " #" + str(ref_id) + "</b>\n"
        "От: " + from_mention + "\n\n" + (text or "—")
    )
    kb = conv_staff_reply_kb(kind, ref_id, conv_id)

    if mod_id:
        try:
            if photo_id:
                await bot.send_photo(mod_id, photo_id, caption=body, reply_markup=kb)
            elif video_id:
                await bot.send_video(mod_id, video_id, caption=body, reply_markup=kb)
            else:
                await bot.send_message(mod_id, body, reply_markup=kb)
        except Exception:
            pass
    else:
        await broadcast_staff(bot, body, kb=kb)

    await state.clear()
    await message.answer("✅ Отправлено.")


# ==========================================================
# STAFF: панель
# ==========================================================
@router_staff.message(Command("admin"), IsPrivateChat())
async def admin_cmd(message: Message, state: FSMContext):
    role = await get_user_role(message.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN, ROLE_MODERATOR):
        await message.answer("⛔ Нет доступа.")
        return
    await state.clear()
    await message.answer(
        "🛠 <b>" + BOT_NAME + "</b> — панель\n" +
        "Роль: " + ROLE_LABELS[role] + "\n\n"
        "Здесь: жалобы, апелляции, статусы, проверка пользователей, "
        "управление группами.",
        reply_markup=staff_menu(role)
    )


@router_staff.message(Command("roles"), IsPrivateChat())
async def roles_cmd(message: Message, state: FSMContext):
    role = await get_user_role(message.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN):
        await message.answer("⛔ Нет доступа.")
        return
    await state.set_state(StaffFSM.waiting_role_target)
    await message.answer("🎭 Введи @username или ID пользователя.")


@router_staff.callback_query(F.data == "admin_roles")
async def cb_admin_roles(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(StaffFSM.waiting_role_target)
    await cb.message.answer("🎭 Введи @username или ID.")


@router_staff.message(StaffFSM.waiting_role_target, F.text, IsPrivateChat())
async def roles_set_target(message: Message, state: FSMContext):
    role = await get_user_role(message.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN):
        await state.clear()
        return

    arg = message.text.strip()
    target_id = None
    target_username = None
    for p in arg.split():
        if p.startswith("@"):
            target_username = p[1:]
        elif p.lstrip("-").isdigit():
            target_id = int(p)

    if target_id is None and target_username:
        found = await get_user_by_username(target_username)
        if found:
            target_id = found["user_id"]
        else:
            await message.answer("❗ Не найден в базе.")
            await state.clear()
            return
    if target_id is None:
        await message.answer("Не понял.")
        return

    await state.update_data(target_id=target_id)
    await message.answer(
        "Кому какую роль выдать для <code>" + str(target_id) + "</code>?",
        reply_markup=roles_menu(role)
    )


@router_staff.callback_query(F.data.startswith("role_set:"))
async def role_set_apply(cb: CallbackQuery, state: FSMContext, bot: Bot):
    actor_role = await get_user_role(cb.from_user.id)
    new_role = cb.data.split(":", 1)[1]
    data = await state.get_data()
    target_id = data.get("target_id")
    if not target_id:
        await safe_answer(cb, "Потерян таргет", alert=True)
        return
    if not await role_can_assign(actor_role, new_role):
        await safe_answer(cb, "Недостаточно прав", alert=True)
        return

    await safe_answer(cb)
    await set_user_role(target_id, new_role)
    await log_action(cb.from_user.id, "set_role:" + new_role, target_id)
    actor_mention = user_mention(cb.from_user)
    await send_log(bot,
        "🎭 " + actor_mention + " (" + ROLE_LABELS[actor_role] + ") выдал " +
        ROLE_LABELS[new_role] + " → <code>" + str(target_id) + "</code>")
    await cb.message.answer("✅ Роль: " + ROLE_LABELS[new_role])
    await state.clear()


# ==========================================================
# STAFF: РАССЫЛКА
# ==========================================================
@router_staff.callback_query(F.data == "broadcast_start")
async def broadcast_start(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(BroadcastFSM.waiting_content)
    await cb.message.answer(
        "📢 <b>Рассылка</b>\n\n"
        "Отправь сообщение, которое хочешь разослать во все группы, где есть бот.\n\n"
        "Поддерживается:\n"
        "• текст с любым форматированием (жирный, курсив, код, ссылки, "
        "спойлеры и т.д.) — уйдёт 1-в-1\n"
        "• фото с подписью\n"
        "• видео с подписью\n"
        "• GIF/анимация\n\n"
        "⚠️ Перед отправкой покажу превью и попрошу подтверждение."
    )


@router_staff.message(BroadcastFSM.waiting_content, IsPrivateChat())
async def broadcast_content(message: Message, state: FSMContext):
    role = await get_user_role(message.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN):
        await state.clear()
        return

    # Сохраняем «снимок» сообщения, чтобы затем отправить 1-в-1
    payload = {
        "text": message.html_text if message.text else None,
        "caption": message.html_text if message.caption else None,
        "photo_id": message.photo[-1].file_id if message.photo else None,
        "video_id": message.video.file_id if message.video else None,
        "animation_id": message.animation.file_id if message.animation else None,
        "entities": True,
    }
    await state.update_data(payload=payload)
    await state.set_state(BroadcastFSM.waiting_confirm)

    preview = "📢 <b>Превью рассылки</b>\n\n"
    try:
        if payload["photo_id"]:
            await message.answer_photo(payload["photo_id"],
                caption="📢 <b>Превью</b>\n\n" + (payload["caption"] or ""),
                reply_markup=broadcast_confirm_kb())
        elif payload["video_id"]:
            await message.answer_video(payload["video_id"],
                caption="📢 <b>Превью</b>\n\n" + (payload["caption"] or ""),
                reply_markup=broadcast_confirm_kb())
        elif payload["animation_id"]:
            await message.answer_animation(payload["animation_id"],
                caption="📢 <b>Превью</b>\n\n" + (payload["caption"] or ""),
                reply_markup=broadcast_confirm_kb())
        else:
            await message.answer(preview + (payload["text"] or "—"),
                reply_markup=broadcast_confirm_kb())
    except Exception as e:
        log.warning("broadcast preview: %s", e)
        await message.answer("Ошибка превью: " + str(e))


@router_staff.callback_query(F.data == "broadcast_send")
async def broadcast_send(cb: CallbackQuery, state: FSMContext, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    data = await state.get_data()
    payload = data.get("payload")
    if not payload:
        await safe_answer(cb, "Потерян payload", alert=True)
        return

    await safe_answer(cb, "Рассылка пошла")

    chats = await list_all_chats()
    sent = 0
    failed = 0

    for c in chats:
        cid = c["chat_id"]
        try:
            if payload.get("photo_id"):
                await bot.send_photo(cid, payload["photo_id"],
                    caption=payload.get("caption") or None)
            elif payload.get("video_id"):
                await bot.send_video(cid, payload["video_id"],
                    caption=payload.get("caption") or None)
            elif payload.get("animation_id"):
                await bot.send_animation(cid, payload["animation_id"],
                    caption=payload.get("caption") or None)
            else:
                await bot.send_message(cid, payload.get("text") or "—")
            sent += 1
        except Exception as e:
            failed += 1
            log.warning("Broadcast to %s: %s", cid, e)

    await state.clear()
    await cb.message.answer(
        "📢 <b>Готово</b>\n"
        "Отправлено: " + str(sent) + "\n"
        "Ошибок: " + str(failed)
    )
    await send_log(bot, "📢 " + user_mention(cb.from_user) +
                        " сделал рассылку в " + str(sent) + " чатов")


@router_staff.callback_query(F.data == "broadcast_cancel")
async def broadcast_cancel(cb: CallbackQuery, state: FSMContext):
    await safe_answer(cb, "Отменено")
    await state.clear()
    await cb.message.answer("❌ Рассылка отменена.")


# ---- Жалобы: список ----
@router_staff.callback_query(F.data == "staff:reports")
async def cb_staff_reports(cb: CallbackQuery):
    role = await get_user_role(cb.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN, ROLE_MODERATOR):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    await safe_answer(cb)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM reports WHERE status='pending' ORDER BY id ASC LIMIT 10")
        rows = [dict(r) for r in await cur.fetchall()]

    if not rows:
        await cb.message.answer("📭 Нет новых жалоб.")
        return

    for r in rows:
        target_user = await get_user(r["target_id"]) or {}
        target_mention = user_mention_by_id(
            r["target_id"],
            target_user.get("username"),
            target_user.get("full_name"),
        )
        body = (
            "🚨 <b>Жалоба #" + str(r["id"]) + "</b>\n"
            "От: <code>" + str(r["reporter_id"]) + "</code>\n"
            "На: " + target_mention + "\n"
            "Текст: " + (r.get("text") or "—")
        )
        kb = report_review_kb(r["id"])
        try:
            if r.get("photo_id"):
                await cb.message.answer_photo(r["photo_id"], caption=body,
                                               reply_markup=kb)
            elif r.get("video_id"):
                await cb.message.answer_video(r["video_id"], caption=body,
                                               reply_markup=kb)
            else:
                await cb.message.answer(body, reply_markup=kb)
        except TelegramBadRequest as e:
            log.warning("reports item: %s", e)


# ---- Жалобы: принять ----
@router_staff.callback_query(F.data.startswith("report_accept:"))
async def report_accept(cb: CallbackQuery, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    report_id = int(cb.data.split(":")[1])
    rep = await get_report(report_id)
    if not rep:
        await safe_answer(cb, "Жалоба не найдена", alert=True)
        return
    if rep["status"] != "pending":
        await safe_answer(cb, "Уже обработана", alert=True)
        return

    conv = await get_conversation_by_ref("report", report_id)
    if conv and not await claim_conversation(conv["id"], cb.from_user.id):
        await safe_answer(cb, "Диалог ведёт другой модератор", alert=True)
        return

    await safe_answer(cb, "Принято")

    await set_report_status(report_id, "accepted", cb.from_user.id)
    await log_action(cb.from_user.id, "report_accept", rep["target_id"],
                     "report=" + str(report_id))

    await cb.message.answer(
        "✅ Жалоба принята. Выбери статус для пользователя:",
        reply_markup=report_status_kb(report_id)
    )


# ---- Жалобы: применить статус ----
@router_staff.callback_query(F.data.startswith("report_apply:"))
async def report_apply_status(cb: CallbackQuery, bot: Bot):
    parts = cb.data.split(":")
    if len(parts) != 3:
        await safe_answer(cb)
        return
    _, report_id_str, status = parts
    report_id = int(report_id_str)

    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    rep = await get_report(report_id)
    if not rep:
        await safe_answer(cb, "Жалоба не найдена", alert=True)
        return

    await safe_answer(cb, "Статус: " + STATUS_LABELS[status])

    target_id = rep["target_id"]
    await set_status(target_id, status, "По жалобе", None)

    target_user = await get_user(target_id) or {}
    await send_evidence(bot, rep, target_user, status)

    await set_report_status(report_id, "resolved", cb.from_user.id)
    await log_action(cb.from_user.id, "report_status:" + status, target_id,
                     "report=" + str(report_id))
    actor_mention = user_mention(cb.from_user)
    await send_log(bot,
        "✅ Жалоба #" + str(report_id) + " решена: <b>" + STATUS_LABELS[status] +
        "</b> для <code>" + str(target_id) + "</code> модератором " + actor_mention)

    try:
        await bot.send_message(
            rep["reporter_id"],
            "✅ По твоей жалобе #" + str(report_id) + " принято решение:\n"
            "Пользователь <code>" + str(target_id) + "</code> → " +
            STATUS_LABELS[status]
        )
    except Exception:
        pass

    try:
        await bot.send_message(
            target_id,
            "⚖️ Твой статус изменён на: " + STATUS_LABELS[status] + "\n"
            "Если считаешь это ошибкой — обжалуй через /start."
        )
    except Exception:
        pass

    await cb.message.answer("✅ Статус установлен: " + STATUS_LABELS[status])


@router_staff.callback_query(F.data.startswith("report_reject:"))
async def report_reject(cb: CallbackQuery, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    report_id = int(cb.data.split(":")[1])
    rep = await get_report(report_id)
    if not rep or rep["status"] != "pending":
        await safe_answer(cb, "Уже обработана", alert=True)
        return

    await safe_answer(cb, "Отклонено")

    await set_report_status(report_id, "rejected", cb.from_user.id)
    await log_action(cb.from_user.id, "report_reject", rep["target_id"],
                     "report=" + str(report_id))
    try:
        await bot.send_message(rep["reporter_id"],
            "❌ Жалоба #" + str(report_id) + " отклонена модератором.")
    except Exception:
        pass
    await cb.message.answer("❌ Отклонено.")


@router_staff.callback_query(F.data.startswith("report_msg:"))
async def report_msg(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    report_id = int(cb.data.split(":")[1])
    rep = await get_report(report_id)
    if not rep:
        await safe_answer(cb, "Не найдено", alert=True)
        return

    conv = await get_conversation_by_ref("report", report_id)
    if conv and not await claim_conversation(conv["id"], cb.from_user.id):
        await safe_answer(cb, "Диалог ведёт другой модератор", alert=True)
        return

    await safe_answer(cb)
    await state.set_state(ConvFSM.waiting_staff_message)
    await state.update_data(kind="report", ref_id=report_id,
                            conv_id=conv["id"], target_user=rep["reporter_id"],
                            as_staff=True)
    await cb.message.answer("✍️ Напиши сообщение автору жалобы:")


@router_staff.message(ConvFSM.waiting_staff_message, IsPrivateChat())
async def conv_staff_send(message: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    conv_id = data.get("conv_id")
    kind = data.get("kind")
    ref_id = data.get("ref_id")
    target_user = data.get("target_user")
    if not conv_id or not target_user:
        await state.clear()
        return

    photo_id = message.photo[-1].file_id if message.photo else None
    video_id = message.video.file_id if message.video else None
    text = message.caption or message.text or ""

    await add_conv_message(conv_id, message.from_user.id, is_mod=True,
                            text=text, photo_id=photo_id, video_id=video_id)

    kb = conv_reply_kb(kind, ref_id, message.from_user.id)
    body = (
        "💬 <b>Сообщение от модератора</b>\n"
        "(по " + kind + " #" + str(ref_id) + ")\n\n" + (text or "—")
    )
    try:
        if photo_id:
            await bot.send_photo(target_user, photo_id, caption=body, reply_markup=kb)
        elif video_id:
            await bot.send_video(target_user, video_id, caption=body, reply_markup=kb)
        else:
            await bot.send_message(target_user, body, reply_markup=kb)
    except Exception as e:
        await message.answer("Не смог отправить: " + str(e))
        await state.clear()
        return

    await state.clear()
    await message.answer("✅ Отправлено.")


@router_staff.callback_query(F.data.startswith("conv_staff_reply:"))
async def conv_staff_reply(cb: CallbackQuery, state: FSMContext):
    conv_id = int(cb.data.split(":")[1])
    conv = await get_conversation(conv_id)
    if not conv or conv["status"] == "closed":
        await safe_answer(cb, "Диалог закрыт", alert=True)
        return
    if conv.get("moderator_id") and conv["moderator_id"] != cb.from_user.id:
        await safe_answer(cb, "Диалог ведёт другой модератор", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(ConvFSM.waiting_staff_message)
    await state.update_data(kind=conv["kind"], ref_id=conv["ref_id"],
                            conv_id=conv_id, target_user=conv["user_id"],
                            as_staff=True)
    await cb.message.answer("✍️ Напиши сообщение пользователю:")


@router_staff.callback_query(F.data.startswith("conv_close:"))
async def conv_close(cb: CallbackQuery, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    conv_id = int(cb.data.split(":")[1])
    conv = await get_conversation(conv_id)
    if not conv:
        await safe_answer(cb, "Не найдено", alert=True)
        return
    if conv.get("moderator_id") and conv["moderator_id"] != cb.from_user.id:
        await safe_answer(cb, "Диалог ведёт другой модератор", alert=True)
        return

    await safe_answer(cb, "Закрыто")
    await close_conversation(conv_id)
    try:
        await bot.send_message(conv["user_id"], "🔒 Диалог закрыт модератором.")
    except Exception:
        pass
    await cb.message.answer("🔒 Диалог закрыт.")


# ---- Апелляции: список ----
@router_staff.callback_query(F.data == "staff:appeals")
async def cb_staff_appeals(cb: CallbackQuery):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    await safe_answer(cb)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM appeals WHERE status='pending' ORDER BY id ASC LIMIT 10")
        rows = [dict(r) for r in await cur.fetchall()]

    if not rows:
        await cb.message.answer("📭 Нет новых апелляций.")
        return

    for r in rows:
        u = await get_user(r["user_id"]) or {}
        from_mention = user_mention_by_id(
            r["user_id"],
            u.get("username"),
            u.get("full_name"),
        )
        body = (
            "⚖️ <b>Апелляция #" + str(r["id"]) + "</b>\n"
            "От: " + from_mention + "\n"
            "Текст: " + (r.get("text") or "—")
        )
        kb = appeal_review_kb(r["id"])
        try:
            if r.get("photo_id"):
                await cb.message.answer_photo(r["photo_id"], caption=body,
                                               reply_markup=kb)
            elif r.get("video_id"):
                await cb.message.answer_video(r["video_id"], caption=body,
                                               reply_markup=kb)
            else:
                await cb.message.answer(body, reply_markup=kb)
        except TelegramBadRequest as e:
            log.warning("appeals item: %s", e)


@router_staff.callback_query(F.data.startswith("appeal_change:"))
async def appeal_change(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await safe_answer(cb, "Не найдено", alert=True)
        return
    conv = await get_conversation_by_ref("appeal", appeal_id)
    if conv and not await claim_conversation(conv["id"], cb.from_user.id):
        await safe_answer(cb, "Ведёт другой модератор", alert=True)
        return
    await safe_answer(cb)
    await state.update_data(appeal_id=appeal_id, appeal_user=appeal["user_id"])
    await cb.message.answer("Выбери новый статус:",
                             reply_markup=status_choice_kb("appeal"))


@router_staff.callback_query(F.data.startswith("appeal:"))
async def appeal_apply(cb: CallbackQuery, state: FSMContext, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    new_status = cb.data.split(":", 1)[1]
    data = await state.get_data()
    appeal_id = data.get("appeal_id")
    user_id = data.get("appeal_user")
    if not user_id:
        await safe_answer(cb, "Данные потеряны", alert=True)
        return

    await safe_answer(cb, "Изменено")

    await set_status(user_id, new_status, "Решение по апелляции")
    await set_appeal_status(appeal_id, "changed", cb.from_user.id)
    await log_action(cb.from_user.id, "appeal_change:" + new_status,
                     user_id, "appeal=" + str(appeal_id))
    try:
        await bot.send_message(user_id,
            "⚖️ Апелляция рассмотрена. Новый статус: " + STATUS_LABELS[new_status])
    except Exception:
        pass
    await send_log(bot, "⚖️ Апелляция #" + str(appeal_id) + " → " +
                        STATUS_LABELS[new_status])
    await cb.message.answer("✅ Изменено.")
    await state.clear()


@router_staff.callback_query(F.data.startswith("appeal_reject:"))
async def appeal_reject(cb: CallbackQuery, state: FSMContext, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await safe_answer(cb, "Не найдено", alert=True)
        return
    await safe_answer(cb, "Отклонено")
    await set_appeal_status(appeal_id, "rejected", cb.from_user.id)
    try:
        await bot.send_message(appeal["user_id"], "❌ Апелляция отклонена.")
    except Exception:
        pass
    await cb.message.answer("Отклонено.")


@router_staff.callback_query(F.data.startswith("appeal_msg:"))
async def appeal_msg(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await safe_answer(cb, "Не найдено", alert=True)
        return
    conv = await get_conversation_by_ref("appeal", appeal_id)
    if conv and not await claim_conversation(conv["id"], cb.from_user.id):
        await safe_answer(cb, "Ведёт другой модератор", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(ConvFSM.waiting_staff_message)
    await state.update_data(kind="appeal", ref_id=appeal_id,
                            conv_id=conv["id"], target_user=appeal["user_id"],
                            as_staff=True)
    await cb.message.answer("✍️ Напиши сообщение автору апелляции:")


# ---- Статусы (модераторы) ----
@router_staff.callback_query(F.data == "admin_set_status")
async def admin_set_status(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.update_data(action="set")
    await state.set_state(StaffFSM.waiting_target)
    await cb.message.answer(
        "Отправь <code>@username</code>, <code>ID</code> или "
        "<code>@username ID</code>."
    )


@router_staff.message(StaffFSM.waiting_target, F.text, IsPrivateChat())
async def staff_target(message: Message, state: FSMContext):
    role = await get_user_role(message.from_user.id)
    if not await role_can_set_status(role):
        await state.clear()
        return

    data = await state.get_data()
    action = data.get("action", "set")
    arg = message.text.strip()
    target_id = None
    target_username = None
    for p in arg.split():
        if p.startswith("@"):
            target_username = p[1:]
        elif p.lstrip("-").isdigit():
            target_id = int(p)

    if target_id is None and target_username is None:
        await message.answer("Не понял.")
        return

    if target_id:
        existing = await get_user(target_id)
        if not existing:
            await upsert_user(target_id, target_username, None)
    if target_id is None and target_username:
        found = await get_user_by_username(target_username)
        if found:
            target_id = found["user_id"]
        else:
            await message.answer("❗ Нет в базе.")
            await state.clear()
            return

    await state.update_data(target_id=target_id, target_username=target_username)

    if action == "ban":
        await set_status(target_id, STATUS_BANNED, "Глобальный бан", None)
        await log_action(message.from_user.id, "ban_anywhere", target_id)
        await message.answer("⛔ <code>" + str(target_id) + "</code> забанен везде.")
        await state.clear()
        return

    if action == "reset":
        await set_status(target_id, STATUS_NORMAL, None, None)
        await log_action(message.from_user.id, "reset_status", target_id)
        await message.answer("🔁 Сброшено на «Обычный».")
        await state.clear()
        return

    await state.set_state(None)
    label = ("@" + target_username) if target_username else str(target_id)
    await message.answer("Выбери статус для <code>" + label + "</code>:",
                         reply_markup=status_choice_kb("set"))


@router_staff.callback_query(F.data.startswith("set:"))
async def staff_pick_status(cb: CallbackQuery, state: FSMContext, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    status = cb.data.split(":", 1)[1]
    data = await state.get_data()
    if status in (STATUS_SCAM, STATUS_SUSPICIOUS):
        await safe_answer(cb)
        await state.update_data(pending_status=status)
        await state.set_state(StaffFSM.waiting_reason)
        await cb.message.answer("Введи причину:")
    else:
        await safe_answer(cb, "Статус: " + STATUS_LABELS[status])
        await _apply_status(data.get("target_id"), data.get("target_username"),
                            status, None, None, cb.from_user.id, bot)
        await state.clear()
        await cb.message.answer("✅ Статус: " + STATUS_LABELS[status])


@router_staff.message(StaffFSM.waiting_reason, IsPrivateChat())
async def staff_reason(message: Message, state: FSMContext):
    await state.update_data(pending_reason=message.text)
    await state.set_state(StaffFSM.waiting_evidence)
    await message.answer("Пришли ссылку на доказательства или <code>-</code>.")


@router_staff.message(StaffFSM.waiting_evidence, IsPrivateChat())
async def staff_evidence(message: Message, state: FSMContext, bot: Bot):
    evidence = message.text.strip()
    if evidence == "-":
        evidence = None
    data = await state.get_data()
    await _apply_status(data.get("target_id"), data.get("target_username"),
                        data.get("pending_status"),
                        data.get("pending_reason"),
                        evidence, message.from_user.id, bot)
    await state.clear()
    await message.answer("✅ Обновлено.")


async def _apply_status(target_id, target_username, status,
                        reason, evidence_url, actor_id, bot: Bot):
    if target_id is None and target_username:
        found = await get_user_by_username(target_username)
        if found:
            target_id = found["user_id"]
    if target_id is None:
        return
    await set_status(target_id, status, reason, evidence_url,
                     username=target_username)
    await log_action(actor_id, "set_status:" + status, target_id,
                     "reason=" + str(reason) + "; evidence=" + str(evidence_url))
    actor = await get_user(actor_id) or {}
    actor_mention = user_mention_by_id(
        actor_id,
        actor.get("username"),
        actor.get("full_name"),
    )
    await send_log(bot,
        "📌 " + actor_mention + " установил <b>" + STATUS_LABELS[status] +
        "</b> → <code>" + str(target_id) + "</code>\n"
        "Причина: " + (reason or "—"))


@router_staff.callback_query(F.data == "admin_ban_anywhere")
async def admin_ban_start(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.update_data(action="ban")
    await state.set_state(StaffFSM.waiting_target)
    await cb.message.answer("Отправь @username или ID.")


@router_staff.callback_query(F.data == "admin_reset_status")
async def admin_reset_start(cb: CallbackQuery, state: FSMContext):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.update_data(action="reset")
    await state.set_state(StaffFSM.waiting_target)
    await cb.message.answer("Кому сбросить? Отправь @username или ID.")


@router_staff.callback_query(F.data == "admin_stats")
async def admin_stats(cb: CallbackQuery):
    role = await get_user_role(cb.from_user.id)
    if not await role_can_set_status(role):
        await safe_answer(cb, "Нет доступа", alert=True)
        return

    await safe_answer(cb)

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM users")
        total = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE status=?", (STATUS_SCAM,))
        scams = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE status=?", (STATUS_BANNED,))
        banned = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE role='moderator'")
        mods = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
        admins = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM appeals WHERE status='pending'")
        ap_pending = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM reports WHERE status='pending'")
        rp_pending = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM reports")
        rp_total = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM chats")
        chats = (await cur.fetchone())[0]

    await cb.message.answer(
        "📊 <b>Статистика</b>\n"
        "Всего юзеров: " + str(total) + "\n"
        "🚨 Скамеров: " + str(scams) + "\n"
        "⛔ Забанено: " + str(banned) + "\n"
        "🛡 Модераторов: " + str(mods) + "\n"
        "🛠 Админов: " + str(admins) + "\n"
        "💬 Чатов: " + str(chats) + "\n"
        "🚨 Жалоб новых: " + str(rp_pending) + " (всего " + str(rp_total) + ")\n"
        "⚖️ Апелляций новых: " + str(ap_pending)
    )


# ==========================================================
# STAFF: Мои группы (список)
# ==========================================================
@router_staff.callback_query(F.data == "staff:settings_list")
async def staff_settings_list(cb: CallbackQuery, bot: Bot):
    role = await get_user_role(cb.from_user.id)
    if role not in (ROLE_SUPER, ROLE_ADMIN, ROLE_MODERATOR):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    chats = await list_all_chats()
    my = []
    for c in chats:
        try:
            m = await bot.get_chat_member(c["chat_id"], cb.from_user.id)
            if m.status in (ChatMemberStatus.CREATOR, ChatMemberStatus.ADMINISTRATOR):
                my.append(c)
        except Exception:
            continue
    if not my:
        await cb.message.answer("ℹ️ Ты не админ ни в одной группе с ботом.")
        return
    await cb.message.answer("⚙️ Выбери группу:",
                             reply_markup=settings_chats_kb(my))


# ==========================================================
# SETTINGS — в группе и в личке
# ==========================================================
async def _show_settings(message_or_cb, chat_id: int, bot: Bot):
    title = "—"
    try:
        chat = await bot.get_chat(chat_id)
        title = chat.title or chat.full_name or str(chat_id)
    except Exception:
        pass

    s = await get_chat_settings(chat_id)
    welcome = s.get("welcome_text") or "<i>не задано — стандартное</i>"
    img_status = "✅ задана" if s.get("welcome_image") else "❌ не задана"
    reqs = await list_required_chats(chat_id)

    w_on = "✅ вкл" if s.get("welcome_enabled") else "❌ выкл"
    a_links = "✅ вкл" if s.get("antispam_links") else "❌ выкл"
    a_caps = "✅ вкл" if s.get("antispam_caps") else "❌ выкл"
    a_flood = "✅ вкл" if s.get("antispam_flood") else "❌ выкл"

    text = (
        "⚙️ <b>Настройки группы</b>\n"
        "📛 <b>" + title + "</b>\n\n"

        "👋 <b>Приветствие</b>: " + w_on + "\n"
        "  • Текст:\n" + welcome + "\n"
        "  • Картинка: " + img_status + "\n"
        "  • Переменные: <code>{group_name}</code>, <code>{username}</code>\n\n"

        "🛡 <b>Антиспам</b>:\n"
        "  • Ссылки: " + a_links + "\n"
        "  • Капс: " + a_caps + "\n"
        "  • Флуд: " + a_flood + "\n\n"

        "🔒 <b>Обязательных подписок:</b> " + str(len(reqs)) + "\n\n"

        "💡 Нажми на кнопку ниже, чтобы изменить."
    )

    kb = settings_menu(chat_id, s)
    if hasattr(message_or_cb, "answer"):
        await message_or_cb.answer(text, reply_markup=kb,
                                    disable_web_page_preview=True)


# --- /settings в группе ---
@router_group.message(Command("settings"), IsGroupChat())
async def cmd_settings_group(message: Message, bot: Bot):
    if not await is_chat_admin(bot, message.chat.id, message.from_user.id):
        await message.reply("⛔ Только админы группы.")
        return
    await _show_settings(message, message.chat.id, bot)


# --- /settings в личке ---
@router_user.message(Command("settings"), IsPrivateChat())
async def cmd_settings_private(message: Message, bot: Bot):
    chats = await list_all_chats()
    my = []
    for c in chats:
        try:
            m = await bot.get_chat_member(c["chat_id"], message.from_user.id)
            if m.status in (ChatMemberStatus.CREATOR, ChatMemberStatus.ADMINISTRATOR):
                my.append(c)
        except Exception:
            continue

    if not my:
        await message.answer(
            "ℹ️ Ты не админ ни одной группы, где есть бот.\n\n"
            "Добавь бота в свою группу и выдай ему права админа."
        )
        return
    if len(my) == 1:
        await _show_settings(message, my[0]["chat_id"], bot)
        return
    await message.answer("⚙️ Выбери группу:",
                          reply_markup=settings_chats_kb(my))


@router_user.callback_query(F.data.startswith("settings:open:"))
async def cb_settings_open(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data.split(":")[2])
    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await _show_settings(cb.message, chat_id, bot)


# --- Приветствие: текст ---
@router_user.callback_query(F.data.startswith("settings:welcome:"))
@router_group.callback_query(F.data.startswith("settings:welcome:"))
async def cb_settings_welcome(cb: CallbackQuery, state: FSMContext, bot: Bot):
    # не путать с settings:welcome_img
    parts = cb.data.split(":")
    if len(parts) != 3:
        await safe_answer(cb)
        return
    chat_id = int(parts[2])
    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(SettingsFSM.waiting_welcome)
    await state.update_data(chat_id=chat_id,
                            from_private=cb.message.chat.type == "private")
    await cb.message.answer(
        "✏️ Отправь новый текст приветствия.\n\n"
        "Переменные:\n"
        "• <code>{group_name}</code> — название группы\n"
        "• <code>{username}</code> — упоминание нового участника\n\n"
        "Пример: <code>Добро пожаловать в {group_name}, {username}! 🎉</code>\n\n"
        "Отправь <code>-</code>, чтобы сбросить на стандартный."
    )


@router_user.message(SettingsFSM.waiting_welcome, IsPrivateChat())
@router_group.message(SettingsFSM.waiting_welcome, IsGroupChat())
async def settings_set_welcome(message: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    chat_id = data.get("chat_id")
    if not chat_id:
        await state.clear()
        return
    if not await is_chat_admin(bot, chat_id, message.from_user.id):
        await state.clear()
        return
    text = message.text or ""
    if text == "-":
        text = None
    await set_welcome_text(chat_id, text)
    await state.clear()
    await message.reply("✅ Текст приветствия обновлён.")
    if data.get("from_private"):
        await _show_settings(message, chat_id, bot)


# --- Приветствие: картинка ---
@router_user.callback_query(F.data.startswith("settings:welcome_img:"))
@router_group.callback_query(F.data.startswith("settings:welcome_img:"))
async def cb_settings_welcome_img(cb: CallbackQuery, state: FSMContext, bot: Bot):
    chat_id = int(cb.data.split(":")[2])
    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(SettingsFSM.waiting_welcome_img)
    await state.update_data(chat_id=chat_id,
                            from_private=cb.message.chat.type == "private")
    await cb.message.answer(
        "🖼 Отправь картинку для приветствия (одним фото).\n"
        "Отправь <code>-</code>, чтобы убрать."
    )


@router_user.message(SettingsFSM.waiting_welcome_img, IsPrivateChat())
@router_group.message(SettingsFSM.waiting_welcome_img, IsGroupChat())
async def settings_set_welcome_img(message: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    chat_id = data.get("chat_id")
    if not chat_id:
        await state.clear()
        return
    if not await is_chat_admin(bot, chat_id, message.from_user.id):
        await state.clear()
        return
    if (message.text or "").strip() == "-":
        await set_welcome_image(chat_id, None)
        await state.clear()
        await message.reply("✅ Картинка убрана.")
        if data.get("from_private"):
            await _show_settings(message, chat_id, bot)
        return
    if not message.photo:
        await message.reply("❗ Отправь фото или <code>-</code>.")
        return
    await set_welcome_image(chat_id, message.photo[-1].file_id)
    await state.clear()
    await message.reply("✅ Картинка приветствия обновлена.")
    if data.get("from_private"):
        await _show_settings(message, chat_id, bot)


# --- Переключатели ---
@router_user.callback_query(F.data.startswith("settings:toggle:"))
@router_group.callback_query(F.data.startswith("settings:toggle:"))
async def cb_settings_toggle(cb: CallbackQuery, bot: Bot):
    parts = cb.data.split(":")
    # settings:toggle:<key>:<chat_id>
    if len(parts) != 4:
        await safe_answer(cb)
        return
    _, _, key, chat_id_str = parts
    chat_id = int(chat_id_str)
    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    new_val = await toggle_chat_setting(chat_id, key)
    if new_val is None:
        await safe_answer(cb, "Неизвестный параметр", alert=True)
        return
    await safe_answer(cb, "Вкл" if new_val else "Выкл")
    await _show_settings(cb.message, chat_id, bot)


# --- Добавить подписку ---
@router_user.callback_query(F.data.startswith("settings:required:"))
@router_group.callback_query(F.data.startswith("settings:required:"))
async def cb_settings_required(cb: CallbackQuery, state: FSMContext, bot: Bot):
    chat_id = int(cb.data.split(":")[2])
    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb)
    await state.set_state(SettingsFSM.waiting_req_chat)
    await state.update_data(chat_id=chat_id,
                            from_private=cb.message.chat.type == "private")
    await cb.message.answer(
        "🔒 Отправь ссылку на канал/группу для обязательной подписки:\n"
        "Например: <code>@mychannel</code> или <code>https://t.me/mychannel</code>\n\n"
        "⚠️ Бот должен быть добавлен в этот канал/группу."
    )


@router_user.message(SettingsFSM.waiting_req_chat, IsPrivateChat())
@router_group.message(SettingsFSM.waiting_req_chat, IsGroupChat())
async def settings_set_req_chat(message: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    chat_id = data.get("chat_id")
    if not chat_id:
        await state.clear()
        return
    if not await is_chat_admin(bot, chat_id, message.from_user.id):
        await state.clear()
        return
    username, link = parse_link(message.text or "")
    if not username:
        await message.reply("❌ Неверная ссылка.")
        return
    title = await get_chat_title(bot, username)
    req_chat_id = None
    try:
        chat = await bot.get_chat("@" + username)
        req_chat_id = chat.id
    except Exception as e:
        await message.reply("❌ Не могу получить чат. " + str(e))
        return
    await state.update_data(req_chat_id=req_chat_id,
                            req_username=username, title=title, link=link)
    await state.set_state(SettingsFSM.waiting_req_time)
    await message.reply("⏱ Срок действия: <code>30m</code>, <code>1h</code>, "
                        "<code>7d</code> или <code>0</code> (бессрочно).")


@router_user.message(SettingsFSM.waiting_req_time, IsPrivateChat())
@router_group.message(SettingsFSM.waiting_req_time, IsGroupChat())
async def settings_set_req_time(message: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    chat_id = data.get("chat_id")
    if not chat_id:
        await state.clear()
        return
    if not await is_chat_admin(bot, chat_id, message.from_user.id):
        await state.clear()
        return
    raw = (message.text or "").strip().lower()
    expire_at = parse_duration(raw)
    if raw != "0" and expire_at is None:
        await message.reply("❌ Формат: 30m, 1h, 7d, 0.")
        return
    await add_required_chat(
        chat_id=chat_id,
        req_chat_id=data.get("req_chat_id"),
        req_username=data.get("req_username"),
        title=data.get("title"),
        link=data.get("link"),
        expire_at=expire_at.isoformat() if expire_at else None,
        added_by=message.from_user.id,
    )
    await log_action(message.from_user.id, "add_required_chat", chat_id,
                     "req=" + str(data.get("req_username")))
    await message.reply("✅ Подписка добавлена.")
    await state.clear()
    if data.get("from_private"):
        await _show_settings(message, chat_id, bot)


# --- Список подписок ---
@router_user.callback_query(F.data.startswith("settings:list:"))
@router_group.callback_query(F.data.startswith("settings:list:"))
async def cb_settings_list(cb: CallbackQuery, bot: Bot):
    chat_id = int(cb.data.split(":")[2])
    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    reqs = await list_required_chats(chat_id)
    await safe_answer(cb)
    if not reqs:
        await cb.message.answer("ℹ️ Список пуст.")
        return
    text = "📋 <b>Обязательные подписки:</b>\n\n"
    for r in reqs:
        title = r["title"] or ("@" + r["req_username"])
        exp = r["expire_at"]
        text += "• <a href=\"" + r["link"] + "\">" + title + "</a> — "
        text += "бессрочно\n" if not exp else "до " + exp[:16] + "\n"
    await cb.message.answer(text, reply_markup=remgroup_kb(chat_id, reqs),
                             disable_web_page_preview=True)


@router_user.callback_query(F.data.startswith("remgroup:"))
@router_group.callback_query(F.data.startswith("remgroup:"))
async def cb_remgroup(cb: CallbackQuery, bot: Bot):
    _, chat_id_str, req_id_str = cb.data.split(":")
    chat_id = int(chat_id_str)
    req_id = int(req_id_str)
    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await safe_answer(cb, "Нет доступа", alert=True)
        return
    await safe_answer(cb, "Удалено")
    await delete_required_chat(req_id)
    await log_action(cb.from_user.id, "delete_required_chat", chat_id,
                     "req_id=" + str(req_id))
    try:
        await cb.message.delete()
    except Exception:
        pass


# ==========================================================
# GROUP: /check, /report
# ==========================================================
@router_group.message(Command("check"), IsGroupChat())
async def cmd_check(message: Message):
    target_id = None
    target_username = None
    target_name = None
    if message.reply_to_message and message.reply_to_message.from_user:
        u = message.reply_to_message.from_user
        target_id, target_username, target_name = u.id, u.username, u.full_name
    else:
        parts = (message.text or "").split(maxsplit=1)
        if len(parts) < 2:
            await message.reply("Использование: /check @username или /check ID, "
                                "либо реплаем.")
            return
        arg = parts[1].strip()
        if arg.startswith("@"):
            target_username = arg[1:]
        elif arg.lstrip("-").isdigit():
            target_id = int(arg)
        else:
            await message.reply("Некорректно.")
            return

    user = None
    if target_id:
        user = await get_user(target_id)
    if not user and target_username:
        user = await get_user_by_username(target_username)

    if user:
        await send_status_card(message, user, reply_to=message)
    else:
        await message.reply(
            "📇 <b>Проверка</b>\n"
            "ID: <code>" + str(target_id or "—") + "</code>\n"
            "Имя: " + (target_name or "—") + "\n"
            "Юзернейм: @" + (target_username or "—") + "\n"
            "Статус: " + STATUS_LABELS[STATUS_NORMAL] + "\n\n"
            "<i>Пользователя нет в базе.</i>"
        )


@router_group.message(Command("report"), IsGroupChat())
async def cmd_report(message: Message, bot: Bot):
    target = None
    if message.reply_to_message and message.reply_to_message.from_user:
        target = message.reply_to_message.from_user
    if not target:
        await message.reply(
            "Использование: <b>реплаем</b> на сообщение → /report"
        )
        return
    if target.is_bot:
        await message.reply("Нельзя пожаловаться на бота.")
        return

    await upsert_user(target.id, target.username, target.full_name)
    me = await bot.get_me()
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="📨 Открыть бота и пожаловаться",
            url="https://t.me/" + me.username + "?start=report_" + str(target.id))],
    ])
    target_mention = user_mention(target)
    await message.reply(
        "🚨 Жалоба на " + target_mention + "\n\n"
        "Перейди в бота — там отправь доказательства одним сообщением.",
        reply_markup=kb,
    )


# ==========================================================
# GROUP: приветствие, кик
# ==========================================================
@router_group.chat_member()
async def on_chat_member(event: ChatMemberUpdated, bot: Bot):
    new = event.new_chat_member
    old = event.old_chat_member
    invalidate_admin_cache(event.chat.id)

    if old.status in ("left", "kicked") and new.status in ("member", "administrator"):
        u = new.user
        s = await get_chat_settings(event.chat.id)
        if s.get("welcome_enabled"):
            if u.username:
                mention = "@" + u.username
            else:
                mention = "<a href=\"tg://user?id=" + str(u.id) + "\">" + str(u.full_name) + "</a>"
            template = s.get("welcome_text")
            if template:
                text = template.replace("{group_name}", event.chat.title or "группа")
                text = text.replace("{username}", mention)
            else:
                text = ("👋 Добро пожаловать в <b>" + (event.chat.title or "этот чат") +
                        "</b>, " + mention + "!\n\nПриятного общения! 🎉")

            welcome_img = s.get("welcome_image")
            try:
                if welcome_img:
                    await bot.send_photo(event.chat.id, welcome_img,
                        caption=_cut_caption(text))
                else:
                    await send_photo_cached(bot, event.chat.id, IMAGE_HELLO, text,
                                            cache_prefix="banner")
            except Exception as e:
                log.warning("Приветствие: %s", e)

    if new.status in ("member", "restricted"):
        u_db = await get_user(new.user.id)
        if u_db and u_db.get("status") == STATUS_BANNED:
            try:
                await bot.ban_chat_member(event.chat.id, new.user.id)
                await bot.unban_chat_member(event.chat.id, new.user.id)
            except Exception:
                pass


@router_group.my_chat_member()
async def bot_added(event: ChatMemberUpdated, bot: Bot):
    if event.new_chat_member.status in ("member", "administrator"):
        await register_chat(event.chat.id, event.chat.title or str(event.chat.id))
        invalidate_admin_cache(event.chat.id)
        try:
            text = (
                "👋 Привет! Я бот-помощник.\n\n"
                "<code>/check @username</code> — проверить\n"
                "<code>/report</code> реплаем — пожаловаться\n"
                "<code>/settings</code> — настройки (админ группы)"
            )
            await send_photo_cached(bot, event.chat.id, IMAGE_HELLO, text,
                                    cache_prefix="banner")
        except Exception:
            pass


@router_group.message(F.text | F.caption, IsGroupChat())
async def group_autoreply_status(message: Message):
    if is_command(message):
        return
    u = await get_user(message.from_user.id)
    if not u:
        return
    if u.get("status") in (STATUS_SCAM, STATUS_BANNED):
        await send_status_card(message, u, reply_to=message)


# ==========================================================
# DEEPLINK /start=report_<id>
# ==========================================================
@router_user.message(CommandStart(deep_link=True), IsPrivateChat())
async def user_start_deeplink(message: Message, state: FSMContext, bot: Bot):
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].startswith("report_"):
        return await user_start(message, state, bot)
    try:
        target_id = int(args[1].split("_", 1)[1])
    except Exception:
        return await user_start(message, state, bot)
    await state.set_state(ReportFSM.waiting_evidence)
    target_user = await get_user(target_id) or {}
    target_mention = user_mention_by_id(
        target_id,
        target_user.get("username"),
        target_user.get("full_name"),
    )
    await message.answer(
        "📨 Жалоба на " + target_mention + "\n\n"
        "Отправь доказательства одним сообщением (текст, фото или видео).\n"
        "Можно начать с описания: <code>" + str(target_id) + " описание</code>"
    )


# ==========================================================
# ФОНОВАЯ ЗАДАЧА
# ==========================================================
async def cleaner_task():
    while True:
        try:
            await cleanup_expired_required_chats()
        except Exception as e:
            log.warning("cleaner: %s", e)
        await asyncio.sleep(600)


# ==========================================================
# ЗАПУСК
# ==========================================================
async def main():
    await init_db()
    bot = Bot(token=BOT_TOKEN,
              default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()

    await upsert_user(SUPER_ADMIN_ID)
    await set_user_role(SUPER_ADMIN_ID, ROLE_SUPER)

    global RESOLVED_LOG_ID
    if not RESOLVED_LOG_ID and LOG_GROUP_URL:
        RESOLVED_LOG_ID = await _resolve_group_id(bot, LOG_GROUP_URL, None)
        if RESOLVED_LOG_ID:
            log.info("LOG_GROUP_ID resolved: %s", RESOLVED_LOG_ID)

    global RESOLVED_EVIDENCE_ID
    if not RESOLVED_EVIDENCE_ID and EVIDENCE_GROUP_URL:
        RESOLVED_EVIDENCE_ID = await _resolve_group_id(bot, EVIDENCE_GROUP_URL, None)
        if RESOLVED_EVIDENCE_ID:
            log.info("EVIDENCE_GROUP_ID resolved: %s", RESOLVED_EVIDENCE_ID)

    dp.include_router(router_staff)
    dp.include_router(router_group)
    dp.include_router(router_user)

    await bot.delete_webhook(drop_pending_updates=True)
    log.info("%s запущен, главный админ=%s", BOT_NAME, SUPER_ADMIN_ID)

    asyncio.create_task(cleaner_task())
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
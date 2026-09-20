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
REPORT_GROUP_URL = os.getenv("REPORT_GROUP_URL", "https://t.me/")
EVIDENCE_GROUP_URL = os.getenv("EVIDENCE_GROUP_URL", REPORT_GROUP_URL)
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

# ==========================================================
# СТАТУСЫ
# ==========================================================
STATUS_SCAM = "scam"
STATUS_SUSPICIOUS = "suspicious"
STATUS_NORMAL = "normal"
STATUS_VERIFIED = "verified"
STATUS_BANNED = "banned"
STATUS_ADMIN = "admin"

STATUS_LABELS = {
    STATUS_SCAM: "🚨 Скамер",
    STATUS_SUSPICIOUS: "⚠️ Подозрительный",
    STATUS_NORMAL: "✅ Обычный",
    STATUS_VERIFIED: "🛡 Проверенный",
    STATUS_BANNED: "⛔ Забанен везде",
    STATUS_ADMIN: "👑 Администратор",
}

STATUS_IMAGES = {
    STATUS_SCAM: "scam.png",
    STATUS_SUSPICIOUS: "sus.png",
    STATUS_NORMAL: "def.png",
    STATUS_VERIFIED: "proof.png",
    STATUS_BANNED: "scam.png",
    STATUS_ADMIN: "admin.png",
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
# АНТИСПАМ: константы
# ==========================================================
LINK_REGEX = re.compile(
    r"(https?://\S+|t\.me/\S+|www\.\S+)",
    re.IGNORECASE,
)

USERNAME_ONLY_REGEX = re.compile(r"^@[A-Za-z0-9_]{5,32}$")

CAPS_MIN_LEN = 10
CAPS_RATIO = 0.7

FLOOD_WINDOW = 60
FLOOD_LIMIT = 10
FLOOD_MUTE_SECONDS = 300

flood_store = defaultdict(lambda: defaultdict(deque))


# ==========================================================
# КЕШИ ДЛЯ СКОРОСТИ
# ==========================================================
# Кеш админов чата: {(chat_id, user_id): (timestamp, bool)}
_ADMIN_CACHE: dict[tuple[int, int], tuple[float, bool]] = {}
_ADMIN_CACHE_TTL = 300  # 5 минут

# Кеш подписок: {(chat_id, user_id): (timestamp, bool)}
_SUB_CACHE: dict[tuple[int, int], tuple[float, bool]] = {}
_SUB_CACHE_TTL = 30  # 30 секунд

# Кеш требований чата: {chat_id: (timestamp, list[dict])}
_REQ_CACHE: dict[int, tuple[float, list]] = {}
_REQ_CACHE_TTL = 60


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


def invalidate_admin_cache(chat_id: int = None):
    if chat_id is None:
        _ADMIN_CACHE.clear()
    else:
        for k in list(_ADMIN_CACHE.keys()):
            if k[0] == chat_id:
                _ADMIN_CACHE.pop(k, None)


def invalidate_req_cache(chat_id: int = None):
    if chat_id is None:
        _REQ_CACHE.clear()
    else:
        _REQ_CACHE.pop(chat_id, None)


def invalidate_sub_cache(chat_id: int = None):
    if chat_id is None:
        _SUB_CACHE.clear()
    else:
        for k in list(_SUB_CACHE.keys()):
            if k[0] == chat_id:
                _SUB_CACHE.pop(k, None)


# ==========================================================
# Быстрые локальные проверки
# ==========================================================
def has_link(text: str) -> bool:
    if not text:
        return False
    cleaned = re.sub(r"@[A-Za-z0-9_]{5,32}", "", text)
    return bool(LINK_REGEX.search(cleaned))


def is_caps(text: str) -> bool:
    if not text:
        return False
    letters = [c for c in text if c.isalpha()]
    if len(letters) < CAPS_MIN_LEN:
        return False
    upper = sum(1 for c in letters if c.isupper())
    return (upper / len(letters)) >= CAPS_RATIO


def normalize_text(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", text.strip().lower())


def is_flood(chat_id: int, user_id: int, text: str) -> bool:
    now = time.time()
    bucket = flood_store[chat_id][user_id]
    norm = normalize_text(text)
    while bucket and (now - bucket[0][0]) > FLOOD_WINDOW:
        bucket.popleft()
    same = sum(1 for ts, t in bucket if t == norm)
    bucket.append((now, norm))
    return same >= FLOOD_LIMIT


def clear_flood(chat_id: int, user_id: int):
    flood_store[chat_id].pop(user_id, None)


# ==========================================================
# РАБОТА С КАРТИНКАМИ
# ==========================================================
def template_path(filename: str) -> str:
    return os.path.join(TEMPLATES_DIR, filename)


def template_exists(filename: str) -> bool:
    return os.path.isfile(template_path(filename))


def compressed_template_path(filename: str) -> str:
    return os.path.join(TEMPLATES_CACHE_DIR, filename)


def compress_image(src: str, dst: str, max_side: int = 1280, quality: int = 85):
    if not HAS_PIL:
        return src
    try:
        img = Image.open(src)
        img = img.convert("RGB")
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


def prepare_image(filename: str):
    src = template_path(filename)
    if not os.path.isfile(src):
        log.warning("Шаблон не найден: %s", src)
        return None
    dst = compressed_template_path(filename)
    if (not os.path.isfile(dst)
            or os.path.getmtime(src) > os.path.getmtime(dst)):
        return compress_image(src, dst)
    return dst


def _cut_caption(text: str) -> str:
    if len(text) <= MAX_CAPTION:
        return text
    return text[:MAX_CAPTION - 20] + "\n\n<i>…(сокращено)</i>"


# ==========================================================
# ФИЛЬТРЫ
# ==========================================================
class IsSuperAdmin(BaseFilter):
    async def __call__(self, event) -> bool:
        user = getattr(event, "from_user", None)
        return bool(user and user.id == SUPER_ADMIN_ID)


class IsNotSuperAdmin(BaseFilter):
    async def __call__(self, event) -> bool:
        user = getattr(event, "from_user", None)
        return bool(user and user.id != SUPER_ADMIN_ID)


class IsPrivateChat(BaseFilter):
    async def __call__(self, event) -> bool:
        chat = getattr(event, "chat", None)
        if chat is None and hasattr(event, "message"):
            chat = event.message.chat
        return bool(chat and chat.type == "private")


class IsGroupChat(BaseFilter):
    async def __call__(self, event) -> bool:
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
            reason       TEXT,
            evidence_url TEXT,
            updated_at   TEXT
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
        await db.commit()
    log.info("База данных готова: %s", DB_PATH)


async def upsert_user(user_id, username=None, full_name=None):
    status = STATUS_ADMIN if user_id == SUPER_ADMIN_ID else STATUS_NORMAL
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO users (user_id, username, full_name, status, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username=COALESCE(excluded.username, users.username),
                full_name=COALESCE(excluded.full_name, users.full_name),
                status=CASE WHEN excluded.status='admin' THEN 'admin'
                            ELSE users.status END,
                updated_at=excluded.updated_at
        """, (user_id, username, full_name, status,
              datetime.utcnow().isoformat()))
        await db.commit()


async def get_user(user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def get_user_by_username(username):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (username,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def set_status(user_id, status, reason=None, evidence_url=None,
                     username=None, full_name=None):
    if status == STATUS_ADMIN and user_id != SUPER_ADMIN_ID:
        return
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


async def set_appeal_status(appeal_id, status):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE appeals SET status=? WHERE id=?",
                         (status, appeal_id))
        await db.commit()


async def log_action(admin_id, action, target_id=None, payload=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO action_log (admin_id, action, target_id, payload, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (admin_id, action, target_id, payload,
              datetime.utcnow().isoformat()))
        await db.commit()


async def is_banned_anywhere(user_id):
    u = await get_user(user_id)
    return bool(u and u["status"] == STATUS_BANNED)


async def register_chat(chat_id, title):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO chats (chat_id, title, added_at) VALUES (?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET title=excluded.title
        """, (chat_id, title, datetime.utcnow().isoformat()))
        await db.commit()


async def get_cached_file_id(key: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT file_id FROM media_cache WHERE key=?", (key,))
        row = await cur.fetchone()
        return row[0] if row else None


async def cache_file_id(key: str, file_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO media_cache (key, file_id, added_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET file_id=excluded.file_id
        """, (key, file_id, datetime.utcnow().isoformat()))
        await db.commit()


async def delete_cached_file_id(key: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM media_cache WHERE key=?", (key,))
        await db.commit()


# ==========================================================
# БАЗА: ОБЯЗАТЕЛЬНЫЕ ГРУППЫ
# ==========================================================
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
    invalidate_sub_cache(chat_id)


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
    """С кешем на 60 секунд."""
    cached = _cache_get(_REQ_CACHE, chat_id, _REQ_CACHE_TTL)
    if cached is not None:
        return cached
    reqs = await list_required_chats_db(chat_id)
    _cache_set(_REQ_CACHE, chat_id, reqs)
    return reqs


async def delete_required_chat(req_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT chat_id FROM required_chats WHERE id=?", (req_id,))
        row = await cur.fetchone()
        if row:
            chat_id = row[0]
        else:
            chat_id = None
        await db.execute("DELETE FROM required_chats WHERE id=?", (req_id,))
        await db.commit()
    if chat_id is not None:
        invalidate_req_cache(chat_id)
        invalidate_sub_cache(chat_id)


async def cleanup_expired_required_chats():
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM required_chats WHERE expire_at IS NOT NULL AND expire_at <= ?",
            (now,))
        await db.commit()
    invalidate_req_cache()
    invalidate_sub_cache()


# ==========================================================
# УТИЛИТЫ
# ==========================================================
def parse_duration(raw: str):
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


def parse_link(raw: str):
    raw = raw.strip()
    if raw.startswith("@"):
        username = raw[1:]
        return username, f"https://t.me/{username}"
    m = re.fullmatch(r"(?:https?://)?t\.me/([A-Za-z0-9_]+)/?", raw)
    if m:
        username = m.group(1)
        return username, f"https://t.me/{username}"
    return None, None


async def get_chat_title(bot: Bot, username: str) -> str:
    try:
        chat = await bot.get_chat(f"@{username}")
        return chat.title or chat.full_name or f"@{username}"
    except Exception:
        return f"@{username}"


async def is_user_subscribed(bot: Bot, user_id: int, req: dict) -> bool:
    """С кешем на 30 секунд."""
    key = (req["req_chat_id"] or 0, user_id)
    cached = _cache_get(_SUB_CACHE, key, _SUB_CACHE_TTL)
    if cached is not None:
        return cached
    try:
        member = await bot.get_chat_member(
            req["req_chat_id"] or f"@{req['req_username']}", user_id)
        ok = member.status in (
            ChatMemberStatus.CREATOR,
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.MEMBER,
            ChatMemberStatus.RESTRICTED,
        )
    except TelegramBadRequest as e:
        log.info("get_chat_member %s@%s: %s", user_id, req["req_username"], e)
        ok = False
    except Exception as e:
        log.warning("Ошибка проверки подписки: %s", e)
        ok = False
    _cache_set(_SUB_CACHE, key, ok)
    return ok


async def check_user_all_subscriptions(bot: Bot, user_id: int, chat_id: int):
    """Параллельно проверяет все требования."""
    reqs = await list_required_chats(chat_id)
    if not reqs:
        return []
    results = await asyncio.gather(
        *(is_user_subscribed(bot, user_id, r) for r in reqs),
        return_exceptions=False,
    )
    return [r for r, ok in zip(reqs, results) if not ok]


def user_mention(user) -> str:
    if user.username:
        return f"@{user.username}"
    return f'<a href="tg://user?id={user.id}">{user.full_name}</a>'


async def is_chat_admin(bot: Bot, chat_id: int, user_id: int) -> bool:
    """С кешем на 5 минут. Главный админ — всегда True."""
    if user_id == SUPER_ADMIN_ID:
        return True
    key = (chat_id, user_id)
    cached = _cache_get(_ADMIN_CACHE, key, _ADMIN_CACHE_TTL)
    if cached is not None:
        return cached
    try:
        m = await bot.get_chat_member(chat_id, user_id)
        ok = m.status in (ChatMemberStatus.CREATOR,
                           ChatMemberStatus.ADMINISTRATOR)
    except Exception:
        ok = False
    _cache_set(_ADMIN_CACHE, key, ok)
    return ok


async def is_chat_admin_fast(bot: Bot, chat_id: int, user_id: int) -> bool:
    """
    Быстрая проверка админа через кеш. Если нет — считаем не админом
    и запрашиваем обновление в фоне.
    """
    if user_id == SUPER_ADMIN_ID:
        return True
    key = (chat_id, user_id)
    cached = _cache_get(_ADMIN_CACHE, key, _ADMIN_CACHE_TTL)
    if cached is not None:
        return cached
    # Нет в кеше — не блокируем. Обновим в фоне.
    asyncio.create_task(is_chat_admin(bot, chat_id, user_id))
    return False


# ==========================================================
# ОТПРАВКА КАРТИНОК С КЭШЕМ
# ==========================================================
async def send_photo_cached(
    bot_or_message,
    chat_id,
    img_name: str,
    caption: str,
    reply_markup=None,
    reply_to_message_id=None,
    cache_prefix: str = "img",
):
    cache_key = f"{cache_prefix}:{img_name}"
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
            log.warning("Кэш %s не сработал (%s) — удаляю", cache_key, e)
            await delete_cached_file_id(cache_key)

    img_full = prepare_image(img_name)
    if img_full is None:
        return await _send_text()

    try:
        msg = await _send_photo(FSInputFile(img_full))
    except Exception as e:
        log.warning("send_photo(%s) упал: %s — отправляю текстом",
                    img_name, e)
        return await _send_text()

    if msg and getattr(msg, "photo", None):
        try:
            await cache_file_id(cache_key, msg.photo[-1].file_id)
        except Exception as e:
            log.warning("Не смог закэшировать file_id: %s", e)
    return msg


# ==========================================================
# КАРТОЧКА
# ==========================================================
async def send_status_card(target, user_data: dict, extra_text: str = "",
                           reply_to: Message | None = None):
    status = user_data.get("status", STATUS_NORMAL)
    label = STATUS_LABELS.get(status, status)
    img_name = STATUS_IMAGES.get(status, IMAGE_NORMAL_FALLBACK)

    text = (
        f"📇 <b>Карточка</b>\n"
        f"ID: <code>{user_data.get('user_id', '—')}</code>\n"
        f"Имя: {user_data.get('full_name') or '—'}\n"
        f"Юзернейм: @{user_data.get('username') or '—'}\n"
        f"Статус: {label}\n"
    )
    if user_data.get("reason"):
        text += f"Причина: {user_data['reason']}\n"
    if extra_text:
        text += f"\n{extra_text}"

    kb = profile_kb(
        user_data.get("user_id") or 0,
        user_data.get("evidence_url"),
        user_data.get("username"),
    )
    reply_to_id = reply_to.message_id if reply_to else None

    return await send_photo_cached(
        target, None, img_name, text,
        reply_markup=kb,
        reply_to_message_id=reply_to_id,
        cache_prefix="status",
    )


# ==========================================================
# АВТО-СОХРАНЕНИЕ
# ==========================================================
async def auto_save_from_message(message: Message):
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
# ГЕЙТ ПОДПИСКИ — УДАЛЕНИЕ МГНОВЕННОЕ
# ==========================================================
def _is_service_message(event: Message) -> bool:
    return bool(
        event.new_chat_members or event.left_chat_member
        or event.new_chat_title or event.new_chat_photo
        or event.delete_chat_photo or event.pinned_message
        or event.group_chat_created or event.supergroup_chat_created
        or event.channel_chat_created or event.migrate_to_chat_id
        or event.migrate_from_chat_id
    )


class SubscriptionGateMiddleware(BaseMiddleware):
    """
    Сначала — быстрые локальные проверки. Если чат точно не имеет
    требований (кеш), сразу пропускаем. Если имеет и юзер не в кеше
    админов — удаляем сообщение, потом уже проверяем всё остальное.
    """

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

        # === БЫСТРАЯ ПРОВЕРКА ИЗ КЕША ===
        reqs = _cache_get(_REQ_CACHE, chat.id, _REQ_CACHE_TTL)
        if reqs is None:
            # Кеша нет — грузим в фоне, а пока пропускаем
            asyncio.create_task(list_required_chats(chat.id))
            return await handler(event, data)

        if not reqs:
            # Требований нет — сразу пропускаем без сетевых запросов
            return await handler(event, data)

        # === ЕСТЬ ТРЕБОВАНИЯ. Проверяем админа быстро из кеша ===
        admin_flag = _cache_get(_ADMIN_CACHE, (chat.id, user.id),
                                _ADMIN_CACHE_TTL)
        if admin_flag is True:
            return await handler(event, data)

        text = event.text or event.caption or ""
        if text.startswith("/"):
            return await handler(event, data)

        # === БЫСТРАЯ ПРОВЕРКА ПОДПИСОК ИЗ КЕША ===
        # Если для юзера есть ВСЕ результаты по всем требованиям и
        # среди них нет False — пропускаем. Если есть хоть один False —
        # сразу удаляем, не ждём.
        missing_cached = []
        all_cached = True
        for r in reqs:
            key = (r["req_chat_id"] or 0, user.id)
            v = _cache_get(_SUB_CACHE, key, _SUB_CACHE_TTL)
            if v is None:
                all_cached = False
                break
            if not v:
                missing_cached.append(r)

        if all_cached:
            if not missing_cached:
                return await handler(event, data)
            # Юзер точно не подписан — удаляем немедленно
            await _delete_and_notify(event, user, missing_cached,
                                     reason="подписка")
            return

        # Кеша нет — надо проверить через API. Чтобы не тормозить,
        # удаляем сразу (если триггер — не подписка), а полную проверку
        # делаем после удаления. Если вдруг окажется, что юзер подписан —
        # ничего страшного, сообщение уже удалено.
        # НО: если требований несколько, а юзер подписан — его сообщение
        # удалять нельзя. Поэтому здесь компромисс: ждём проверку,
        # но все запросы идут параллельно.
        missing = await check_user_all_subscriptions(event.bot, user.id,
                                                     chat.id)
        if not missing:
            return await handler(event, data)

        await _delete_and_notify(event, user, missing, reason="подписка")
        return


async def _delete_and_notify(event: Message, user, missing: list, reason: str):
    """Удаляет сообщение и отправляет требование подписки."""
    chat = event.chat
    try:
        await event.bot.delete_message(chat.id, event.message_id)
        log.info("Удалено (%s) msg=%s user=%s chat=%s",
                 reason, event.message_id, user.id, chat.id)
    except TelegramForbiddenError as e:
        log.error("Нет права удалять в %s: %s", chat.id, e)
    except TelegramBadRequest as e:
        log.warning("Не смог удалить %s: %s", event.message_id, e)
    except Exception as e:
        log.warning("Ошибка удаления: %s", e)

    mention = user_mention(user)
    lines = [f"{mention}, 🚫 <b>чтобы писать в этом чате, "
             f"нужно подписаться на:</b>\n"]
    kb_rows = []
    for r in missing:
        title = r["title"] or f"@{r['req_username']}"
        link = r["link"]
        lines.append(f"• <a href=\"{link}\">{title}</a>")
        kb_rows.append([InlineKeyboardButton(text=f"📎 {title}", url=link)])

    text_out = "\n".join(lines) + "\n\n<i>После подписки напиши снова.</i>"
    kb = InlineKeyboardMarkup(inline_keyboard=kb_rows) if kb_rows else None

    try:
        await event.bot.send_message(chat.id, text_out,
                                      reply_markup=kb,
                                      disable_web_page_preview=True)
    except Exception as e:
        log.warning("Не смог отправить требование: %s", e)


# ==========================================================
# АНТИСПАМ — УДАЛЕНИЕ МГНОВЕННОЕ
# ==========================================================
class AntiSpamMiddleware(BaseMiddleware):
    """
    Сначала быстрые локальные проверки (ссылка/капс/флуд) — они не
    требуют сети. Если триггер сработал — удаляем немедленно.
    Только после удаления (или если триггеров нет) делаем проверки
    через сеть (админ ли чата).
    """

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

        text = event.text or event.caption or ""
        if not text or text.startswith("/"):
            return await handler(event, data)

        # === 1. БЫСТРАЯ ЛОКАЛЬНАЯ ПРОВЕРКА ТРИГГЕРОВ ===
        reason = None
        if USERNAME_ONLY_REGEX.match(text.strip()):
            pass
        elif has_link(text):
            reason = "ссылка"
        if reason is None and is_caps(text):
            reason = "капс"
        if reason is None and is_flood(chat.id, user.id, text):
            reason = "флуд"

        if reason is None:
            return await handler(event, data)

        # === 2. ПРОВЕРКА НА АДМИНА (БЫСТРО ИЗ КЕША) ===
        # Если кеш говорит, что это админ — не удаляем.
        admin_flag = _cache_get(_ADMIN_CACHE, (chat.id, user.id),
                                _ADMIN_CACHE_TTL)
        if admin_flag is True:
            return await handler(event, data)

        # === 3. МГНОВЕННОЕ УДАЛЕНИЕ ===
        try:
            await event.bot.delete_message(chat.id, event.message_id)
            log.info("AntiSpam: удалено msg=%s user=%s chat=%s reason=%s",
                     event.message_id, user.id, chat.id, reason)
        except TelegramForbiddenError as e:
            log.error("AntiSpam: нет права удалять в %s: %s", chat.id, e)
        except TelegramBadRequest as e:
            log.warning("AntiSpam: не смог удалить %s: %s",
                        event.message_id, e)
        except Exception as e:
            log.warning("AntiSpam: ошибка удаления: %s", e)

        # === 4. ПАРАЛЛЕЛЬНО: проверка админа (обновление кеша) и
        #               уведомление ===
        mention = user_mention(user)
        if reason == "ссылка":
            warn = f"{mention}, 🚫 ссылки в этом чате запрещены."
        elif reason == "капс":
            warn = f"{mention}, 🚫 не пиши капсом."
        elif reason == "флуд":
            warn = f"{mention}, 🚫 прекрати флудить."
            # Мут — отдельная задача, чтобы не тормозить ответ
            async def mute():
                try:
                    await event.bot.restrict_chat_member(
                        chat.id, user.id,
                        until_date=datetime.utcnow()
                                   + timedelta(seconds=FLOOD_MUTE_SECONDS),
                        can_send_messages=False,
                    )
                    clear_flood(chat.id, user.id)
                except Exception as e:
                    log.warning("AntiSpam: не смог замутить %s: %s",
                                user.id, e)
            asyncio.create_task(mute())
            warn += f"\nТы заглушен на {FLOOD_MUTE_SECONDS // 60} мин."
        else:
            warn = f"{mention}, 🚫 сообщение удалено."

        # Не ждём отправки предупреждения — шлём в фоне
        async def notify():
            try:
                await event.bot.send_message(chat.id, warn)
            except Exception as e:
                log.warning("AntiSpam: не смог отправить предупреждение: %s", e)

        asyncio.create_task(notify())

        # Обновляем кеш админов в фоне (на случай, если юзер — админ,
        # а кеш был пуст)
        if _cache_get(_ADMIN_CACHE, (chat.id, user.id),
                       _ADMIN_CACHE_TTL) is None:
            asyncio.create_task(is_chat_admin(event.bot, chat.id, user.id))

        # Не пропускаем дальше
        return


# ==========================================================
# КЛАВИАТУРЫ
# ==========================================================
def user_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚨 Пожаловаться", url=REPORT_GROUP_URL)],
        [InlineKeyboardButton(text="🔎 Проверить меня", callback_data="check_me")],
        [InlineKeyboardButton(text="👤 Проверить пользователя",
                              callback_data="check_user_hint")],
        [InlineKeyboardButton(text="⚖️ Обжаловать решение",
                              callback_data="appeal_start")],
    ])


def admin_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Добавить/изменить статус",
                              callback_data="admin_set_status")],
        [InlineKeyboardButton(text="⛔ Забанить везде",
                              callback_data="admin_ban_anywhere")],
        [InlineKeyboardButton(text="🔁 Сбросить статус",
                              callback_data="admin_reset_status")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="admin_stats")],
        [InlineKeyboardButton(text="📋 Группа жалоб и доказательств",
                              url=EVIDENCE_GROUP_URL)],
    ])


def status_choice_kb(prefix):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_SCAM],
                              callback_data=f"{prefix}:{STATUS_SCAM}")],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_SUSPICIOUS],
                              callback_data=f"{prefix}:{STATUS_SUSPICIOUS}")],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_NORMAL],
                              callback_data=f"{prefix}:{STATUS_NORMAL}")],
        [InlineKeyboardButton(text=STATUS_LABELS[STATUS_VERIFIED],
                              callback_data=f"{prefix}:{STATUS_VERIFIED}")],
    ])


def profile_kb(user_id, evidence_url, username):
    rows = []
    link = f"https://t.me/{username}" if username else f"tg://user?id={user_id}"
    rows.append([InlineKeyboardButton(text="👤 Открыть профиль", url=link)])
    if evidence_url:
        rows.append([InlineKeyboardButton(text="📎 Доказательства",
                                          url=evidence_url)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def appeal_admin_kb(appeal_id):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Поменять решение",
                              callback_data=f"appeal_change:{appeal_id}")],
        [InlineKeyboardButton(text="✍️ Написать ответ",
                              callback_data=f"appeal_reply:{appeal_id}")],
        [InlineKeyboardButton(text="❌ Отказать",
                              callback_data=f"appeal_reject:{appeal_id}")],
    ])


def remgroup_kb(chat_id, reqs):
    rows = []
    for r in reqs:
        title = r["title"] or f"@{r['req_username']}"
        btn_text = f"🗑 {title}"[:60]
        rows.append([InlineKeyboardButton(
            text=btn_text,
            callback_data=f"remgroup:{chat_id}:{r['id']}")])
    return InlineKeyboardMarkup(inline_keyboard=rows) if rows else None


# ==========================================================
# FSM
# ==========================================================
class AppealFSM(StatesGroup):
    waiting_evidence = State()


class AdminFSM(StatesGroup):
    waiting_target = State()
    waiting_reason = State()
    waiting_evidence = State()
    waiting_appeal_reply = State()


# ==========================================================
# РОУТЕРЫ
# ==========================================================
router_admin = Router()
router_group = Router()
router_user = Router()

router_user.message.outer_middleware(AutoRegisterMiddleware())
router_user.callback_query.outer_middleware(AutoRegisterMiddleware())
router_group.message.outer_middleware(AutoRegisterMiddleware())
router_group.callback_query.outer_middleware(AutoRegisterMiddleware())
router_group.chat_member.outer_middleware(AutoRegisterMiddleware())

# Порядок: сначала антиспам (локальные триггеры → мгновенное удаление),
# потом гейт подписки. Так мгновенно удаляются ссылки/капс/флуд,
# а подписка проверяется уже после.
router_group.message.outer_middleware(AntiSpamMiddleware())
router_group.message.outer_middleware(SubscriptionGateMiddleware())


# ---------------- USER ----------------
@router_user.message(CommandStart(), IsNotSuperAdmin(), IsPrivateChat())
async def user_start(message: Message, state: FSMContext):
    await state.clear()
    text = (
        f"👋 Привет! Это <b>{BOT_NAME}</b>.\n\n"
        "Помогаю собирать информацию о скамерах и проверять пользователей.\n"
        "Выбери действие:"
    )
    await send_photo_cached(message, None, IMAGE_START, text,
                            reply_markup=user_menu(),
                            cache_prefix="banner")


@router_user.callback_query(F.data == "check_me", IsPrivateChat())
async def check_me(cb: CallbackQuery):
    u = await get_user(cb.from_user.id)
    if not u:
        await upsert_user(cb.from_user.id, cb.from_user.username,
                          cb.from_user.full_name)
        u = await get_user(cb.from_user.id)
    await send_status_card(cb.message, u)
    await cb.answer()


@router_user.callback_query(F.data == "check_user_hint", IsPrivateChat())
async def check_user_hint(cb: CallbackQuery):
    await cb.message.answer(
        "Чтобы проверить пользователя:\n"
        "• в группе: <code>/check @username</code> или "
        "<code>/check 123456789</code>, либо ответом на его сообщение\n"
        "• либо перешли мне любое его сообщение"
    )
    await cb.answer()


@router_user.message(F.forward_from, IsPrivateChat())
async def check_forward(message: Message):
    t = message.forward_from
    u = await get_user(t.id)
    if not u:
        await upsert_user(t.id, t.username, t.full_name)
        u = await get_user(t.id)
    await send_status_card(message, u)


@router_user.message(F.forward_from_chat, IsPrivateChat())
async def check_forward_chat(message: Message):
    c = message.forward_from_chat
    u = await get_user(c.id) or {
        "user_id": c.id, "username": c.username,
        "full_name": c.title, "status": STATUS_NORMAL,
        "reason": None, "evidence_url": None,
    }
    await send_status_card(message, u)


@router_user.callback_query(F.data == "appeal_start", IsPrivateChat())
async def appeal_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(AppealFSM.waiting_evidence)
    await cb.message.answer(
        "⚖️ <b>Обжалование</b>\n\n"
        "Отправь одним сообщением доказательства: текст, фото или видео. "
        "Админ рассмотрит."
    )
    await cb.answer()


@router_user.message(AppealFSM.waiting_evidence, IsPrivateChat())
async def appeal_evidence(message: Message, state: FSMContext, bot: Bot):
    photo_id = message.photo[-1].file_id if message.photo else None
    video_id = message.video.file_id if message.video else None
    text = message.caption or message.text

    appeal_id = await add_appeal(message.from_user.id, text, photo_id, video_id)

    admin_text = (
        f"⚖️ <b>Новая апелляция #{appeal_id}</b>\n"
        f"От: {message.from_user.full_name} "
        f"(<code>{message.from_user.id}</code>, "
        f"@{message.from_user.username or '—'})\n"
        f"Текст: {text or '—'}"
    )
    try:
        if photo_id:
            await bot.send_photo(SUPER_ADMIN_ID, photo_id,
                                 caption=admin_text,
                                 reply_markup=appeal_admin_kb(appeal_id))
        elif video_id:
            await bot.send_video(SUPER_ADMIN_ID, video_id,
                                 caption=admin_text,
                                 reply_markup=appeal_admin_kb(appeal_id))
        else:
            await bot.send_message(SUPER_ADMIN_ID, admin_text,
                                   reply_markup=appeal_admin_kb(appeal_id))
    except Exception as e:
        log.warning("Не смог отправить апелляцию админу: %s", e)

    await state.clear()
    await message.answer("✅ Апелляция отправлена админу. Ожидай ответа.")


# ---------------- GROUP ----------------
@router_group.message(Command("addgroup"), IsGroupChat())
async def cmd_addgroup(message: Message, bot: Bot):
    if not await is_chat_admin(bot, message.chat.id, message.from_user.id):
        await message.reply("⛔ Только администраторы чата могут использовать эту команду.")
        return

    parts = (message.text or "").split()
    if len(parts) < 3:
        await message.reply(
            "Использование: <code>/addgroup &lt;ссылка&gt; &lt;время&gt;</code>\n\n"
            "Примеры:\n"
            "<code>/addgroup https://t.me/mychannel 1d</code>\n"
            "<code>/addgroup @mychannel 1h</code>\n"
            "<code>/addgroup @mychannel 0</code> — бессрочно\n\n"
            "Время: <code>30m</code>, <code>1h</code>, <code>7d</code>, "
            "<code>0</code> (бессрочно)."
        )
        return

    link_raw = parts[1]
    time_raw = parts[2]

    username, link = parse_link(link_raw)
    if not username:
        await message.reply("❌ Неверная ссылка. Пример: <code>@mychannel</code> "
                             "или <code>https://t.me/mychannel</code>")
        return

    expire_at = parse_duration(time_raw)
    if time_raw != "0" and expire_at is None:
        await message.reply("❌ Неверное время. Примеры: <code>30m</code>, "
                             "<code>1h</code>, <code>7d</code>, <code>0</code>.")
        return

    title = await get_chat_title(bot, username)
    req_chat_id = None
    try:
        chat = await bot.get_chat(f"@{username}")
        req_chat_id = chat.id
    except Exception as e:
        await message.reply(
            f"❌ Не могу получить чат <code>@{username}</code>.\n"
            f"Убедись, что бот добавлен в этот чат/канал.\n"
            f"<i>Причина: {e}</i>"
        )
        return

    await add_required_chat(
        chat_id=message.chat.id,
        req_chat_id=req_chat_id,
        req_username=username,
        title=title,
        link=link,
        expire_at=expire_at.isoformat() if expire_at else None,
        added_by=message.from_user.id,
    )
    await log_action(message.from_user.id,
                     "add_required_chat", message.chat.id,
                     f"req={username}; expire={expire_at}")

    until = "бессрочно" if expire_at is None else expire_at.strftime("%Y-%m-%d %H:%M UTC")
    await message.reply(
        f"✅ Добавлено требование подписки:\n"
        f"• <b>{title}</b> (<a href=\"{link}\">{link}</a>)\n"
        f"• Действует до: <b>{until}</b>"
    )


@router_group.message(Command("remgroup"), IsGroupChat())
async def cmd_remgroup(message: Message, bot: Bot):
    if not await is_chat_admin(bot, message.chat.id, message.from_user.id):
        await message.reply("⛔ Только администраторы чата могут использовать эту команду.")
        return

    reqs = await list_required_chats(message.chat.id)
    if not reqs:
        await message.reply("ℹ️ В этом чате нет обязательных подписок.")
        return

    text = ("📋 <b>Обязательные подписки этого чата</b>\n\n"
            "Нажми на кнопку, чтобы удалить требование:")
    kb = remgroup_kb(message.chat.id, reqs)
    await message.reply(text, reply_markup=kb)


@router_group.message(Command("listgroup"), IsGroupChat())
async def cmd_listgroup(message: Message, bot: Bot):
    if not await is_chat_admin(bot, message.chat.id, message.from_user.id):
        await message.reply("⛔ Только администраторы чата могут использовать эту команду.")
        return

    reqs = await list_required_chats(message.chat.id)
    if not reqs:
        await message.reply("ℹ️ В этом чате нет обязательных подписок.")
        return

    lines = ["📋 <b>Обязательные подписки:</b>\n"]
    for r in reqs:
        title = r["title"] or f"@{r['req_username']}"
        exp = r["expire_at"]
        until = "бессрочно" if not exp else exp.replace("T", " ")[:16] + " UTC"
        lines.append(f"• <a href=\"{r['link']}\">{title}</a> — до {until}")
    await message.reply("\n".join(lines), disable_web_page_preview=True)


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
            await message.reply(
                "Использование: <code>/check @username</code> или "
                "<code>/check 123456789</code>, либо ответом на сообщение."
            )
            return
        arg = parts[1].strip()
        if arg.startswith("@"):
            target_username = arg[1:]
        elif arg.lstrip("-").isdigit():
            target_id = int(arg)
        else:
            await message.reply("Некорректный аргумент.")
            return

    user = None
    if target_id:
        user = await get_user(target_id)
    if not user and target_username:
        user = await get_user_by_username(target_username)

    if user:
        target_id = user["user_id"]
        target_username = user.get("username") or target_username
        target_name = user.get("full_name") or target_name
        await send_status_card(message, user, reply_to=message)
    else:
        text = (
            f"📇 <b>Проверка</b>\n"
            f"ID: <code>{target_id or '—'}</code>\n"
            f"Имя: {target_name or '—'}\n"
            f"Юзернейм: @{target_username or '—'}\n"
            f"Статус: {STATUS_LABELS[STATUS_NORMAL]}\n"
            f"\n<i>ℹ️ Пользователя пока нет в базе. Он автоматически "
            f"появится, как только напишет в эту группу или боту.</i>"
        )
        await message.reply(text)


@router_group.callback_query(F.data.startswith("remgroup:"))
async def cb_remgroup(cb: CallbackQuery, bot: Bot):
    try:
        _, chat_id_str, req_id_str = cb.data.split(":")
        chat_id = int(chat_id_str)
        req_id = int(req_id_str)
    except Exception:
        await cb.answer("Ошибка данных", show_alert=True)
        return

    if not await is_chat_admin(bot, chat_id, cb.from_user.id):
        await cb.answer("Только админ чата может удалять.", show_alert=True)
        return

    await delete_required_chat(req_id)
    await log_action(cb.from_user.id, "delete_required_chat", chat_id,
                     f"req_id={req_id}")

    try:
        await cb.message.delete()
    except Exception:
        pass
    await cb.answer("🗑 Удалено")


@router_group.chat_member()
async def on_chat_member(event: ChatMemberUpdated, bot: Bot):
    new = event.new_chat_member
    old = event.old_chat_member

    # Инвалидируем кеш админов для этого чата
    invalidate_admin_cache(event.chat.id)

    if old.status in ("left", "kicked") and new.status in ("member", "administrator"):
        u = new.user
        if u.username:
            mention = f"@{u.username}"
        else:
            mention = f'<a href="tg://user?id={u.id}">{u.full_name}</a>'

        text = (
            f"👋 Добро пожаловать в <b>{event.chat.title or 'этот чат'}</b>, "
            f"{mention}!\n\n"
            f"Приятного общения! 🎉"
        )
        try:
            await send_photo_cached(bot, event.chat.id, IMAGE_HELLO, text,
                                    cache_prefix="banner")
        except Exception as e:
            log.warning("Не смог поприветствовать %s: %s", u.id, e)

    if new.status in ("member", "restricted"):
        if await is_banned_anywhere(new.user.id):
            try:
                await bot.ban_chat_member(event.chat.id, new.user.id)
                await bot.unban_chat_member(event.chat.id, new.user.id)
            except Exception as e:
                log.warning("Не смог кикнуть %s: %s", new.user.id, e)


@router_group.my_chat_member()
async def bot_added(event: ChatMemberUpdated, bot: Bot):
    if event.new_chat_member.status in ("member", "administrator"):
        await register_chat(event.chat.id,
                            event.chat.title or str(event.chat.id))
        invalidate_admin_cache(event.chat.id)
        try:
            text = (
                f"👋 Привет! Я бот-помощник этого чата.\n\n"
                f"Проверяйте пользователей командой "
                f"<code>/check @username</code> или реплаем на сообщение.\n"
                f"Администраторы могут настроить обязательную подписку: "
                f"<code>/addgroup &lt;ссылка&gt; &lt;время&gt;</code>"
            )
            await send_photo_cached(bot, event.chat.id, IMAGE_HELLO, text,
                                    cache_prefix="banner")
        except Exception as e:
            log.warning("Не смог представиться в чате %s: %s",
                        event.chat.id, e)


@router_group.message(IsNotSuperAdmin(), IsGroupChat(), F.text | F.caption)
async def group_autoreply_status(message: Message):
    text = message.text or message.caption or ""
    if text.startswith("/"):
        return
    u = await get_user(message.from_user.id)
    if not u:
        return
    if u.get("status") in (STATUS_SCAM, STATUS_BANNED):
        await send_status_card(message, u, reply_to=message)


# ---------------- ADMIN ----------------
@router_admin.message(CommandStart(), IsSuperAdmin(), IsPrivateChat())
async def admin_start(message: Message, state: FSMContext):
    await state.clear()
    text = f"🛠 <b>{BOT_NAME}</b> — админ-панель"
    await send_photo_cached(message, None, IMAGE_START, text,
                            reply_markup=admin_menu(),
                            cache_prefix="banner")


@router_admin.message(Command("admin"), IsSuperAdmin(), IsPrivateChat())
async def admin_cmd(message: Message):
    await message.answer("🛠 Админ-панель", reply_markup=admin_menu())


@router_admin.callback_query(F.data == "admin_stats", IsSuperAdmin(), IsPrivateChat())
async def admin_stats(cb: CallbackQuery):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM users")
        total = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE status=?",
                               (STATUS_SCAM,))
        scams = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE status=?",
                               (STATUS_BANNED,))
        banned = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM appeals")
        appeals = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM chats")
        chats = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM required_chats")
        req = (await cur.fetchone())[0]
    await cb.message.answer(
        f"📊 <b>Статистика {BOT_NAME}</b>\n"
        f"Всего записей: {total}\n"
        f"🚨 Скамеров: {scams}\n"
        f"⛔ Забанено везде: {banned}\n"
        f"⚖️ Апелляций: {appeals}\n"
        f"💬 Чатов с ботом: {chats}\n"
        f"🔒 Обязательных подписок: {req}"
    )
    await cb.answer()


@router_admin.callback_query(F.data == "admin_set_status", IsSuperAdmin(), IsPrivateChat())
async def admin_set_status(cb: CallbackQuery, state: FSMContext):
    await state.update_data(action="set")
    await state.set_state(AdminFSM.waiting_target)
    await cb.message.answer(
        "Отправь одно из:\n"
        "• <code>@username</code>\n"
        "• <code>123456789</code> (ID)\n"
        "• <code>@username 123456789</code> (оба сразу)\n\n"
        "⚠️ Статус «Администратор» выдать нельзя."
    )
    await cb.answer()


@router_admin.message(AdminFSM.waiting_target, F.text, IsSuperAdmin(), IsPrivateChat())
async def admin_target(message: Message, state: FSMContext):
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
        await message.answer(
            "Не понял. Отправь <code>@username</code>, "
            "<code>123456789</code> или <code>@username 123456789</code>."
        )
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
            await message.answer(
                "❗ Пользователя с таким @username нет в базе.\n\n"
                "Варианты:\n"
                "• дождись, пока он напишет в группу с ботом\n"
                "• укажи его ID: <code>@username 123456789</code>"
            )
            await state.clear()
            return

    await state.update_data(target_id=target_id,
                            target_username=target_username)

    if action == "ban":
        await set_status(target_id, STATUS_BANNED, "Глобальный бан",
                         None, username=target_username)
        await log_action(message.from_user.id, "ban_anywhere", target_id)
        await message.answer(f"⛔ <code>{target_id}</code> забанен везде.")
        await state.clear()
        return

    if action == "reset":
        await set_status(target_id, STATUS_NORMAL, None, None)
        await log_action(message.from_user.id, "reset_status", target_id)
        await message.answer("🔁 Статус сброшен на «Обычный».")
        await state.clear()
        return

    await state.set_state(None)
    label = f"@{target_username}" if target_username else str(target_id)
    await message.answer(f"Выбери статус для <code>{label}</code>:",
                         reply_markup=status_choice_kb("set"))


@router_admin.callback_query(F.data.startswith("set:"), IsSuperAdmin(), IsPrivateChat())
async def admin_pick_status(cb: CallbackQuery, state: FSMContext):
    status = cb.data.split(":", 1)[1]
    data = await state.get_data()
    if status in (STATUS_SCAM, STATUS_SUSPICIOUS):
        await state.update_data(pending_status=status)
        await state.set_state(AdminFSM.waiting_reason)
        await cb.message.answer("Введи причину (кратко):")
    else:
        await _apply_status(data.get("target_id"),
                            data.get("target_username"),
                            status, None, None, cb.from_user.id)
        await state.clear()
        await cb.message.answer(f"✅ Статус: {STATUS_LABELS[status]}")
    await cb.answer()


@router_admin.message(AdminFSM.waiting_reason, IsSuperAdmin(), IsPrivateChat())
async def admin_reason(message: Message, state: FSMContext):
    await state.update_data(pending_reason=message.text)
    await state.set_state(AdminFSM.waiting_evidence)
    await message.answer(
        "Пришли ссылку на сообщение с доказательствами "
        "(или <code>-</code>, чтобы без ссылки):"
    )


@router_admin.message(AdminFSM.waiting_evidence, IsSuperAdmin(), IsPrivateChat())
async def admin_evidence(message: Message, state: FSMContext):
    evidence = message.text.strip()
    if evidence == "-":
        evidence = None
    data = await state.get_data()
    await _apply_status(data.get("target_id"),
                        data.get("target_username"),
                        data.get("pending_status"),
                        data.get("pending_reason"),
                        evidence, message.from_user.id)
    await state.clear()
    await message.answer("✅ Запись обновлена.")


async def _apply_status(target_id, target_username, status,
                        reason, evidence_url, admin_id):
    if status == STATUS_ADMIN and target_id != SUPER_ADMIN_ID:
        return
    if target_id is None and target_username:
        found = await get_user_by_username(target_username)
        if found:
            target_id = found["user_id"]
    if target_id is None:
        return
    await set_status(target_id, status, reason, evidence_url,
                     username=target_username)
    await log_action(admin_id, f"set_status:{status}", target_id,
                     f"reason={reason}; evidence={evidence_url}")


@router_admin.callback_query(F.data == "admin_ban_anywhere", IsSuperAdmin(), IsPrivateChat())
async def admin_ban_start(cb: CallbackQuery, state: FSMContext):
    await state.update_data(action="ban")
    await state.set_state(AdminFSM.waiting_target)
    await cb.message.answer("Отправь @username или ID для глобального бана.")
    await cb.answer()


@router_admin.callback_query(F.data == "admin_reset_status", IsSuperAdmin(), IsPrivateChat())
async def admin_reset_start(cb: CallbackQuery, state: FSMContext):
    await state.update_data(action="reset")
    await state.set_state(AdminFSM.waiting_target)
    await cb.message.answer("Кому сбросить статус? Отправь @username или ID.")
    await cb.answer()


@router_admin.callback_query(F.data.startswith("appeal_change:"), IsSuperAdmin(), IsPrivateChat())
async def appeal_change(cb: CallbackQuery, state: FSMContext):
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await cb.answer("Не найдено", show_alert=True)
        return
    await state.update_data(appeal_id=appeal_id, appeal_user=appeal["user_id"])
    await cb.message.answer("Выбери новый статус:",
                            reply_markup=status_choice_kb("appeal"))
    await cb.answer()


@router_admin.callback_query(F.data.startswith("appeal:"), IsSuperAdmin(), IsPrivateChat())
async def appeal_apply(cb: CallbackQuery, state: FSMContext, bot: Bot):
    new_status = cb.data.split(":", 1)[1]
    data = await state.get_data()
    appeal_id = data.get("appeal_id")
    user_id = data.get("appeal_user")
    if not user_id:
        await cb.answer("Данные потеряны", show_alert=True)
        return
    await set_status(user_id, new_status, "Решение по апелляции")
    await set_appeal_status(appeal_id, "changed")
    await log_action(cb.from_user.id, f"appeal_change:{new_status}",
                     user_id, f"appeal={appeal_id}")
    try:
        await bot.send_message(user_id,
                               f"⚖️ Апелляция рассмотрена. Новый статус: "
                               f"{STATUS_LABELS[new_status]}")
    except Exception:
        pass
    await cb.message.answer("✅ Решение изменено.")
    await state.clear()
    await cb.answer()


@router_admin.callback_query(F.data.startswith("appeal_reply:"), IsSuperAdmin(), IsPrivateChat())
async def appeal_reply(cb: CallbackQuery, state: FSMContext):
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await cb.answer("Не найдено", show_alert=True)
        return
    await state.update_data(appeal_id=appeal_id, appeal_user=appeal["user_id"])
    await state.set_state(AdminFSM.waiting_appeal_reply)
    await cb.message.answer("Напиши текст ответа пользователю:")
    await cb.answer()


@router_admin.message(AdminFSM.waiting_appeal_reply, IsSuperAdmin(), IsPrivateChat())
async def appeal_reply_send(message: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    user_id = data.get("appeal_user")
    appeal_id = data.get("appeal_id")
    try:
        await bot.send_message(user_id,
                               f"✍️ Ответ по апелляции #{appeal_id}:\n\n"
                               f"{message.text}")
        await set_appeal_status(appeal_id, "answered")
        await message.answer("✅ Ответ отправлен.")
    except Exception as e:
        await message.answer(f"Не удалось отправить: {e}")
    await state.clear()


@router_admin.callback_query(F.data.startswith("appeal_reject:"), IsSuperAdmin(), IsPrivateChat())
async def appeal_reject(cb: CallbackQuery, state: FSMContext, bot: Bot):
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await cb.answer("Не найдено", show_alert=True)
        return
    await set_appeal_status(appeal_id, "rejected")
    try:
        await bot.send_message(appeal["user_id"], "❌ Апелляция отклонена.")
    except Exception:
        pass
    await cb.message.answer("Апелляция отклонена.")
    await cb.answer()


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

    dp.include_router(router_admin)
    dp.include_router(router_group)
    dp.include_router(router_user)

    await bot.delete_webhook(drop_pending_updates=True)
    log.info("%s запущен, админ=%s", BOT_NAME, SUPER_ADMIN_ID)

    asyncio.create_task(cleaner_task())
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

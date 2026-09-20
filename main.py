# bot.py
import asyncio
import logging
import os
from datetime import datetime

import aiosqlite
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    ChatMemberUpdated,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    Message,
)

# ==========================================================
# КОНФИГ ИЗ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ
# ==========================================================
BOT_TOKEN = os.getenv("BOT_TOKEN")
SUPER_ADMIN_ID = int(os.getenv("SUPER_ADMIN_ID", "0"))
REPORT_GROUP_URL = os.getenv("REPORT_GROUP_URL", "https://t.me/")
EVIDENCE_GROUP_URL = os.getenv("EVIDENCE_GROUP_URL", REPORT_GROUP_URL)  # одна группа
DB_PATH = os.getenv("DB_PATH", "data/antiscam.db")

if not BOT_TOKEN:
    raise SystemExit("Не задана переменная окружения BOT_TOKEN")
if not SUPER_ADMIN_ID:
    raise SystemExit("Не задана переменная окружения SUPER_ADMIN_ID")

os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("antiscam")

# ==========================================================
# БАЗА ДАННЫХ
# ==========================================================
async def init_db():
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
        await db.commit()


async def upsert_user(user_id, username=None, full_name=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO users (user_id, username, full_name, status, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username=COALESCE(excluded.username, users.username),
                full_name=COALESCE(excluded.full_name, users.full_name),
                updated_at=excluded.updated_at
        """, (user_id, username, full_name, STATUS_NORMAL,
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
            "SELECT * FROM users WHERE LOWER(username)=LOWER(?)",
            (username,))
        row = await cur.fetchone()
        return dict(row) if row else None


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


async def all_chats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT chat_id, title FROM chats")
        return [dict(r) for r in await cur.fetchall()]


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
    if username:
        link = f"https://t.me/{username}"
    else:
        link = f"tg://user?id={user_id}"
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


def is_super_admin(user_id: int) -> bool:
    return user_id == SUPER_ADMIN_ID


# ---------------- USER ----------------
@router_user.message(CommandStart())
async def user_start(message: Message, state: FSMContext):
    if is_super_admin(message.from_user.id):
        return
    await state.clear()
    await upsert_user(message.from_user.id,
                      message.from_user.username,
                      message.from_user.full_name)
    await message.answer(
        "👋 Привет! Я антискам-бот.\n\n"
        "Помогаю собирать информацию о скамерах и проверять пользователей.\n"
        "Выбери действие:",
        reply_markup=user_menu()
    )


@router_user.callback_query(F.data == "check_me")
async def check_me(cb: CallbackQuery):
    u = await get_user(cb.from_user.id)
    status = u["status"] if u else STATUS_NORMAL
    text = (
        f"🔎 <b>Твоя карточка</b>\n"
        f"ID: <code>{cb.from_user.id}</code>\n"
        f"Имя: {cb.from_user.full_name}\n"
        f"Юзернейм: @{cb.from_user.username or '—'}\n"
        f"Статус: {STATUS_LABELS.get(status, status)}\n"
    )
    if u and u.get("reason"):
        text += f"Причина: {u['reason']}\n"
    await cb.message.answer(
        text,
        reply_markup=profile_kb(cb.from_user.id,
                                u.get("evidence_url") if u else None,
                                cb.from_user.username)
    )
    await cb.answer()


@router_user.callback_query(F.data == "check_user_hint")
async def check_user_hint(cb: CallbackQuery):
    await cb.message.answer(
        "Чтобы проверить пользователя:\n"
        "• в группе: <code>/check @username</code> или "
        "<code>/check 123456789</code>, либо ответом на его сообщение\n"
        "• либо перешли мне любое его сообщение"
    )
    await cb.answer()


@router_user.message(F.forward_from)
async def check_forward(message: Message):
    t = message.forward_from
    await _send_profile(message, t.id, t.username, t.full_name)


@router_user.message(F.forward_from_chat)
async def check_forward_chat(message: Message):
    c = message.forward_from_chat
    await _send_profile(message, c.id, c.username, c.title)


async def _send_profile(message: Message, user_id, username, full_name):
    u = await get_user(user_id)
    status = u["status"] if u else STATUS_NORMAL
    text = (
        f"📇 <b>Карточка</b>\n"
        f"ID: <code>{user_id}</code>\n"
        f"Имя: {full_name or '—'}\n"
        f"Юзернейм: @{username or '—'}\n"
        f"Статус: {STATUS_LABELS.get(status, status)}\n"
    )
    if u and u.get("reason"):
        text += f"Причина: {u['reason']}\n"
    await message.answer(
        text,
        reply_markup=profile_kb(user_id,
                                u.get("evidence_url") if u else None,
                                username)
    )


@router_user.callback_query(F.data == "appeal_start")
async def appeal_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(AppealFSM.waiting_evidence)
    await cb.message.answer(
        "⚖️ <b>Обжалование</b>\n\n"
        "Отправь одним сообщением доказательства: текст, фото или видео. "
        "Админ рассмотрит."
    )
    await cb.answer()


@router_user.message(AppealFSM.waiting_evidence)
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
@router_group.message(Command("check"))
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

    status = user["status"] if user else STATUS_NORMAL
    display_name = (user["full_name"] if user else target_name) or "—"
    display_username = (user["username"] if user else target_username) or "—"
    display_id = (user["user_id"] if user else target_id) or "—"

    text = (
        f"📇 <b>Проверка</b>\n"
        f"ID: <code>{display_id}</code>\n"
        f"Имя: {display_name}\n"
        f"Юзернейм: @{display_username}\n"
        f"Статус: {STATUS_LABELS.get(status, status)}\n"
    )
    if user and user.get("reason"):
        text += f"Причина: {user['reason']}\n"

    await message.reply(
        text,
        reply_markup=profile_kb(
            display_id if isinstance(display_id, int) else 0,
            user.get("evidence_url") if user else None,
            display_username if display_username != "—" else None,
        )
    )


@router_group.chat_member()
async def on_chat_member(event: ChatMemberUpdated, bot: Bot):
    new = event.new_chat_member
    if new.status in ("member", "restricted"):
        if await is_banned_anywhere(new.user.id):
            try:
                await bot.ban_chat_member(event.chat.id, new.user.id)
                await bot.unban_chat_member(event.chat.id, new.user.id)
            except Exception as e:
                log.warning("Не смог кикнуть %s: %s", new.user.id, e)


@router_group.my_chat_member()
async def bot_added(event: ChatMemberUpdated):
    if event.new_chat_member.status in ("member", "administrator"):
        await register_chat(event.chat.id, event.chat.title or str(event.chat.id))


# ---------------- ADMIN ----------------
@router_admin.message(CommandStart())
async def admin_start(message: Message, state: FSMContext):
    if not is_super_admin(message.from_user.id):
        return
    await state.clear()
    await message.answer("🛠 <b>Админ-панель</b>", reply_markup=admin_menu())


@router_admin.message(Command("admin"))
async def admin_cmd(message: Message):
    if not is_super_admin(message.from_user.id):
        return
    await message.answer("🛠 Админ-панель", reply_markup=admin_menu())


@router_admin.callback_query(F.data == "admin_stats")
async def admin_stats(cb: CallbackQuery):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
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
    await cb.message.answer(
        f"📊 <b>Статистика</b>\n"
        f"Всего записей: {total}\n"
        f"🚨 Скамеров: {scams}\n"
        f"⛔ Забанено везде: {banned}\n"
        f"⚖️ Апелляций: {appeals}\n"
        f"💬 Чатов с ботом: {chats}"
    )
    await cb.answer()


# --- добавление статуса ---
@router_admin.callback_query(F.data == "admin_set_status")
async def admin_set_status(cb: CallbackQuery, state: FSMContext):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
    await state.update_data(action="set")
    await state.set_state(AdminFSM.waiting_target)
    await cb.message.answer("Отправь @username или ID пользователя:")
    await cb.answer()


@router_admin.message(AdminFSM.waiting_target, F.text)
async def admin_target(message: Message, state: FSMContext):
    if not is_super_admin(message.from_user.id):
        return
    data = await state.get_data()
    action = data.get("action", "set")
    arg = message.text.strip()

    target_id = None
    target_username = None
    if arg.startswith("@"):
        target_username = arg[1:]
    elif arg.lstrip("-").isdigit():
        target_id = int(arg)
    else:
        await message.answer("Некорректно. Отправь @username или ID.")
        return

    if target_id is None and target_username:
        found = await get_user_by_username(target_username)
        if found:
            target_id = found["user_id"]

    await state.update_data(target_id=target_id,
                            target_username=target_username)

    if action == "ban":
        if target_id is None:
            await message.answer(
                "Пользователь не найден в базе. Пусть он запустит бота "
                "или перешли его сообщение."
            )
            await state.clear()
            return
        await set_status(target_id, STATUS_BANNED, "Глобальный бан",
                         None, username=target_username)
        await log_action(message.from_user.id, "ban_anywhere", target_id)
        await message.answer(f"⛔ <code>{target_id}</code> забанен везде.")
        await state.clear()
        return

    if action == "reset":
        if target_id is None:
            await message.answer("Не найден.")
            await state.clear()
            return
        await set_status(target_id, STATUS_NORMAL, None, None)
        await log_action(message.from_user.id, "reset_status", target_id)
        await message.answer("🔁 Статус сброшен на «Обычный».")
        await state.clear()
        return

    # action == "set"
    await state.set_state(None)
    await message.answer(f"Выбери статус для <code>{arg}</code>:",
                         reply_markup=status_choice_kb("set"))


@router_admin.callback_query(F.data.startswith("set:"))
async def admin_pick_status(cb: CallbackQuery, state: FSMContext):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
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


@router_admin.message(AdminFSM.waiting_reason)
async def admin_reason(message: Message, state: FSMContext):
    if not is_super_admin(message.from_user.id):
        return
    await state.update_data(pending_reason=message.text)
    await state.set_state(AdminFSM.waiting_evidence)
    await message.answer(
        "Пришли ссылку на сообщение с доказательствами "
        "(или <code>-</code>, чтобы без ссылки):"
    )


@router_admin.message(AdminFSM.waiting_evidence)
async def admin_evidence(message: Message, state: FSMContext):
    if not is_super_admin(message.from_user.id):
        return
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


# --- бан / сброс ---
@router_admin.callback_query(F.data == "admin_ban_anywhere")
async def admin_ban_start(cb: CallbackQuery, state: FSMContext):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
    await state.update_data(action="ban")
    await state.set_state(AdminFSM.waiting_target)
    await cb.message.answer("Отправь @username или ID для глобального бана.")
    await cb.answer()


@router_admin.callback_query(F.data == "admin_reset_status")
async def admin_reset_start(cb: CallbackQuery, state: FSMContext):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
    await state.update_data(action="reset")
    await state.set_state(AdminFSM.waiting_target)
    await cb.message.answer("Кому сбросить статус? Отправь @username или ID.")
    await cb.answer()


# --- апелляции ---
@router_admin.callback_query(F.data.startswith("appeal_change:"))
async def appeal_change(cb: CallbackQuery, state: FSMContext):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await cb.answer("Не найдено", show_alert=True)
        return
    await state.update_data(appeal_id=appeal_id, appeal_user=appeal["user_id"])
    await cb.message.answer("Выбери новый статус:",
                            reply_markup=status_choice_kb("appeal"))
    await cb.answer()


@router_admin.callback_query(F.data.startswith("appeal:"))
async def appeal_apply(cb: CallbackQuery, state: FSMContext, bot: Bot):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
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


@router_admin.callback_query(F.data.startswith("appeal_reply:"))
async def appeal_reply(cb: CallbackQuery, state: FSMContext):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await cb.answer("Не найдено", show_alert=True)
        return
    await state.update_data(appeal_id=appeal_id, appeal_user=appeal["user_id"])
    await state.set_state(AdminFSM.waiting_appeal_reply)
    await cb.message.answer("Напиши текст ответа пользователю:")
    await cb.answer()


@router_admin.message(AdminFSM.waiting_appeal_reply)
async def appeal_reply_send(message: Message, state: FSMContext, bot: Bot):
    if not is_super_admin(message.from_user.id):
        return
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


@router_admin.callback_query(F.data.startswith("appeal_reject:"))
async def appeal_reject(cb: CallbackQuery, state: FSMContext, bot: Bot):
    if not is_super_admin(cb.from_user.id):
        await cb.answer("Нет доступа", show_alert=True)
        return
    appeal_id = int(cb.data.split(":")[1])
    appeal = await get_appeal(appeal_id)
    if not appeal:
        await cb.answer("Не найдено", show_alert=True)
        return
    await set_appeal_status(appeal_id, "rejected")
    try:
        await bot.send_message(appeal["user_id"],
                               "❌ Апелляция отклонена.")
    except Exception:
        pass
    await cb.message.answer("Апелляция отклонена.")
    await cb.answer()


# ==========================================================
# ЗАПУСК
# ==========================================================
async def main():
    await init_db()
    bot = Bot(token=BOT_TOKEN,
              default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()

    # Порядок: админ → группа → user (catch-all)
    dp.include_router(router_admin)
    dp.include_router(router_group)
    dp.include_router(router_user)

    await bot.delete_webhook(drop_pending_updates=True)
    log.info("Бот запущен, админ=%s", SUPER_ADMIN_ID)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

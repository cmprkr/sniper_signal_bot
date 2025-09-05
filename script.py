# script.py — single file; reads settings from environment (.env)

"""
'.env' format:

DISCORD_TOKEN=token

RH_CRED_USER_ID=0000000000000000000

C_CONFIG=0000000000000000000
C_EXPORT=0000000000000000000
C_CALLOUTS=0000000000000000000
C_ATI=0000000000000000000

BOT_NAME=name
BROADCAST_ENABLED=true
CALLOUT_ROLE_ID=0000000000000000000
ALLOWED_ROLE_IDS=0000000000000000000,0000000000000000000

CREDENTIALS_FILE=rh_credentials.json
"""

import os
import io
import re
import json
import base64
import time
import hmac
import hashlib
import logging
import asyncio
import discord
from datetime import datetime
from robin_stocks import robinhood as r
from dotenv import load_dotenv

# -----------------------------------------------------------------------------
# Load environment
# -----------------------------------------------------------------------------
load_dotenv()  # reads .env if present

def _env_int(name, default="0"):
    try:
        return int(os.getenv(name, default))
    except Exception:
        return 0

DISCORD_TOKEN     = os.getenv("DISCORD_TOKEN")

# Discord user ID to DM on first run to collect Robinhood creds (required)
RH_CRED_USER_ID   = _env_int("RH_CRED_USER_ID")

# Channel IDs
C_EXPORT          = _env_int("C_EXPORT")
C_CALLOUTS        = _env_int("C_CALLOUTS")
C_ATI             = _env_int("C_ATI")

# Bot identity/behavior
BOT_NAME          = os.getenv("BOT_NAME", "sniper")
CALLOUT_ROLE_ID   = _env_int("CALLOUT_ROLE_ID")

# Role gating (comma-separated list of allowed role IDs)
ALLOWED_ROLE_IDS = [
    int(x) for x in os.getenv("ALLOWED_ROLE_IDS", "").replace(" ", "").split(",") if x.isdigit()
]

# Credential storage + encryption key handling
CREDENTIALS_FILE  = os.getenv("CREDENTIALS_FILE", "rh_credentials.json")
RH_CRED_KEY_ENV   = os.getenv("RH_CRED_KEY", None)  # optional passphrase for encryption
KEY_FILE          = os.getenv("RH_KEY_FILE", "rh_key.key")  # fallback on-disk key

# -----------------------------------------------------------------------------
# Bot config
# -----------------------------------------------------------------------------
POLL_INTERVAL        = 1           # seconds between Robinhood polls
LIVE_STATS_INTERVAL  = 2           # seconds between stats refresh
LIVE_STATS_MAX_SECS  = 3600        # stop auto-updating stats after 1 hour

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logging.getLogger("robin_stocks").setLevel(logging.WARNING)

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True  # <— IMPORTANT: requires enabling in Dev Portal
client = discord.Client(intents=intents)

# -----------------------------------------------------------------------------
# Runtime state
# -----------------------------------------------------------------------------
# BOTH are OFF at boot
broadcast_enabled = False     # controls posting/edits to callout channel only
rh_active = False             # controls Robinhood login + monitor loop

# Robinhood creds (populated when RH is turned ON)
rh_username = None
rh_password = None

# monitor task handle
monitor_task = None  # type: asyncio.Task | None

# Track order state for edits & stats
order_messages = {}           # order_id -> {base,last_status,message_id,option_id,stats_text,closed,updater_task}
open_option_to_buy = {}       # option_id -> buy_order_id

# -----------------------------------------------------------------------------
# Encryption helpers (Fernet/AES)
# -----------------------------------------------------------------------------
def _load_or_create_key():
    """
    Prefer env passphrase (RH_CRED_KEY). Otherwise persist a Fernet key file.
    """
    if RH_CRED_KEY_ENV:
        k = hashlib.sha256(RH_CRED_KEY_ENV.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(k)
    if not os.path.exists(KEY_FILE):
        try:
            from cryptography.fernet import Fernet
        except Exception:
            return None
        k = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(k)
        return k
    try:
        with open(KEY_FILE, "rb") as f:
            return f.read()
    except Exception:
        return None

def _get_cipher():
    try:
        from cryptography.fernet import Fernet
    except Exception:
        logger.warning("cryptography not installed; storing RH password in PLAINTEXT (install: pip install cryptography)")
        return None
    key = _load_or_create_key()
    if not key:
        logger.warning("No encryption key available; storing RH password in PLAINTEXT.")
        return None
    from cryptography.fernet import Fernet as F
    return F(key)

def _encrypt_password(plaintext):
    cipher = _get_cipher()
    if cipher is None:
        return {"enc": plaintext, "scheme": "PLAINTEXT"}
    token = cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    return {"enc": token, "scheme": "FERNET"}

def _decrypt_password(enc_obj):
    scheme = enc_obj.get("scheme")
    enc = enc_obj.get("enc")
    if scheme == "PLAINTEXT":
        return enc
    if scheme == "FERNET":
        cipher = _get_cipher()
        if cipher is None:
            raise RuntimeError("Encrypted password present but cryptography is unavailable.")
        return cipher.decrypt(enc.encode("utf-8")).decode("utf-8")
    raise RuntimeError("Unknown password scheme")

def _hash_password(plaintext, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt, 200_000)
    return base64.b64encode(salt).decode("utf-8"), base64.b64encode(dk).decode("utf-8")

# -----------------------------------------------------------------------------
# Creds persistence
# -----------------------------------------------------------------------------
def _load_all_creds():
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    try:
        with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        logger.exception("Failed to read credentials file; starting empty.")
        return {}

def _save_all_creds(data):
    tmp = CREDENTIALS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CREDENTIALS_FILE)

# --- add this helper near other small helpers ---
def _notification_from_status(status_text: str) -> str:
    s = (status_text or "").lower()
    if "partially filled" in s:
        return "Partially Filled"
    if "filled" in s:
        return "Filled"
    if "cancel" in s:
        return "Cancelled"
    if "reject" in s:
        return "Rejected"
    if "expire" in s:
        return "Expired"
    if any(k in s for k in ("submitted", "placed", "confirmed", "queued", "unconfirmed")):
        return "Submitted"
    # Fallback: strip leading "Order " if present and title-case the rest
    return status_text.replace("Order ", "") if status_text else "Submitted"

def _get_stored_creds(user_id):
    data = _load_all_creds()
    return (data.get("users") or {}).get(str(user_id))

def _put_stored_creds(user_id, username, password_plaintext):
    salt_b64, hash_b64 = _hash_password(password_plaintext)
    enc_obj = _encrypt_password(password_plaintext)
    data = _load_all_creds()
    users = data.setdefault("users", {})
    users[str(user_id)] = {
        "username": username,
        "password": enc_obj,   # encrypted or plaintext depending on crypto availability
        "hash_salt": salt_b64, # integrity only
        "hash_value": hash_b64
    }
    _save_all_creds(data)

# -----------------------------------------------------------------------------
# Robinhood + formatting helpers
# -----------------------------------------------------------------------------
def fetch_orders_silent():
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    from contextlib import redirect_stdout, redirect_stderr
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        return r.get_all_option_orders()

def _safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

def extract_leg(order):
    legs = order.get("legs") or []
    return legs[0] if legs else {}

def resolve_option_id(order):
    leg = extract_leg(order)

    oid = leg.get("option_id") or order.get("option_id")
    if oid:
        return oid

    url = leg.get("option") or order.get("option")
    if url:
        m = re.search(r"/options/instruments/([0-9a-f-]+)/?", url, re.I)
        if m:
            return m.group(1)

    try:
        symbol = order.get("chain_symbol")
        exp_date = leg.get("expiration_date") or order.get("expiration_date")
        strike = leg.get("strike_price")
        opt_type = (leg.get("option_type") or order.get("option_type") or "").lower()
        if symbol and exp_date and strike and opt_type in ("call", "put"):
            found = r.options.find_options_by_expiration_and_strike(
                symbol, exp_date, strike, opt_type, info="id"
            )
            if found:
                if isinstance(found, list) and found:
                    return found[0]
                return found
    except Exception:
        pass

    return None

def format_trade_message(order):
    leg = extract_leg(order)
    symbol = order.get("chain_symbol", "UNKNOWN")
    side = (leg.get("side") or order.get("direction") or "N/A").upper()
    qty = _safe_float(order.get("quantity", 0))
    strike = _safe_float(leg.get("strike_price", 0))
    exp_date = leg.get("expiration_date", "N/A")
    opt_type = (leg.get("option_type") or "N/A").upper()
    price = _safe_float(order.get("price", 0))

    letter = "C" if opt_type == "CALL" else "P"
    strike_fmt = int(strike) if isinstance(strike, float) and strike.is_integer() else strike

    try:
        exp_dt = datetime.strptime(exp_date, "%Y-%m-%d")
        exp_fmt = f"{exp_dt.month}/{exp_dt.day}"
    except Exception:
        exp_fmt = exp_date

    price_fmt = f"${price:.2f}"
    qty_int = int(qty) if qty == int(qty) else qty
    contract_word = "contract" if qty_int == 1 else "contracts"

    return f"{side} {symbol} {strike_fmt}{letter} {exp_fmt} @ {price_fmt}, {qty_int} {contract_word}"

def human_status(order):
    state = (order.get("state") or "").lower()
    total_qty = _safe_float(order.get("quantity", 0))
    cum_qty = _safe_float(order.get("cumulative_quantity", 0))
    leg = extract_leg(order)
    leg_cum_qty = _safe_float(leg.get("executed_quantity", cum_qty))
    filled = leg_cum_qty if leg_cum_qty > 0 else cum_qty

    if state in ("queued", "unconfirmed", "confirmed", "placed", "submitted"):
        return "Order Submitted"
    if state in ("partially_filled",) or (0 < filled < total_qty):
        x = int(filled) if filled == int(filled) else filled
        y = int(total_qty) if total_qty == int(total_qty) else total_qty
        return f"Order Partially Filled {x}/{y}"
    if state in ("filled",):
        return "Order Filled"
    if state in ("canceled", "cancelled"):
        return "Order Cancelled"
    if state in ("rejected",):
        return "Order Rejected"
    if state in ("expired",):
        return "Order Expired"
    return (state or "Order Submitted").title().replace("_", " ")

def should_show_stats(status_text):
    s = status_text.lower()
    return ("submitted" in s) or ("partially filled" in s) or (s == "order filled")

def role_mention():
    return f"<@&{CALLOUT_ROLE_ID}>"

def build_export_text(base, status_text):
    # include broadcasting note
    bflag = "ON" if broadcast_enabled else "OFF"
    return f"[Robinhood] {base} (Status: {status_text})"

def compose_callout(base, status_text, stats_block):
    front = f"{role_mention()} {base} (Status: {status_text})"
    return f"{front}\n\n{stats_block}" if stats_block else front

# --- change the signature and body of build_ati_text ---
def build_ati_text(order, status_text=None):
    """
    Bracketed, single-line field format + Broadcasting flag.
    Now includes Notification type (Submitted/Filled/Cancelled/etc.).
    """
    leg = extract_leg(order)
    symbol = order.get("chain_symbol", "UNKNOWN")
    side = (leg.get("side") or order.get("direction") or "N/A").capitalize()
    strike = _safe_float(leg.get("strike_price", 0))
    opt_type = (leg.get("option_type") or "N/A").capitalize()
    exp_date = leg.get("expiration_date") or order.get("expiration_date") or "N/A"
    price = _safe_float(order.get("price", 0))
    qty = _safe_float(order.get("quantity", 0))

    try:
        exp_dt = datetime.strptime(exp_date, "%Y-%m-%d")
        exp_fmt = exp_dt.strftime("%m/%d/%Y")
    except Exception:
        exp_fmt = exp_date

    strike_out = int(strike) if strike == int(strike) else strike
    qty_out = int(qty) if qty == int(qty) else qty

    bflag = "On" if broadcast_enabled else "Off"

    # NEW: derive notification type from status
    notif = _notification_from_status(status_text or human_status(order))

    return (
        f"[Author: {BOT_NAME}, "
        f"Notification: {notif}, "              # <-- NEW FIELD
        f"Type: {side}, "
        f"Ticker: {symbol}, "
        f"Strike: {strike_out}, "
        f"Direction: {opt_type}, "
        f"Expiration: {exp_fmt}, "
        f"Price: ${price:.2f}, "
        f"Size: {qty_out}, "
        f"Broadcasting: {bflag}]"
    )

def fetch_option_market_data(option_id):
    try:
        md = r.options.get_option_market_data(option_id)
        if isinstance(md, list) and md:
            md = md[0]
    except Exception:
        try:
            md = r.options.get_option_market_data_by_id(option_id)
        except Exception:
            md = None
    if not md:
        return None
    return {
        "volume": md.get("volume"),
        "bid_price": md.get("bid_price") or md.get("bid"),
        "ask_price": md.get("ask_price") or md.get("ask"),
        "bid_size": md.get("bid_size") or md.get("bid_quantity"),
        "ask_size": md.get("ask_size") or md.get("ask_quantity"),
    }


# -----------------------------------------------------------------------------
# Posting / Editing
# -----------------------------------------------------------------------------
async def ensure_callout_created(order_id, base, status_text):
    meta = order_messages[order_id]
    if meta["message_id"] is None and broadcast_enabled:
        chan = client.get_channel(C_CALLOUTS) or await client.fetch_channel(C_CALLOUTS)
        msg = await chan.send(compose_callout(base, status_text, None))
        meta["message_id"] = msg.id
        return msg
    if meta["message_id"] is not None:
        chan = client.get_channel(C_CALLOUTS) or await client.fetch_channel(C_CALLOUTS)
        return await chan.fetch_message(meta["message_id"])
    return None

async def edit_callout(order_id):
    meta = order_messages[order_id]
    if meta["message_id"] is None or not broadcast_enabled:
        return
    chan = client.get_channel(C_CALLOUTS) or await client.fetch_channel(C_CALLOUTS)
    try:
        msg = await chan.fetch_message(meta["message_id"])
    except discord.NotFound:
        msg = await chan.send(compose_callout(meta["base"], meta["last_status"], meta["stats_text"]))
        meta["message_id"] = msg.id
        return
    await msg.edit(content=compose_callout(meta["base"], meta["last_status"], meta["stats_text"]))

# --- update post_export to pass status_text into build_ati_text ---
async def post_export(base, status_text, order=None, skip_ati=False):
    """
    ALWAYS export (even if broadcasting is OFF). Broadcasting flag is printed.
    """
    if C_EXPORT and C_EXPORT != C_CALLOUTS:
        exp_chan = client.get_channel(C_EXPORT) or await client.fetch_channel(C_EXPORT)
        await exp_chan.send(build_export_text(base, status_text))
    if (not skip_ati) and C_ATI and (C_ATI not in (C_CALLOUTS, C_EXPORT)) and order:
        ati_chan = client.get_channel(C_ATI) or await client.fetch_channel(C_ATI)
        # pass status_text so ATI includes Notification type
        await ati_chan.send(build_ati_text(order, status_text=status_text))
        
# -----------------------------------------------------------------------------
# Live stats updater (per order)
# -----------------------------------------------------------------------------
async def live_stats_updater(order_id):
    start = time.time()
    while time.time() - start < LIVE_STATS_MAX_SECS:
        meta = order_messages.get(order_id)
        if not meta:
            return

        # stop if SELL-closed or RH inactive; if broadcasting is OFF, we still update internal state but don't edit
        if meta.get("closed") or not rh_active:
            if meta.get("stats_text"):
                meta["stats_text"] = None
                await edit_callout(order_id)
            return

        if should_show_stats(meta["last_status"]):
            stats_text = None
            if meta.get("option_id"):
                md = await asyncio.to_thread(fetch_option_market_data, meta["option_id"])
                if md:
                    vol = md.get("volume")
                    bid_p = md.get("bid_price")
                    ask_p = md.get("ask_price")
                    bid_sz = md.get("bid_size")
                    ask_sz = md.get("ask_size")
                    lines = []
                    if vol not in (None, "", "None"):
                        try:
                            vol = int(float(vol))
                        except Exception:
                            pass
                        lines.append(f"Volume: {vol}")
                    if bid_p not in (None, "", "None"):
                        try:
                            bid_p = f"${float(bid_p):.2f}"
                        except Exception:
                            pass
                        lines.append(f"Bid: {bid_p}" + (f" × {bid_sz}" if bid_sz not in (None, "", "None") else ""))
                    if ask_p not in (None, "", "None"):
                        try:
                            ask_p = f"${float(ask_p):.2f}"
                        except Exception:
                            pass
                        lines.append(f"Ask: {ask_p}" + (f" × {ask_sz}" if ask_sz not in (None, "", "None") else ""))
                    stats_text = "\n".join(lines) if lines else None

            if meta.get("stats_text") != stats_text:
                meta["stats_text"] = stats_text
                await edit_callout(order_id)
        else:
            if meta.get("stats_text"):
                meta["stats_text"] = None
                await edit_callout(order_id)

        await asyncio.sleep(LIVE_STATS_INTERVAL)

    meta = order_messages.get(order_id)
    if meta and meta.get("stats_text"):
        meta["stats_text"] = None
        await edit_callout(order_id)

# -----------------------------------------------------------------------------
# Order handling
# -----------------------------------------------------------------------------
async def handle_new_or_update(order):
    oid = order.get("id")
    if not oid:
        return

    option_id = resolve_option_id(order)
    base = format_trade_message(order)
    status_now = human_status(order)

    if oid not in order_messages:
        order_messages[oid] = {
            "base": base,
            "last_status": status_now,
            "message_id": None,
            "option_id": option_id,
            "stats_text": None,
            "closed": False,
            "updater_task": None,
        }
        leg = extract_leg(order)
        side = (leg.get("side") or order.get("direction") or "").upper()
        if side == "BUY" and option_id:
            open_option_to_buy[option_id] = oid

        # Create callout if broadcasting is ON
        if broadcast_enabled:
            await ensure_callout_created(oid, base, status_now)

        # ALWAYS export to C_EXPORT + C_ATI
        await post_export(base, status_now, order=order)

        # start live stats updater and paint once
        order_messages[oid]["updater_task"] = asyncio.create_task(live_stats_updater(oid))
        asyncio.create_task(edit_callout(oid))
        return

    meta = order_messages[oid]
    if status_now != meta["last_status"]:
        meta["last_status"] = status_now

        # ALWAYS export on status changes
        await post_export(base, status_now, order=order)

        # If cancelled/rejected/expired, hide stats in callout
        if not should_show_stats(status_now):
            meta["stats_text"] = None

        await edit_callout(oid)

async def mark_closed_by_sell(option_id):
    buy_oid = open_option_to_buy.pop(option_id, None)
    if not buy_oid:
        return
    meta = order_messages.get(buy_oid)
    if not meta:
        return
    meta["closed"] = True
    if meta.get("stats_text"):
        meta["stats_text"] = None
        await edit_callout(buy_oid)

# -----------------------------------------------------------------------------
# Credentials workflow (only when RH toggled ON)
# -----------------------------------------------------------------------------
async def get_or_request_credentials():
    global rh_username, rh_password

    entry = _get_stored_creds(RH_CRED_USER_ID)
    if entry:
        try:
            rh_username = entry["username"]
            rh_password = _decrypt_password(entry["password"])
            logger.info("Loaded stored Robinhood creds for user %s.", RH_CRED_USER_ID)
            return True
        except Exception:
            logger.exception("Stored creds exist but could not decrypt; re-requesting via DM.")

    # DM flow
    try:
        user = await client.fetch_user(RH_CRED_USER_ID)
    except Exception:
        logger.exception("Could not fetch Discord user %s for DM.", RH_CRED_USER_ID)
        return False

    try:
        await user.send(f"Hi, this is **{BOT_NAME}**. Please reply with your **Robinhood username (email)**.")
    except Exception:
        logger.exception("Failed to send initial DM.")
        return False

    def check_user(m: discord.Message):
        return m.author.id == RH_CRED_USER_ID and isinstance(m.channel, discord.DMChannel)

    try:
        msg_user = await client.wait_for("message", timeout=300.0, check=check_user)
        username = msg_user.content.strip()
    except asyncio.TimeoutError:
        logger.error("Timeout waiting for username via DM.")
        return False

    await user.send("Thanks. Now please reply with your **Robinhood password**. (Do not share this with anyone else.)")

    try:
        msg_pass = await client.wait_for("message", timeout=300.0, check=check_user)
        password = msg_pass.content.strip()
    except asyncio.TimeoutError:
        logger.error("Timeout waiting for password via DM.")
        return False

    _put_stored_creds(RH_CRED_USER_ID, username, password)
    rh_username = username
    rh_password = password
    logger.info("Stored encrypted Robinhood credentials for user %s.", RH_CRED_USER_ID)
    try:
        await user.send("Credentials saved securely. I’ll use these to connect to Robinhood from now on.")
    except Exception:
        pass
    return True

# -----------------------------------------------------------------------------
# Monitor lifecycle (start/stop)
# -----------------------------------------------------------------------------
def _clear_robinhood_session():
    import os, pathlib
    candidates = [
        "robinhood.pickle",
        "./.robinhood.pickle",
        os.path.expanduser("~/.config/robin_stocks/robinhood.pickle"),
        os.path.expanduser("~/.robinhood.pickle"),
    ]
    for p in candidates:
        try:
            if os.path.exists(p): os.remove(p)
        except Exception as e:
            logger.warning("Couldn't remove %s: %s", p, e)

async def start_monitor():
    global rh_active, monitor_task, rh_username, rh_password

    if rh_active and monitor_task and not monitor_task.done():
        logger.info("Robinhood monitor already running.")
        return True

    # 1) Ensure we have creds (loads or DMs the bound Discord user)
    ok = await get_or_request_credentials()
    if not ok:
        return False

    # 2) Clear any old global session cache to avoid cross-user bleed
    try:
        await asyncio.to_thread(r.logout)
    except Exception:
        pass
    _clear_robinhood_session()

    # 3) Attempt login off the event loop; pass keyword args explicitly
    session_path = f"robinhood_{RH_CRED_USER_ID}.pickle"
    logger.info("Logging in to Robinhood for Discord user %s, username=%r", RH_CRED_USER_ID, rh_username)

    def _try_login(mfa_code=None):
        kwargs = dict(username=rh_username, password=rh_password, store_session=True, pickle_path=session_path)
        if mfa_code:
            kwargs["mfa_code"] = mfa_code
        return r.login(**kwargs)

    try:
        ok = await asyncio.to_thread(_try_login, None)
    except Exception as e:
        logger.warning("Initial login raised %s; will try MFA flow if required.", e)
        ok = False

    # 4) MFA fallback: if first try failed, ask the bound user for a 2FA code and retry once
    if not ok:
        try:
            user = await client.fetch_user(RH_CRED_USER_ID)
            await user.send("Robinhood may require a 2FA code. If you just received one, please reply here with the **6-digit code** within 2 minutes. If not, ignore this message.")
        except Exception:
            user = None

        code = None
        if user is not None:
            def _check(m: discord.Message):
                return m.author.id == RH_CRED_USER_ID and isinstance(m.channel, discord.DMChannel) and m.content.strip().isdigit()

            try:
                msg = await client.wait_for("message", timeout=120.0, check=_check)
                code = msg.content.strip()
            except asyncio.TimeoutError:
                code = None

        if code:
            try:
                ok = await asyncio.to_thread(_try_login, code)
            except Exception:
                ok = False

    if not ok:
        logger.error("Robinhood login failed (after MFA attempt if any).")
        return False

    logger.info("Robinhood login successful")
    rh_active = True
    monitor_task = asyncio.create_task(monitor_option_orders())
    return True


async def stop_monitor():
    global rh_active, monitor_task
    rh_active = False
    if monitor_task and not monitor_task.done():
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Error waiting for monitor task to cancel")
    monitor_task = None
    try:
        r.logout()
    except Exception:
        pass
    logger.info("Robinhood monitor stopped and logged out.")

# -----------------------------------------------------------------------------
# Background monitor loop (runs only when rh_active is True)
# -----------------------------------------------------------------------------
async def monitor_option_orders():
    # Seed existing orders
    try:
        initial = await asyncio.to_thread(fetch_orders_silent)
    except Exception:
        logger.exception("Failed to fetch initial orders")
        initial = []

    for o in initial:
        oid = o.get("id")
        if not oid:
            continue
        option_id = resolve_option_id(o)
        order_messages[oid] = {
            "base": format_trade_message(o),
            "last_status": human_status(o),
            "message_id": None,
            "option_id": option_id,
            "stats_text": None,
            "closed": False,
            "updater_task": None,
        }
        leg = extract_leg(o)
        side = (leg.get("side") or o.get("direction") or "").upper()
        if side == "BUY" and option_id:
            open_option_to_buy[option_id] = oid

    logger.info("Tracking %d existing option orders", len(order_messages))

    seen_ids = set(order_messages.keys())
    while True:
        try:
            if not rh_active:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            orders = await asyncio.to_thread(fetch_orders_silent)
            by_id = {o.get("id"): o for o in orders if o.get("id")}

            # New/updates
            for oid, o in by_id.items():
                if oid not in seen_ids:
                    seen_ids.add(oid)
                    await handle_new_or_update(o)
                else:
                    await handle_new_or_update(o)

            # Detect SELLs that close open BUYs
            for o in orders:
                leg = extract_leg(o)
                side = (leg.get("side") or o.get("direction") or "").upper()
                if side != "SELL":
                    continue
                opt_id = resolve_option_id(o)
                if opt_id and opt_id in open_option_to_buy:
                    await mark_closed_by_sell(opt_id)

            await asyncio.sleep(POLL_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Error in monitor loop")
            await asyncio.sleep(POLL_INTERVAL)

# -----------------------------------------------------------------------------
# Auth / role gate
# -----------------------------------------------------------------------------
def _user_allowed(message: discord.Message) -> bool:
    """
    Only allow commands from members having at least one role in ALLOWED_ROLE_IDS.
    DMs aren't allowed (no role context).
    """
    if isinstance(message.channel, discord.DMChannel):
        return False
    if not message.guild:
        return False
    try:
        member = message.guild.get_member(message.author.id)
        if not member:
            return False
        role_ids = {r.id for r in member.roles}
        return any(rid in role_ids for rid in ALLOWED_ROLE_IDS)
    except Exception:
        return False

# -----------------------------------------------------------------------------
# Discord events
# -----------------------------------------------------------------------------
@client.event
async def on_ready():
    logger.info("Bot logged in as %s", client.user)

    # On startup: send online status (both OFF)
    try:
        if C_EXPORT and C_EXPORT != C_CALLOUTS:
            exp_chan = client.get_channel(C_EXPORT) or await client.fetch_channel(C_EXPORT)
            await exp_chan.send(f"[Robinhood] {BOT_NAME} broadcasting online. Robinhood: OFF, Broadcasting: OFF")
    except Exception as e:
        logger.warning("Could not send online status: %s", e)

@client.event
async def on_message(message: discord.Message):
    """
    Commands (in ANY guild channel; role-gated):
      !bot <name> on          -> RH engine ON (login + start monitor)
      !bot <name> off         -> RH engine OFF (stop monitor + logout)
      !bot <name> broadcasting on|off -> toggle broadcasting
      !bot <name> status      -> show both: Robinhood + Broadcasting

    Users without allowed roles get a denial message.
    """
    global broadcast_enabled, rh_active

    if message.author == client.user:
        return

    content = message.content.strip()
    if not content.lower().startswith("!bot "):
        return

    # Role gate
    if not _user_allowed(message):
        try:
            await message.channel.send("You don't have the required roles to use this command.")
        except Exception:
            pass
        return

    parts = content.split()
    if len(parts) < 3:
        return  # silently ignore

    _, name = parts[0], parts[1]
    if name.lower() != BOT_NAME.lower():
        return  # wrong bot name: silently ignore

    # 3-part commands
    if len(parts) == 3:
        cmd = parts[2].lower()

        if cmd == "on":
            # RH ON
            if rh_active:
                await message.channel.send("Robinhood is already **ON**.")
                return
            ok = await start_monitor()
            if ok:
                await message.channel.send("Robinhood is now **ON**.")
            else:
                await message.channel.send("Robinhood **failed to start**. Check DMs/creds and try again.")
            return

        if cmd == "off":
            # RH OFF
            if not rh_active:
                await message.channel.send("Robinhood is already **OFF**.")
                return
            await stop_monitor()
            await message.channel.send("Robinhood is now **OFF**.")
            return

        if cmd == "status":
            await message.channel.send(
                f"Robinhood is **{'ON' if rh_active else 'OFF'}**, "
                f"Broadcasting is **{'ON' if broadcast_enabled else 'OFF'}**."
            )
            return

        return  # unknown -> ignore

    # broadcasting subcommand
    if len(parts) == 4 and parts[2].lower() == "broadcasting":
        state = parts[3].lower()
        if state == "on":
            broadcast_enabled = True
            await message.channel.send("Broadcasting is now **ON**.")
        elif state == "off":
            broadcast_enabled = False
            await message.channel.send("Broadcasting is now **OFF**.")
        return
    # else ignore silently

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        logger.error("Missing DISCORD_TOKEN (set it in environment or .env)")
        raise SystemExit(1)
    logger.info("Starting Discord client…")
    client.run(DISCORD_TOKEN)
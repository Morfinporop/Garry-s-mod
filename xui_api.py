import asyncio
import json
import logging
import logging.handlers
import os
import secrets
import string
import time
import uuid
from urllib.parse import quote

import aiohttp

from config import (
    XUI_HOST,
    XUI_USERNAME,
    XUI_PASSWORD,
    XUI_SUB_URL,
    SUSPICIOUS_NEW_IP_THRESHOLD,
)

logger = logging.getLogger(__name__)

XUI_TIMEOUT = 20
CIRCUIT_COOLDOWN = 60
DEFAULT_INBOUND_IDS = [1, 2]

_previous_ips: dict[str, set[str]] = {}

os.makedirs("logs", exist_ok=True)
_sus_logger = logging.getLogger("suspicious_activity")
_sus_logger.setLevel(logging.WARNING)
_sus_logger.propagate = False

if not _sus_logger.handlers:
    _h = logging.handlers.RotatingFileHandler(
        "logs/suspicious_activity.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    _h.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    _sus_logger.addHandler(_h)


def _normalize_host(raw: str) -> str:
    h = (raw or "").strip()
    if not h:
        return ""
    if not h.startswith(("http://", "https://")):
        h = "http://" + h
    h = h.rstrip("/")
    for suffix in ("/panel/clients", "/panel/inbounds", "/panel"):
        if h.endswith(suffix):
            h = h[: -len(suffix)]
            break
    return h.rstrip("/")


_BASE_URL = _normalize_host(XUI_HOST)
_SUB_BASE_URL = (XUI_SUB_URL or "https://sub.flowvpn.su:2053/3o3ntto7rlvdmgtv").strip().rstrip("/")

_api_lock = asyncio.Lock()
_session: aiohttp.ClientSession | None = None
_logged_in: bool = False
_csrf_token: str = ""
_circuit_broken_until: float = 0.0

_inbound_ids_cache: list[int] | None = None
_inbound_ids_cache_ts: float = 0.0
_INBOUND_CACHE_TTL = 60.0

_panel_semaphore = asyncio.Semaphore(2)


def _generate_sub_id(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_sub_link(sub_id: str) -> str:
    return f"{_SUB_BASE_URL}/{sub_id}"


def _invalidate_session() -> None:
    global _logged_in, _csrf_token
    _logged_in = False
    _csrf_token = ""


async def _get_http_session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=XUI_TIMEOUT)
        # unsafe=True нужен для сохранения cookie, если панель открыта по IP-адресу
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        _session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookie_jar=cookie_jar,
        )
    return _session


async def _fetch_csrf_token(session: aiohttp.ClientSession, path: str) -> str:
    url = f"{_BASE_URL}/{path.lstrip('/')}"
    try:
        async with session.get(url, allow_redirects=False, ssl=False) as r:
            if r.status != 200:
                return ""
            data = await r.json(content_type=None)
            if isinstance(data, dict) and data.get("success") and isinstance(data.get("obj"), str):
                return data["obj"]
    except Exception:
        pass
    return ""


async def _ensure_logged_in(force: bool = False) -> None:
    global _logged_in, _csrf_token, _circuit_broken_until

    now = time.time()
    if now < _circuit_broken_until:
        raise RuntimeError(
            f"3x-UI на паузе после сбоя (ещё {int(_circuit_broken_until - now)}с)"
        )

    if _logged_in and not force:
        return

    async with _api_lock:
        if _logged_in and not force:
            return

        if not _BASE_URL:
            raise RuntimeError("XUI_HOST не задан в настройках")

        session = await _get_http_session()
        logger.info("[xui] Авторизация в 3x-UI...")

        try:
            csrf = await _fetch_csrf_token(session, "csrf-token")
            headers = {}
            if csrf:
                headers["X-CSRF-Token"] = csrf

            async with session.post(
                f"{_BASE_URL}/login",
                data={"username": XUI_USERNAME, "password": XUI_PASSWORD},
                headers=headers,
                allow_redirects=False,
                ssl=False,
            ) as r:
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status} при входе в 3x-UI")
                data = await r.json(content_type=None)
                if not isinstance(data, dict) or not data.get("success"):
                    msg = data.get("msg") if isinstance(data, dict) else "unknown"
                    raise RuntimeError(f"Отказ входа в 3x-UI: {msg}")

            panel_csrf = await _fetch_csrf_token(session, "panel/csrf-token")
            _csrf_token = panel_csrf or csrf
            _logged_in = True
            logger.info("[xui] Сессия 3x-UI активна")

        except Exception as e:
            _invalidate_session()
            _circuit_broken_until = time.time() + CIRCUIT_COOLDOWN
            logger.error(f"[xui] Логин в 3x-UI не удался: {e}. Cooldown {CIRCUIT_COOLDOWN}s")
            raise RuntimeError("Панель 3x-UI временно недоступна")


async def _raw_request(
    method: str,
    path: str,
    json_body: dict | list | None = None,
) -> tuple[int, dict | None]:
    session = await _get_http_session()
    url = f"{_BASE_URL}/{path.lstrip('/')}"

    headers = {}
    if method.upper() not in ("GET", "HEAD", "OPTIONS") and _csrf_token:
        headers["X-CSRF-Token"] = _csrf_token

    kwargs: dict = {
        "headers": headers,
        "allow_redirects": False,
        "ssl": False,
    }
    if json_body is not None:
        kwargs["json"] = json_body

    async with session.request(method, url, **kwargs) as r:
        status = r.status
        ctype = (r.headers.get("Content-Type") or "").lower()

        if status in (401, 403, 404) or (300 <= status < 400) or "text/html" in ctype:
            return status, None

        try:
            data = await r.json(content_type=None)
            return status, data if isinstance(data, dict) else None
        except Exception:
            return status, None


async def _panel_request(
    method: str,
    path: str,
    json_body: dict | list | None = None,
) -> dict | None:
    global _csrf_token

    async with _panel_semaphore:
        await _ensure_logged_in(force=False)
        status, data = await _raw_request(method, path, json_body)
        if data is not None:
            return data

        # Если устарел только CSRF-токен (403), пробуем быстро обновить его
        if status == 403 and _logged_in:
            session = await _get_http_session()
            new_csrf = await _fetch_csrf_token(session, "panel/csrf-token")
            if new_csrf:
                _csrf_token = new_csrf
                status, data = await _raw_request(method, path, json_body)
                if data is not None:
                    return data

        # Иначе перелогиниваемся один раз и повторяем запрос
        _invalidate_session()
        await _ensure_logged_in(force=True)
        _, data = await _raw_request(method, path, json_body)
        return data


async def _get_inbound_ids() -> list[int]:
    """
    Возвращает ID всех активных входящих подключений (локаций) в панели,
    например [1, 2] (Finland + Germany).
    """
    global _inbound_ids_cache, _inbound_ids_cache_ts

    now = time.monotonic()
    if _inbound_ids_cache and (now - _inbound_ids_cache_ts) < _INBOUND_CACHE_TTL:
        return list(_inbound_ids_cache)

    for endpoint in ("/panel/api/inbounds/options", "/panel/api/inbounds/list/slim", "/panel/api/inbounds/list"):
        data = await _panel_request("GET", endpoint)
        if data and data.get("success") and isinstance(data.get("obj"), list):
            ids = [
                int(item["id"])
                for item in data["obj"]
                if isinstance(item, dict) and item.get("id") and item.get("enable", True)
            ]
            if ids:
                _inbound_ids_cache = ids
                _inbound_ids_cache_ts = now
                return list(ids)

    return list(DEFAULT_INBOUND_IDS)


async def _resolve_client_email(identifier: str) -> str:
    """
    В разделе «Клиенты» 3x-UI адресация идёт по email.
    Если передан старый UUID или subId — ищем соответствующий email.
    """
    if not identifier:
        return ""

    encoded = quote(identifier, safe="")
    res = await _panel_request("GET", f"/panel/api/clients/get/{encoded}")
    if res and res.get("success") and isinstance(res.get("obj"), dict):
        client_obj = res["obj"].get("client")
        if isinstance(client_obj, dict) and client_obj.get("email"):
            return str(client_obj["email"])

    list_res = await _panel_request("GET", "/panel/api/clients/list")
    if list_res and list_res.get("success") and isinstance(list_res.get("obj"), list):
        for item in list_res["obj"]:
            if not isinstance(item, dict):
                continue
            if item.get("email") == identifier or item.get("uuid") == identifier or item.get("subId") == identifier:
                if item.get("email"):
                    return str(item["email"])

    return identifier


def _client_update_body_from_record(record: dict) -> dict:
    """
    Преобразует запись из GET /panel/api/clients/get/{email}
    в тело для POST /panel/api/clients/update/{email}, сохраняя все поля.
    """
    body = dict(record)
    for k in ("id", "createdAt", "updatedAt"):
        body.pop(k, None)

    if "uuid" in body:
        body["id"] = body.pop("uuid")

    if isinstance(body.get("allowedIPs"), str):
        ips = [p.strip() for p in body["allowedIPs"].split(",") if p.strip()]
        if ips:
            body["allowedIPs"] = ips
        else:
            body.pop("allowedIPs", None)

    return body


# ──────────────────────────────────────────────────────────────
# 🗝 Операции с клиентами (раздел «Клиенты» -> Привязанные входящие)
# ──────────────────────────────────────────────────────────────

async def create_vpn_user(
    telegram_id: int,
    hours: float,
    key_label: str,
) -> tuple[str, str]:
    if hours <= 0:
        raise ValueError("hours must be > 0")

    try:
        inbound_ids = await _get_inbound_ids()
        client_uuid = str(uuid.uuid4())
        sub_id = _generate_sub_id(16)
        email = f"tg{telegram_id}_{int(time.time())}"
        expiry_ms = int((time.time() + hours * 3600) * 1000)

        payload = {
            "client": {
                "id": client_uuid,
                "email": email,
                "enable": True,
                "expiryTime": expiry_ms,
                "limitIp": 0,
                "limitHwid": 0,
                "totalGB": 0,
                "tgId": int(telegram_id),
                "subId": sub_id,
                "reset": 0,
            },
            "inboundIds": inbound_ids,
        }

        data = await _panel_request("POST", "/panel/api/clients/add", json_body=payload)
        if not data or not data.get("success"):
            msg = data.get("msg") if isinstance(data, dict) else "нет ответа от панели"
            raise RuntimeError(f"Панель отклонила создание клиента: {msg}")

        sub_link = _build_sub_link(sub_id)
        logger.info(
            f"[xui] client created: email={email} sub_id={sub_id} inbounds={inbound_ids}"
        )
        return sub_link, email

    except asyncio.TimeoutError:
        _invalidate_session()
        logger.error(f"[xui] timeout in create_vpn_user for {telegram_id}")
        raise RuntimeError("Панель 3x-ui не ответила вовремя, попробуйте позже")
    except Exception as e:
        logger.exception(f"[xui] create_vpn_user failed: {e}")
        raise RuntimeError(f"Ошибка при создании ключа в 3x-ui: {e}")


async def delete_vpn_user(client_id: str) -> None:
    if not client_id:
        return

    try:
        email = await _resolve_client_email(client_id)
        encoded = quote(email, safe="")
        data = await _panel_request("POST", f"/panel/api/clients/del/{encoded}")
        if data and data.get("success"):
            logger.info(f"[xui] client deleted: {email}")
        else:
            logger.warning(f"[xui] delete skipped or already absent: {email} ({data})")
    except asyncio.TimeoutError:
        _invalidate_session()
        logger.error(f"[xui] delete timeout: {client_id}")
    except Exception:
        logger.exception(f"[xui] delete failed: {client_id}")


async def update_vpn_user_expiry(client_id: str, expiry_time_ms: int) -> None:
    if not client_id:
        return

    try:
        email = await _resolve_client_email(client_id)
        encoded = quote(email, safe="")

        res = await _panel_request("GET", f"/panel/api/clients/get/{encoded}")
        if not res or not res.get("success") or not isinstance(res.get("obj"), dict):
            logger.warning(f"[xui] update_expiry: клиент не найден {client_id}")
            return

        client_record = res["obj"].get("client")
        if not isinstance(client_record, dict):
            logger.warning(f"[xui] update_expiry: пустая запись клиента {email}")
            return

        body = _client_update_body_from_record(client_record)
        body["expiryTime"] = int(expiry_time_ms)
        body["enable"] = True

        upd = await _panel_request("POST", f"/panel/api/clients/update/{encoded}", json_body=body)
        if not upd or not upd.get("success"):
            msg = upd.get("msg") if isinstance(upd, dict) else "unknown"
            raise RuntimeError(f"Панель не обновила срок клиента {email}: {msg}")

        logger.info(f"[xui] expiry updated: {email} -> {expiry_time_ms}")

    except asyncio.TimeoutError:
        _invalidate_session()
        logger.error(f"[xui] update_expiry timeout: {client_id}")
        raise RuntimeError("Панель 3x-ui не ответила вовремя при обновлении срока")
    except Exception as e:
        logger.exception(f"[xui] update_expiry failed: {client_id}: {e}")
        raise RuntimeError(f"Ошибка обновления срока ключа в 3x-ui: {e}")


async def close_panel_session() -> None:
    global _session
    async with _api_lock:
        _invalidate_session()
        if _session is not None and not _session.closed:
            await _session.close()
        _session = None


# ──────────────────────────────────────────────────────────────
# 🔍 Мониторинг IP клиентов
# ──────────────────────────────────────────────────────────────

async def get_client_ips(email: str) -> set[str]:
    encoded = quote(email, safe="")
    data = await _panel_request("POST", f"/panel/api/clients/ips/{encoded}")
    if data is None or not data.get("success"):
        data = await _panel_request("POST", f"/panel/api/inbounds/clientIps/{encoded}")

    if data is None:
        return set()

    raw = data.get("obj")
    if not raw or raw == "No IP Record":
        return set()

    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw.splitlines()
    else:
        parsed = raw

    ips: set[str] = set()
    for line in parsed:
        ip = str(line).split(" ")[0].strip()
        if ip:
            ips.add(ip)
    return ips


async def get_all_client_emails() -> list[str]:
    try:
        data = await _panel_request("GET", "/panel/api/clients/list")
        if data and data.get("success") and isinstance(data.get("obj"), list):
            return [
                str(c["email"])
                for c in data["obj"]
                if isinstance(c, dict) and c.get("email")
            ]
        return []
    except Exception as e:
        logger.warning(f"[xui] get_all_client_emails error: {e}")
        return []


async def check_suspicious_activity() -> int:
    if time.time() < _circuit_broken_until:
        return 0

    emails = await get_all_client_emails()
    if not emails:
        return 0

    found = 0
    consecutive_errors = 0

    for email in emails:
        try:
            current = await get_client_ips(email)
            consecutive_errors = 0
        except Exception:
            consecutive_errors += 1
            if consecutive_errors >= 3:
                logger.warning(
                    "[suspicious] Панель не отвечает при проверке IP — прерываем цикл"
                )
                break
            continue

        previous = _previous_ips.get(email, set())
        new_ips = current - previous
        _previous_ips[email] = current

        if len(new_ips) >= SUSPICIOUS_NEW_IP_THRESHOLD:
            found += 1
            logger.warning(
                f"[suspicious] {email}: +{len(new_ips)} new IPs "
                f"(total {len(current)})"
            )
            _sus_logger.warning(
                f"client='{email}' new={len(new_ips)} "
                f"total={len(current)} ips={sorted(new_ips)}"
            )

        await asyncio.sleep(0.25)

    return found

import asyncio
import json
import logging
import logging.handlers
import os
import re
import secrets
import string
import time
import uuid
from urllib.parse import quote

import httpx
from py3xui import AsyncApi

from config import (
    XUI_HOST, XUI_USERNAME, XUI_PASSWORD, XUI_TOKEN, XUI_TLS_VERIFY,
    XUI_INBOUND_IDS,
    XUI_SUB_HOST, XUI_SUB_PORT, XUI_SUB_PATH, XUI_SUB_SECURE,
    SUSPICIOUS_NEW_IP_THRESHOLD,
)

logger = logging.getLogger(__name__)

XUI_TIMEOUT = 20                  # таймаут одного HTTP-запроса к панели
OP_TIMEOUT = XUI_TIMEOUT * 2      # общий таймаут операции (запрос + возможный перелогин)
# При полном падении панели — короткая пауза, чтобы не долбить её логинами
CIRCUIT_COOLDOWN = 60

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


# ──────────────────────────────────────────────────────────────
# 🛡 Одна авторизация → переиспользуем сессию
# Перелогин ТОЛЬКО если сессия умерла (401/403/редирект на логин).
# ──────────────────────────────────────────────────────────────

_api_lock = asyncio.Lock()
_global_api: AsyncApi | None = None
_circuit_broken_until: float = 0.0

# Не больше 2 параллельных запросов к панели на весь процесс
_panel_semaphore = asyncio.Semaphore(2)

# Кэш автоопределения локаций (если XUI_INBOUND_IDS не задан в env)
_inbound_ids_cache: list[int] | None = None

# Признаки «сессия умерла» в сообщениях панели
_AUTH_ERROR_HINTS = (
    "login", "log in", "unauthorized", "unauthenticated",
    "session", "forbidden", "не автор", "войдите",
)


def _invalidate_session() -> None:
    global _global_api
    _global_api = None


async def _get_api() -> AsyncApi:
    """
    Возвращает уже авторизованный AsyncApi.
    Логин выполняется один раз; дальше все запросы ходят
    с той же cookie-сессией, пока панель её не отвергнет.
    """
    global _global_api, _circuit_broken_until

    now = time.time()
    if now < _circuit_broken_until:
        raise RuntimeError(
            f"3x-UI на паузе после сбоя (ещё {int(_circuit_broken_until - now)}с)"
        )

    # Быстрый путь без лока: сессия уже есть
    if _global_api is not None:
        return _global_api

    async with _api_lock:
        # double-check после захвата лока
        if _global_api is not None:
            return _global_api

        logger.info("[xui] Авторизация в 3x-UI (один раз)...")
        api = AsyncApi(
            XUI_HOST,
            XUI_USERNAME or None,
            XUI_PASSWORD or None,
            use_tls_verify=XUI_TLS_VERIFY,
            token=XUI_TOKEN or None,
        )
        try:
            if XUI_TOKEN:
                # API-токен — логин не нужен
                pass
            else:
                await asyncio.wait_for(api.login(), timeout=XUI_TIMEOUT)

            for sub_api in (api.client, api.inbound, api.database, api.server):
                sub_api.max_retries = 2

            _global_api = api
            logger.info("[xui] Сессия 3x-UI активна, дальше без повторных логинов")
            return _global_api
        except Exception as e:
            _invalidate_session()
            _circuit_broken_until = time.time() + CIRCUIT_COOLDOWN
            logger.error(
                f"[xui] Логин в 3x-UI не удался: {e}. "
                f"Cooldown {CIRCUIT_COOLDOWN}s"
            )
            raise RuntimeError("Панель 3x-UI временно недоступна")


# ──────────────────────────────────────────────────────────────
# 🔌 Единая точка запросов к API панели (новый API 3x-ui)
# ──────────────────────────────────────────────────────────────

async def _panel_call(method: str, path: str, json_body: dict | None = None):
    """
    Один запрос к /panel/api/* через общую сессию py3xui (cookie + CSRF).
    При отвале сессии — перелогин и повтор (один раз).
    Возвращает поле "obj" из ответа панели.
    """
    async with _panel_semaphore:
        return await _panel_call_inner(method, path, json_body, retried_auth=False)


async def _panel_call_inner(method: str, path: str, json_body: dict | None, retried_auth: bool):
    api = await _get_api()
    url = api.client._url(path)
    headers = {"Accept": "application/json"}
    timeout = httpx.Timeout(XUI_TIMEOUT)

    try:
        if method == "GET":
            resp = await api.client._get(url, headers, timeout=timeout)
        else:
            resp = await api.client._post(
                url, headers, json_body if json_body is not None else {}, timeout=timeout
            )
        data = resp.json()

    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        if status in (401, 403) and not retried_auth:
            logger.warning(f"[xui] сессия сброшена (HTTP {status}), перелогин: {path}")
            _invalidate_session()
            return await _panel_call_inner(method, path, json_body, retried_auth=True)
        raise RuntimeError(f"Панель 3x-ui ответила HTTP {status} на {path}") from e

    except json.JSONDecodeError as e:
        # Панель вернула не JSON (например, редирект на страницу логина)
        if not retried_auth:
            logger.warning(f"[xui] не-JSON ответ панели, перелогин: {path}")
            _invalidate_session()
            return await _panel_call_inner(method, path, json_body, retried_auth=True)
        raise RuntimeError("Панель 3x-ui вернула неожиданный ответ (сессия истекла?)") from e

    except ValueError as e:
        # py3xui проверяет success=false и кидает ValueError с msg панели
        msg = str(e)
        if not retried_auth and any(h in msg.lower() for h in _AUTH_ERROR_HINTS):
            logger.warning(f"[xui] панель требует входа, перелогин: {path}")
            _invalidate_session()
            return await _panel_call_inner(method, path, json_body, retried_auth=True)
        raise RuntimeError(f"Панель 3x-ui: {msg}") from e

    except (httpx.RequestError, httpx.TimeoutException) as e:
        _invalidate_session()
        logger.error(f"[xui] сеть/таймаут при запросе {path}: {e}")
        raise RuntimeError("Панель 3x-ui не отвечает, попробуйте позже") from e

    if not isinstance(data, dict):
        raise RuntimeError("Панель 3x-ui вернула неожиданный формат ответа")

    return data.get("obj")


# ──────────────────────────────────────────────────────────────
# 🌍 Локации (inbounds): env или автоопределение из панели
# ──────────────────────────────────────────────────────────────

async def _resolve_inbound_ids() -> list[int]:
    """
    Список inbound'ов (локаций), в которые создаются клиенты.
    1) XUI_INBOUND_IDS из env (например "1,2") — приоритет.
    2) Иначе — ВСЕ inbound'ы панели (обе локации и любые новые).
    """
    global _inbound_ids_cache

    if XUI_INBOUND_IDS:
        return list(XUI_INBOUND_IDS)

    if _inbound_ids_cache is not None:
        return list(_inbound_ids_cache)

    obj = await _panel_call("GET", "panel/api/inbounds/list")

    ids: list[int] = []
    for item in obj or []:
        try:
            if item.get("id") is not None:
                value = int(item["id"])
                if value > 0 and value not in ids:
                    ids.append(value)
        except (TypeError, ValueError, AttributeError):
            continue

    if not ids:
        raise RuntimeError("В панели 3x-ui не найдено ни одной локации (inbound)")

    _inbound_ids_cache = ids
    logger.info(f"[xui] Автоопределение локаций: inbound {ids}")
    return list(ids)


def invalidate_inbound_cache() -> None:
    global _inbound_ids_cache
    _inbound_ids_cache = None


# ──────────────────────────────────────────────────────────────
# 🔗 Ссылка подписки
# ──────────────────────────────────────────────────────────────

_SUB_ALPHABET = string.ascii_lowercase + string.digits


def _generate_sub_id(length: int = 16) -> str:
    return "".join(secrets.choice(_SUB_ALPHABET) for _ in range(length))


def build_sub_link(sub_id: str) -> str:
    """
    Собирает ссылку подписки:
    https://XUI_SUB_HOST:XUI_SUB_PORT/XUI_SUB_PATH/<subId>
    """
    scheme = "https" if XUI_SUB_SECURE else "http"
    host = XUI_SUB_HOST.strip()
    if not host:
        raise RuntimeError("Не настроен адрес подписки (XUI_SUB_HOST)")

    default_port = 443 if XUI_SUB_SECURE else 80
    base = f"{scheme}://{host}"
    if XUI_SUB_PORT and XUI_SUB_PORT != default_port:
        base += f":{XUI_SUB_PORT}"

    path = "/".join(p for p in XUI_SUB_PATH.split("/") if p)
    return f"{base}/{path}/{sub_id}" if path else f"{base}/{sub_id}"


# ──────────────────────────────────────────────────────────────
# 🗝 Операции с клиентами
# ──────────────────────────────────────────────────────────────

async def create_vpn_user(
    telegram_id: int,
    hours: float,
    key_label: str,
) -> tuple[str, str]:
    """
    Создаёт клиента в панели СРАЗУ ВО ВСЕХ локациях (inbounds)
    и возвращает (ссылка подписки, email клиента в панели).

    Ссылка подписки содержит ключи всех локаций — юзер вставляет
    её в VPN-клиент (Happ / INCY / v2rayN и т.д.) и видит оба сервера.
    """
    if hours <= 0:
        raise ValueError("hours must be > 0")

    client_uuid = str(uuid.uuid4())
    sub_id = _generate_sub_id()
    email = f"tg{telegram_id}_{int(time.time() * 1000)}"
    expiry_ms = int((time.time() + hours * 3600) * 1000)

    try:
        inbound_ids = await asyncio.wait_for(
            _resolve_inbound_ids(), timeout=OP_TIMEOUT
        )
        if not inbound_ids:
            raise RuntimeError("В панели 3x-ui не найдено ни одной локации (inbound)")

        payload = {
            "client": {
                "email": email,
                "id": client_uuid,
                "subId": sub_id,
                "expiryTime": expiry_ms,
                "tgId": int(telegram_id),
                "limitIp": 0,
                "totalGB": 0,
                "enable": True,
                "comment": (key_label or "")[:100],
            },
            # 👇 обе локации одним запросом — как галочки в панели
            "inboundIds": list(inbound_ids),
        }

        await asyncio.wait_for(
            _panel_call("POST", "panel/api/clients/add", payload),
            timeout=OP_TIMEOUT,
        )

    except asyncio.TimeoutError:
        _invalidate_session()
        logger.error(f"[xui] timeout in create_vpn_user for {telegram_id}")
        raise RuntimeError("Панель 3x-ui не ответила вовремя, попробуйте позже")
    except (RuntimeError, ValueError):
        raise
    except Exception as e:
        _invalidate_session()
        logger.exception(f"[xui] create_vpn_user failed: {e}")
        raise RuntimeError(f"Ошибка при создании ключа в 3x-ui: {e}")

    sub_link = build_sub_link(sub_id)
    logger.info(
        f"[xui] client created: {email} → inbounds {inbound_ids} ({key_label})"
    )
    return sub_link, email


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


async def _resolve_client_email(client_ref: str) -> str | None:
    """
    client_ref — email (новые ключи) или UUID (старые записи в БД).
    Для UUID ищем email через список клиентов панели.
    """
    ref = (client_ref or "").strip()
    if not ref:
        return None
    if not _UUID_RE.match(ref):
        # это уже email (в 3x-ui email может быть без @)
        return ref

    obj = await _panel_call("GET", "panel/api/clients/list")
    for item in obj or []:
        if not isinstance(item, dict):
            continue
        if ref in (str(item.get("uuid") or ""), str(item.get("id") or "")):
            email = item.get("email")
            if email:
                return str(email)
    return None


async def delete_vpn_user(client_ref: str) -> None:
    """Удаляет клиента из панели (из всех подключённых inbound'ов сразу)."""
    if not client_ref:
        return

    try:
        email = await asyncio.wait_for(
            _resolve_client_email(client_ref), timeout=OP_TIMEOUT
        )
        if not email:
            logger.warning(f"[xui] delete skipped, client already absent: {client_ref}")
            return

        await asyncio.wait_for(
            _panel_call("POST", f"panel/api/clients/del/{quote(email, safe='')}"),
            timeout=OP_TIMEOUT,
        )
        logger.info(f"[xui] client deleted: {email}")

    except asyncio.TimeoutError:
        _invalidate_session()
        logger.error(f"[xui] delete timeout: {client_ref}")
    except Exception:
        _invalidate_session()
        logger.exception(f"[xui] delete failed: {client_ref}")


async def update_vpn_user_expiry(client_ref: str, expiry_time_ms: int) -> None:
    """
    Обновляет срок действия клиента в 3x-ui.
    Изменения применяются сразу во всех inbound'ах клиента
    (новый API панели сам рассылает это по всем локациям).
    """
    if not client_ref:
        return

    try:
        email = await asyncio.wait_for(
            _resolve_client_email(client_ref), timeout=OP_TIMEOUT
        )
        if not email:
            logger.warning(f"[xui] update_expiry: клиент не найден {client_ref}")
            return

        obj = await asyncio.wait_for(
            _panel_call("GET", f"panel/api/clients/get/{quote(email, safe='')}"),
            timeout=OP_TIMEOUT,
        )

        client = None
        if isinstance(obj, dict):
            inner = obj.get("client")
            client = inner if isinstance(inner, dict) else obj

        if not isinstance(client, dict):
            logger.warning(f"[xui] update_expiry: пустой ответ панели для {email}")
            return

        # Меняем только срок и enable, остальное отправляем как есть
        client["expiryTime"] = int(expiry_time_ms)
        client["enable"] = True

        await asyncio.wait_for(
            _panel_call(
                "POST",
                f"panel/api/clients/update/{quote(email, safe='')}",
                client,
            ),
            timeout=OP_TIMEOUT,
        )
        logger.info(f"[xui] expiry updated: {email} -> {expiry_time_ms}")

    except asyncio.TimeoutError:
        _invalidate_session()
        logger.error(f"[xui] update_expiry timeout: {client_ref}")
        raise RuntimeError("Панель 3x-ui не ответила вовремя при обновлении срока")
    except RuntimeError:
        raise
    except Exception as e:
        _invalidate_session()
        logger.exception(f"[xui] update_expiry failed: {client_ref}: {e}")
        raise RuntimeError(f"Ошибка обновления срока ключа в 3x-ui: {e}")


async def close_panel_session() -> None:
    async with _api_lock:
        _invalidate_session()


# ──────────────────────────────────────────────────────────────
# 🔍 Информация о клиентах
# ──────────────────────────────────────────────────────────────

def _parse_ip_records(raw) -> set[str]:
    ips: set[str] = set()
    if not raw or raw == "No IP Record":
        return ips

    records = raw
    if isinstance(raw, str):
        try:
            records = json.loads(raw)
        except json.JSONDecodeError:
            records = raw.splitlines()

    if not isinstance(records, (list, tuple, set)):
        return ips

    for line in records:
        ip = str(line).split(" ")[0].strip()
        if ip:
            ips.add(ip)
    return ips


async def get_client_ips(email: str) -> set[str]:
    if not email:
        return set()
    try:
        raw = await _panel_call(
            "POST", f"panel/api/clients/ips/{quote(email, safe='')}", {}
        )
    except Exception as e:
        logger.debug(f"[xui] get_client_ips failed for {email}: {e}")
        return set()
    return _parse_ip_records(raw)


async def get_all_client_emails() -> list[str]:
    try:
        obj = await _panel_call("GET", "panel/api/clients/list")
        emails = []
        for item in obj or []:
            if isinstance(item, dict) and item.get("email"):
                emails.append(str(item["email"]))
        return emails
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

        # Лёгкий троттлинг только для массового IP-скана, не для create/update
        await asyncio.sleep(0.25)

    return found


# ──────────────────────────────────────────────────────────────
# 🚀 Проверка при старте: логируем локации и шаблон подписки
# ──────────────────────────────────────────────────────────────

async def warmup_and_log_panel() -> None:
    try:
        if not XUI_HOST:
            logger.error("[xui] ⚠️ XUI_HOST не задан — ключи создаваться не будут!")
            return

        inbound_ids = await _resolve_inbound_ids()
        logger.info(f"[xui] ✅ Локации для новых ключей (inbounds): {inbound_ids}")

        try:
            logger.info(
                f"[xui] ✅ Ссылка подписки: {build_sub_link('<subId>')}"
            )
        except Exception as e:
            logger.error(f"[xui] ⚠️ Не настроена ссылка подписки: {e}")
    except Exception as e:
        logger.warning(f"[xui] ⚠️ Панель 3x-ui недоступна при старте: {e}")

import asyncio
import uuid
import time
import json
import logging
import logging.handlers
import os
from urllib.parse import quote

import aiohttp
from py3xui import AsyncApi, Client

from config import (
    XUI_HOST, XUI_USERNAME, XUI_PASSWORD, XUI_INBOUND_ID,
    XUI_SERVER_ADDRESS, XUI_SERVER_PORT, XUI_PUBLIC_KEY,
    XUI_SHORT_ID, XUI_SNI, XUI_FINGERPRINT,
    XUI_ENCRYPTION, XUI_GRPC_SERVICE_NAME,
    SUSPICIOUS_NEW_IP_THRESHOLD,
)

logger = logging.getLogger(__name__)

XUI_TIMEOUT = 20
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
# Перелогин ТОЛЬКО если сессия умерла (401) или была сброшена.
# Никакого планового релогина каждые N минут — без спама.
# ──────────────────────────────────────────────────────────────

_api_lock = asyncio.Lock()
_global_api: AsyncApi | None = None
_circuit_broken_until: float = 0.0

# Не больше 2 параллельных запросов к панели на весь процесс
_panel_semaphore = asyncio.Semaphore(2)


def _invalidate_session() -> None:
    global _global_api
    _global_api = None


async def _get_api() -> AsyncApi:
    """
    Возвращает уже авторизованный AsyncApi.
    Логин выполняется один раз; дальше все create/delete/update
    ходят с той же cookie-сессией, пока панель её не отвергнет.
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
        api = AsyncApi(XUI_HOST, XUI_USERNAME, XUI_PASSWORD)
        try:
            await asyncio.wait_for(api.login(), timeout=XUI_TIMEOUT)
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


def _build_vless_link(client_uuid: str, telegram_id: int) -> str:
    params = {
        "type":        "grpc",
        "serviceName": XUI_GRPC_SERVICE_NAME,
        "mode":        "gun",
        "security":    "reality",
        "pbk":         XUI_PUBLIC_KEY,
        "fp":          XUI_FINGERPRINT,
        "sni":         XUI_SNI,
        "sid":         XUI_SHORT_ID,
        "encryption":  XUI_ENCRYPTION,
    }

    params = {k: v for k, v in params.items() if v}
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())

    short_id = str(telegram_id)[-3:]
    remark = quote(f"🇫🇮 FlowVPN-{short_id}", safe="")

    return (
        f"vless://{client_uuid}"
        f"@{XUI_SERVER_ADDRESS}:{XUI_SERVER_PORT}"
        f"?{query}"
        f"#{remark}"
    )


# ──────────────────────────────────────────────────────────────
# 🗝 Операции с клиентами
# ──────────────────────────────────────────────────────────────

async def create_vpn_user(
    telegram_id: int,
    hours: float,
    key_label: str,
) -> tuple[str, str]:
    if hours <= 0:
        raise ValueError("hours must be > 0")

    async with _panel_semaphore:
        try:
            api = await _get_api()
            client_uuid = str(uuid.uuid4())
            email = f"tg{telegram_id}_{int(time.time())}"
            expiry_ms = int((time.time() + hours * 3600) * 1000)

            client = Client(
                id=client_uuid,
                email=email,
                enable=True,
                expiry_time=expiry_ms,
                limit_ip=0,
                total_gb=0,
                tg_id=int(telegram_id),
                sub_id=uuid.uuid4().hex,
            )

            await asyncio.wait_for(
                api.client.add(XUI_INBOUND_ID, [client]),
                timeout=XUI_TIMEOUT,
            )
            logger.info(f"[xui] client created: {email}")

            return _build_vless_link(client_uuid, telegram_id), client_uuid

        except asyncio.TimeoutError:
            _invalidate_session()
            logger.error(f"[xui] timeout in create_vpn_user for {telegram_id}")
            raise RuntimeError("Панель 3x-ui не ответила вовремя, попробуйте позже")
        except Exception as e:
            _invalidate_session()
            logger.exception(f"[xui] create_vpn_user failed: {e}")
            raise RuntimeError(f"Ошибка при создании ключа в 3x-ui: {e}")


async def delete_vpn_user(client_uuid: str) -> None:
    async with _panel_semaphore:
        try:
            api = await _get_api()
            await asyncio.wait_for(
                api.client.delete(XUI_INBOUND_ID, client_uuid),
                timeout=XUI_TIMEOUT,
            )
            logger.info(f"[xui] client deleted: {client_uuid}")
        except ValueError:
            logger.warning(f"[xui] delete skipped, client already absent: {client_uuid}")
        except asyncio.TimeoutError:
            _invalidate_session()
            logger.error(f"[xui] delete timeout: {client_uuid}")
        except Exception:
            _invalidate_session()
            logger.exception(f"[xui] delete failed: {client_uuid}")


async def update_vpn_user_expiry(client_uuid: str, expiry_time_ms: int) -> None:
    """
    Обновляет expiryTime клиента в 3x-ui.

    Использует УЖЕ авторизованную сессию (без нового логина).
    3x-ui при updateClient перезаписывает объект клиента, поэтому
    сначала читаем inbound, берём клиента как есть, меняем только
    expiry_time и enable — email/tg_id/sub_id/limit не трогаем.
    """
    if not client_uuid:
        return

    async with _panel_semaphore:
        try:
            api = await _get_api()

            inbound = await asyncio.wait_for(
                api.inbound.get_by_id(XUI_INBOUND_ID),
                timeout=XUI_TIMEOUT,
            )
            if not inbound or not inbound.settings or not inbound.settings.clients:
                logger.warning(f"[xui] update_expiry: inbound пуст, client={client_uuid}")
                return

            target = None
            for c in inbound.settings.clients:
                if getattr(c, "id", None) == client_uuid:
                    target = c
                    break

            if target is None:
                logger.warning(f"[xui] update_expiry: клиент не найден {client_uuid}")
                return

            target.expiry_time = int(expiry_time_ms)
            if hasattr(target, "enable"):
                target.enable = True

            await asyncio.wait_for(
                api.client.update(client_uuid, target),
                timeout=XUI_TIMEOUT,
            )
            logger.info(f"[xui] expiry updated: {client_uuid} -> {expiry_time_ms}")

        except asyncio.TimeoutError:
            _invalidate_session()
            logger.error(f"[xui] update_expiry timeout: {client_uuid}")
            raise RuntimeError("Панель 3x-ui не ответила вовремя при обновлении срока")
        except Exception as e:
            _invalidate_session()
            logger.exception(f"[xui] update_expiry failed: {client_uuid}: {e}")
            raise RuntimeError(f"Ошибка обновления срока ключа в 3x-ui: {e}")


async def close_panel_session() -> None:
    async with _api_lock:
        _invalidate_session()


# ──────────────────────────────────────────────────────────────
# 🔍 Прямые запросы к панели через ту же сессию
# ──────────────────────────────────────────────────────────────

async def _panel_request(method: str, path: str, json_body: dict | None = None) -> dict | None:
    """
    HTTP-запрос к 3x-UI с cookie уже авторизованной сессии.
    При 401/403 — сбрасываем сессию (следующий вызов залогинится сам).
    """
    async with _panel_semaphore:
        try:
            api = await _get_api()
            session = api._session

            kwargs = {
                "ssl": False,
                "timeout": aiohttp.ClientTimeout(total=XUI_TIMEOUT),
            }
            if json_body is not None:
                kwargs["json"] = json_body

            async with session.request(method, f"{XUI_HOST}{path}", **kwargs) as r:
                if r.status in (401, 403):
                    _invalidate_session()
                    return None
                if r.status != 200:
                    return None
                try:
                    return await r.json(content_type=None)
                except Exception:
                    return None

        except Exception as e:
            logger.debug(f"[xui] _panel_request {path} failed: {e}")
            return None


async def get_client_ips(email: str) -> set[str]:
    data = await _panel_request("POST", f"/panel/api/inbounds/clientIps/{email}")

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
    async with _panel_semaphore:
        try:
            api = await _get_api()
            inbound = await asyncio.wait_for(
                api.inbound.get_by_id(XUI_INBOUND_ID),
                timeout=XUI_TIMEOUT,
            )
            if inbound and inbound.settings and inbound.settings.clients:
                return [
                    c.email
                    for c in inbound.settings.clients
                    if getattr(c, "email", None)
                ]
            return []
        except asyncio.TimeoutError:
            _invalidate_session()
            logger.error("[xui] ⏳ get_all_client_emails: таймаут")
            return []
        except Exception as e:
            _invalidate_session()
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

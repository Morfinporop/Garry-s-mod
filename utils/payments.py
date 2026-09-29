import uuid
import logging
from yookassa import Configuration, Payment
from config import YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY, YOOKASSA_RETURN_URL

logger = logging.getLogger(__name__)

if YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY:
    Configuration.account_id = str(YOOKASSA_SHOP_ID)
    Configuration.secret_key = str(YOOKASSA_SECRET_KEY)
    logger.info(f"YooKassa инициализирована: SHOP_ID={YOOKASSA_SHOP_ID}")
else:
    logger.error(
        f"YooKassa НЕ инициализирована! "
        f"SHOP_ID={'OK' if YOOKASSA_SHOP_ID else 'ПУСТО'}, "
        f"SECRET_KEY={'OK' if YOOKASSA_SECRET_KEY else 'ПУСТО'}"
    )


def create_payment(user_id: int, amount: int) -> tuple[str, str] | None:
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error("create_payment: YooKassa не настроена")
        return None

    try:
        payment = Payment.create({
            "amount": {
                "value": f"{amount}.00",
                "currency": "RUB"
            },
            "confirmation": {
                "type": "redirect",
                "return_url": YOOKASSA_RETURN_URL
            },
            "capture": True,
            "description": f"Пополнение баланса FlowVPN · user {user_id}",
            "metadata": {
                "user_id": str(user_id),
                "amount": str(amount),
            }
        }, uuid.uuid4())

        return payment.id, payment.confirmation.confirmation_url
    except Exception:
        logger.exception("YooKassa: ошибка создания платежа")
        return None


def check_payment(payment_id: str) -> str | None:
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error("check_payment: YooKassa не настроена")
        return None

    try:
        payment = Payment.find_one(payment_id)
        return payment.status
    except Exception:
        logger.exception(f"YooKassa: ошибка проверки {payment_id}")
        return None


def cancel_payment(payment_id: str) -> bool:
    """⌛ Попытка отменить неоплаченный счёт (если ЮKassa разрешает)."""
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        return False

    try:
        payment = Payment.find_one(payment_id)
        if payment and payment.status == "pending":
            try:
                Payment.cancel(payment_id)
                return True
            except Exception:
                # для redirect-платежей отмена может быть недоступна —
                # счёт просто истечёт на стороне ЮKassa
                logger.info(f"cancel_payment: отмена {payment_id} недоступна, счёт истечёт сам")
                return False
        return False
    except Exception:
        logger.exception(f"Yookassa: ошибка отмены {payment_id}")
        return False

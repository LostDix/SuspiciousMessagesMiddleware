import logging, re
from typing import Callable, Dict, Any, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import Update, Message
from aiogram.enums import ChatType
from itertools import groupby

logger = logging.getLogger(__name__)


class SuspiciousMessagesMiddleware(BaseMiddleware):
    def __init__(self, bot):
        self.bot = bot
        super().__init__()
        logger.info("Initialized SuspiciousMessagesMiddleware")

    async def __call__(
            self,
            handler: Callable[[Update, Dict[str, Any]], Awaitable[Any]],
            event: Update,
            data: Dict[str, Any]
    ) -> Any:
        try:
            message = event.message or event.edited_message
            if not message:
                return await handler(event, data)

            # Пропускаем служебные сообщения от Telegram
            if self._is_service_message(message):
                return await handler(event, data)

            if message.chat.type not in [ChatType.GROUP, ChatType.SUPERGROUP]:
                return await handler(event, data)

            text = message.text or message.caption
            if not text:
                return await handler(event, data)

            if not self._is_suspicious(text):
                return await handler(event, data)

            # Сохраняем reply_to_message
            reply_to_message_id = message.reply_to_message.message_id if message.reply_to_message else None

            try:
                await message.delete()
                logger.info(f"Deleted suspicious message in chat {message.chat.id}")
            except Exception as e:
                logger.error(f"Failed to delete suspicious message: {e}")
                return await handler(event, data)

            user_mention = message.from_user.mention_html() if message.from_user else "Аноним"

            await self.bot.send_message(
                chat_id=message.chat.id,
                text=f"⚠️ {user_mention} отправил подозрительное сообщение (возможен спам):\n{text}",
                parse_mode="HTML",
                reply_to_message_id=reply_to_message_id
            )

            return None

        except Exception as e:
            logger.exception(f"Error in SuspiciousMessagesMiddleware: {e}")
            return await handler(event, data)

    def _is_service_message(self, message: Message) -> bool:
        """Проверяет, является ли сообщение служебным от Telegram"""
        # Сообщения без отправителя (системные)
        if not message.from_user:
            return True

        # Пользователь Telegram имеет ID 777000 (служебные уведомления)
        if message.from_user.id == 777000:
            return True

        # Сообщения о входе в чат, закреплении и т.д.
        if message.new_chat_members or message.left_chat_member or message.pinned_message:
            return True

        return False

    def _is_suspicious(self, text: str) -> bool:
        """Определяет подозрительные сообщения"""
        # Цифры среди букв
        if re.search(r'\w*\d+\w*', text):
            return True

        # Повторяющиеся символы
        if any(len(list(g)) > 3 for _, g in groupby(text.lower())):
            return True

        # Слова в котором буквы разделены пробелом (п р и в е т)
        if re.search(r'(?:^|\s)([а-яa-z]\s){2,}[а-яa-z](?:$|\s)', text.lower()):
            return True

        # Предложения без пробелов вообще (но длиннее 3 символов)
        if len(text) > 3 and ' ' not in text:
            return True

        # Спецсимволы внутри слов
        if re.search(r'\w+[^\w\s]\w+', text):
            return True

        return False
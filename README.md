# SuspiciousMessagesMiddleware | Защита Telegram-чатов от спама и подозрительных сообщений
Этот код реализует middleware для Telegram бота, который анализирует сообщения в группах и супергруппах на предмет подозрительного содержания. Давайте разберём его функционал подробно.
<br>
[Разработка Телеграм ботов](https://else.com.ru "Разработка Телеграм ботов") -> https://else.com.ru/

## Назначение класса
`SuspiciousMessagesMiddleware` - это промежуточный слой, который:

<ol> 
    <li>Анализирует текст сообщений на признаки спама</li> 
    <li>Автоматически удаляет подозрительные сообщения</li> 
    <li>Уведомляет участников чата о действии модерации</li> 
    <li>Сохраняет контекст общения (ответы на сообщения)</li> 
</ol>
    
## Инициализация
```
  def __init__(self, bot):
    self.bot = bot
    super().__init__()
    logger.info("Initialized SuspiciousMessagesMiddleware")
```


+ `bot` - экземпляр бота для выполнения действий (удаление сообщений, отправка уведомлений)</li>
+ Логирование инициализации middleware</li>

## Основная логика работы
Метод __call__ обрабатывает каждое входящее сообщение:
```
  async def __call__(
    self,
    handler: Callable[[Update, Dict[str, Any]], Awaitable[Any]],
    event: Update,
    data: Dict[str, Any]
) -> Any:
```

1. Получение и проверка сообщения
```
  message = event.message or event.edited_message
  if not message:
    return await handler(event, data)

  # Пропускаем служебные сообщения от Telegram
  if self._is_service_message(message):
    return await handler(event, data)

  if message.chat.type not in [ChatType.GROUP, ChatType.SUPERGROUP]:
    return await handler(event, data)
```
+ Работает только с обычными и отредактированными сообщениями</li>
+ Игнорирует служебные сообщения (вход/выход участников и т.д.)</li>
+ Активируется только в группах и супергруппах</li>

2. Анализ текста сообщения
```
  text = message.text or message.caption
  if not text:
    return await handler(event, data)

  if not self._is_suspicious(text):
    return await handler(event, data)
```
+ Проверяет основной текст и подписи к медиа</li>
+ Пропускает сообщения, не содержащие текст</li>
+ Анализирует текст на подозрительные паттерны</li>

3. Действия при обнаружении спама
```
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
```
+ Сохраняет ID сообщения, на которое был ответ</li>
+ Удаляет подозрительное сообщение</li>
+ Уведомляет чат о действии модерации</li>
+ Сохраняет контекст переписки (reply_to_message)</li>

## Методы анализа сообщений
Проверка на служебные сообщения
```
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
```

Детектор подозрительных сообщений
```
  def _is_suspicious(self, text: str) -> bool:
    """Определяет подозрительные сообщения"""
    # Цифры среди букв в слове (например "пр4вет")
    if re.search(r'\b\w+\d+\w+\b', text):
        return True

    # Повторяющиеся символы (более 3 подряд)
    if any(len(list(g)) > 3 for _, g in groupby(text.lower())):
        return True

    # Слова с разделёнными пробелом буквами (п р и в е т)
    if re.search(r'(?:^|\s)([а-яa-z]\s){2,}[а-яa-z](?:$|\s)', text.lower()):
        return True

    # Предложения без пробелов (длиннее 3 символов)
    if len(text) > 3 and ' ' not in text:
        return True

    # Спецсимволы внутри слов
    if re.search(r'\b\w+[^\w\s]\w+\b', text):
        return True

    return False
```

## Практическое применение
Этот middleware эффективен для:

+ Защиты групп от ботов-спамеров</li>
+ Борьбы с обходом цензуры (з4мена букв)</li>
+ Предотвращения флуда повторяющимися символами</li>
+ Обнаружения скрытых ссылок и рекламы</li>
+ Поддержания чистоты общения в чатах</li>

## Настройка и кастомизация
Вы можете расширить функционал:

<ol>
<li>Добавить свои регулярные выражения для обнаружения спама</li>
<li>Настроить белые списки пользователей</li>
<li>Добавить анализ медиафайлов</li>
<li>Реализовать систему предупреждений</li>
</ol>

```
  # Пример расширения детектора
  def _is_suspicious(self, text: str) -> bool:
    # Базовые проверки...
    
    # Дополнительные правила
    if "реклама" in text.lower():
        return True
        
    if "купить" in text.lower() and "http" in text.lower():
        return True
        
    return False
```

## Заключение
Представленный middleware обеспечивает интеллектуальную защиту чатов от спама, сохраняя при этом контекст общения и информируя участников о действиях модерации.
<br>
<blockquote>
<b>Нужна профессиональная защита вашего Telegram-чата от спамеров?</b>

Команда ELSE (https://else.com.ru/) разрабатывает комплексные решения для модерации Telegram-сообществ. Мы реализуем:<br>

✅ Умные антиспам-фильтры<br>
✅ Системы автоматической модерации чатов<br>
✅ Кастомизированные правила для вашего сообщества<br>
✅ Интеграцию с внешними сервисами проверки контента<br>

Оставьте заявку на else.com.ru и получите бота-модератора с индивидуальной настройкой под ваши задачи!<br>
[Создание Телеграм ботов](https://else.com.ru "Разработка Телеграм ботов") -> https://else.com.ru/
</blockquote>
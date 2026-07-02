Serpium Telegram WS-прогон
==========================

Сюда нужно положить официальный бинарник Flowseal TG WS Proxy:

  bin_files\tgws\TgWsProxy_windows.exe

Скачать: https://github.com/Flowseal/tg-ws-proxy/releases/latest

Как работает кнопка в Serpium:
1. Создаёт portable-папку TgWsProxy_data рядом с exe.
2. Создаёт config.json с портом 127.0.0.1:1443 и secret.
3. Запускает TgWsProxy_windows.exe --portable.
4. Открывает tg://proxy ссылку для Telegram Desktop.

Важно: это режим только для Telegram Desktop, не общий VPN для всей системы.

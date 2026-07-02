# Serpium VPN PC — Telegram WS-прогон

Добавлено:

- `TelegramProxyManager.cs`
- кнопка `Telegram WS-прогон` в `MainWindow.xaml`
- подключение Telegram-прокси в `MainWindow.xaml.cs`
- остановка Telegram-прокси через общую кнопку `ОСТАНОВИТЬ`
- папка `bin_files/tgws/` с инструкцией

## Что нужно докинуть вручную

Скачать официальный бинарник Flowseal TG WS Proxy и положить сюда:

```text
bin_files/tgws/TgWsProxy_windows.exe
```

Официальный репозиторий:

```text
https://github.com/Flowseal/tg-ws-proxy/releases/latest
```

## Как работает кнопка

1. Создаёт portable-конфиг в `bin_files/tgws/TgWsProxy_data/config.json`.
2. Фиксирует локальный MTProto-прокси: `127.0.0.1:1443`.
3. Генерирует и хранит secret.
4. Запускает `TgWsProxy_windows.exe --portable`.
5. Открывает `tg://proxy` ссылку для Telegram Desktop.
6. На всякий случай сохраняет ссылку в:

```text
bin_files/tgws/telegram_proxy_link.txt
```

Важно: это режим только для Telegram Desktop, не общий VPN для всей системы.

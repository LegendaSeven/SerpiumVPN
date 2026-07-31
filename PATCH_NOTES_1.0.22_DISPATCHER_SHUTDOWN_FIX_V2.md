# SerpiumVPN v1.0.22 — Dispatcher Shutdown Fix v2

Исправлен сам PowerShell-патчер: больше не используется некорректный многострочный оператор `-replace`.

Патч:
- заменяет `Dispatcher.Invoke(...)` на `SafeDispatcherInvoke(...)`;
- добавляет проверку завершения Dispatcher;
- использует `Dispatcher.BeginInvoke(...)`;
- освобождает Xray client/gateway в `ForceClose()`;
- выполняет чистую сборку.

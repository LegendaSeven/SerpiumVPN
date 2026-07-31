# MVP6.2.1 — Headless Client Build Hotfix

Исправляет две независимые ошибки первого патча MVP6.2.

## 1. Go: `undefined: tsnet.Status`

`tsnet.Server.Up` возвращает `*ipnstate.Status`, а не `*tsnet.Status`.
Сигнатура `upHeadless` исправлена, версия SerpiumNet повышена до
`0.5.1-mvp6.2.1-headless-client-build-hotfix`.

## 2. C#: дубли `StateChanged`, `LogReceived`, `Dispose`, `CanConnectAsync`

Первый apply-скрипт сохранял исходники в `SerpiumVPN\backups`. SDK-style
проект автоматически компилирует все `*.cs` под корнем, поэтому резервные
копии воспринимались как второй экземпляр классов.

Hotfix переносит каталоги `backups\MVP6_2_Headless_Client_*` на рабочий стол
в `SerpiumVPN_Backups`, после чего C#-дубли исчезают. Новая резервная копия
тоже создаётся за пределами проекта.

## После применения

Ожидается:

- успешный `go build`;
- `SerpiumNet.exe version` содержит `0.5.1`;
- успешная упаковка внешнего SerpiumNet Engine;
- `dotnet build` без ошибок `CS0229` и `CS0121`;
- прежние предупреждения проекта могут остаться.

# SerpiumVPN MVP6.2.2 — XrayClient System.IO Hotfix

## Исправление

После MVP6.2.1 файл `Relay/XrayClientManager.cs` использовал типы `Path`, `File`,
`Directory` и `FileNotFoundException`, но не импортировал пространство имён
`System.IO`. Из-за этого итоговая C#-сборка останавливалась с ошибками `CS0103`.

Добавлено:

```csharp
using System.IO;
```

Логика Headless Client Engine, SerpiumNet, Headscale и Xray не изменяется.

## Проверка

После применения ожидается:

- отсутствие ошибок `CS0103` для `Path` и `File`;
- успешная сборка `SerpiumVPN.csproj`;
- допустимы только ранее известные предупреждения, если они ещё присутствуют.

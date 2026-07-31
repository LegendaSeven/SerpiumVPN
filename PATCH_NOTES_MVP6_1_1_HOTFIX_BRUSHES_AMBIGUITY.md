# SerpiumVPN v1.0.35 — MVP6.1.1 Hotfix: Brushes Ambiguity

## Исправлено

Сборка падала с `CS0104`, потому что имя `Brushes` одновременно разрешалось как:

- `System.Drawing.Brushes`
- `System.Windows.Media.Brushes`

Во всех местах окна авторизации SerpiumNet цвета теперь указаны полным WPF-именем:

```csharp
System.Windows.Media.Brushes.Goldenrod
System.Windows.Media.Brushes.LightGreen
System.Windows.Media.Brushes.OrangeRed
```

## Затронутый файл

- `Relay/SerpiumNetAuthWindow.xaml.cs`

## Не изменено

- логика авторизации Tailscale;
- внешний SerpiumNet Engine;
- Relay → Engine bridge;
- XAML окна;
- текущие настройки и ключи.

## Проверка

После применения выполнить:

```powershell
dotnet build .\SerpiumVPN.csproj
```

Ожидается `0` ошибок. Старое предупреждение `CS4014` в `Relay/SerpiumNetManager.cs` допустимо.

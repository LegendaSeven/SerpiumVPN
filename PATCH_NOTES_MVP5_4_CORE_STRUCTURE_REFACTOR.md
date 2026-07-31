# SerpiumVPN MVP5.4 — Core Structure Refactor

## Цель

Устранить ошибочную вложенность `Core/Core` и подготовить `Core` к дальнейшему расширению Engine Infrastructure.

## Новая структура

- `Core/Models`
  - `ComponentInfo.cs`
  - `ComponentState.cs`
  - `ComponentType.cs`
  - `ComponentLoadResult.cs`
- `Core/Loaders`
  - `ComponentLoader.cs`
- `Core/Registry`
  - `ComponentRegistry.cs`
- `Core/Interfaces` остаётся без изменений.

## Поведение

Логика и namespace классов не изменяются. Это безопасный структурный рефакторинг без подключения Core к запуску приложения.

## Удаляется

- старая папка `Core/Core`
- старые файлы моделей из корня `Core`

## Критерий готовности

- проект собирается без новых ошибок;
- папки `Core/Core` больше нет;
- типы компонентов существуют только в одном экземпляре.

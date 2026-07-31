SERPIUMNET / TSNET MVP1
=======================

Это отдельный безопасный этап. Он добавляет и собирает SerpiumNet.exe,
но пока НЕ заменяет рабочий TailscaleManager в WPF.

1. Первая авторизация
--------------------
Из корня проекта:

  .\bin_files\relay\SerpiumNet.exe login -hostname serpium-gateway

При первом запуске появится строка [login] со ссылкой Tailscale.
Открой её в браузере и подтверди устройство. Состояние сохранится рядом:

  bin_files\relay\state\

После LOGIN_OK окно можно закрыть.

2. Проверка статуса
------------------

  .\bin_files\relay\SerpiumNet.exe status -hostname serpium-gateway

Ожидается BACKEND_STATE=Running и TAILSCALE_IP=100.x.x.x.

3. Тест gateway bridge
----------------------
Gateway слушает порт 28443 только внутри tailnet и передаёт соединение
на локальный Xray gateway (по умолчанию 127.0.0.1:28444):

  .\bin_files\relay\SerpiumNet.exe gateway -hostname serpium-gateway -target 127.0.0.1:28444

4. Тест client bridge
---------------------
На клиентском ПК авторизуй отдельный state/hostname, затем запусти:

  .\bin_files\relay\SerpiumNet.exe client -hostname serpium-client -gateway serpium-gateway:28443 -listen 127.0.0.1:28445

Локальный Xray client на следующем этапе будет подключаться к 127.0.0.1:28445.

5. Auth key без передачи в командной строке
-------------------------------------------

  $env:TS_AUTHKEY = 'tskey-auth-...'
  .\bin_files\relay\SerpiumNet.exe login -hostname serpium-gateway
  Remove-Item Env:TS_AUTHKEY

Ключ в проект не записывается.

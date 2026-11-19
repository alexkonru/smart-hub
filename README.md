# SmartHub

Локальный хаб для умного дома на Rust: обнаруживает устройства Tuya и eWeLink в локальной сети, управляет ими напрямую или через облако, показывает веб-интерфейс, ведёт телеметрию, поддерживает автоматизации, камеры и удалённый доступ через собственный VPS-релей.

Проект состоит из трёх независимых компонентов:

| Компонент | Каталог | Назначение |
|---|---|---|
| SmartHub Hub | `src/` | Основной сервер: веб-интерфейс, API, обнаружение и управление устройствами, SQLite, автоматизации, камеры |
| SmartHub VPS Relay | `vps-relay/` | Ретранслятор для удалённого доступа, UDP-rendezvous, P2P и прокси к облачным API |
| SmartHub Mobile | `mobile-client/src-tauri/` | Android-приложение на Tauri 2, использующее общий веб-интерфейс из `static/index.html` |

Готовый подписанный APK после сборки лежит в `dist/SmartHub-0.1.0-universal-release.apk`.

---

## Возможности

- Автообнаружение устройств Tuya:
  - UDP broadcast на портах `6666`, `6667`, `7000`;
  - протоколы Tuya `3.3` (AES-ECB + CRC32), `3.4` и `3.5` (AES-GCM/HMAC);
  - локальное управление по TCP без облака.
- eWeLink / Sonoff:
  - обнаружение через mDNS;
  - облачная синхронизация аккаунта;
  - локальное управление по HTTP с AES-шифрованием.
- Tuya OpenAPI:
  - синхронизация списка устройств, DP-карт и локальных ключей по `access_id` / `access_secret`;
  - поддержка регионов EU, WE, CN, US.
- Камеры:
  - ONVIF / RTSP, iCSee / XMEye, V380, Tapo / Dahua и произвольный URL;
  - снимки через HTTP или `ffmpeg`;
  - детекция движения по яркостной сетке кадра;
  - маскирование паролей в журналах.
- Веб-интерфейс:
  - сетка устройств и групп;
  - графики телеметрии;
  - тёмная/светлая тема, мобильная вёрстка;
  - профили (например, «Дом» и «Дача») с отдельными наборами устройств и настроек.
- Автоматизации:
  - правила по порогу датчика (температура, влажность, мощность, движение);
  - правила по расписанию;
  - защита от повторных срабатываний и учёт текущего состояния устройства.
- Телеметрия:
  - SQLite, история метрик, автоматическая очистка записей старше 30 дней.
- Удалённый доступ:
  - релей на VPS по TCP/UDP `4000`;
  - STUN и определение внешнего адреса;
  - P2P через UDP hole punching;
  - fallback через HTTP-релей;
  - пароль доступа к API и панели.
- Мобильный клиент:
  - автоматический выбор маршрута LAN → P2P → VPS;
  - push-уведомления о движении камер;
  - единый интерфейс с веб-версией.

---

## Архитектура

```text
┌──────────────────────┐        LAN / P2P / VPS        ┌──────────────────────┐
│  Браузер / Android   │ ────────────────────────────▶ │      SmartHub        │
│  static/index.html   │                               │  axum + tokio + SQLite│
└──────────────────────┘                               └──────────┬───────────┘
                                                                  │
                         ┌────────────────────────────────────────┼──────────────────────────┐
                         │                    │                   │                          │
                         ▼                    ▼                   ▼                          ▼
                 Tuya LAN UDP/TCP     eWeLink mDNS/HTTP     Tuya OpenAPI / eWeLink    RTSP / HTTP камеры
                 6666/6667/7000         5353 / 8081              облачные API          ffmpeg + снимки
                                                                  │
                                                                  ▼
                                                        ┌──────────────────────┐
                                                        │   SmartHub VPS Relay │
                                                        │   TCP + UDP :4000    │
                                                        └──────────────────────┘
```

### Маршруты мобильного клиента

1. **LAN** — клиент проверяет локальный адрес хаба (`/api/ping`).
2. **P2P** — UDP hole punching через VPS-rendezvous, запросы идут напрямую.
3. **VPS** — HTTP-запросы проходят через релей на VPS.

Маршрут выбирается автоматически и перепроверяется при сетевых ошибках.

---

## Требования

### Бэкенд

- Rust `1.85+` (используется edition 2024).
- Linux рекомендуется: часть функций (Wi-Fi-анализ через `nmcli`/`iw`, ARP-таблица) ориентирована на Linux.
- `ffmpeg` — для RTSP-снимков и детекции движения (опционально, но без него камеры работают только через HTTP-снимки).
- `NetworkManager` (`nmcli`) — опционально, для диагностики Wi-Fi канала.

### VPS-релей

- Rust `1.85+`.
- Открытый порт `4000/tcp` и `4000/udp`.

### Android-приложение

Проверено на:

- Rust `1.100.0`;
- Tauri CLI `2.11.4`;
- Android SDK Platform `34`;
- Android Build Tools `34.0.0`;
- Android NDK `26.1.10909125`;
- JDK `17`;
- Gradle `8.14.3` (скачивается wrapper-ом автоматически).

Нужны установленные Rust-таргеты:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Переменные окружения:

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
export NDK_HOME="$HOME/Android/Sdk/ndk/26.1.10909125"
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk"
```

---

## Быстрый старт: хаб

1. Создайте локальный `.env` в корне проекта:

```bash
cp src/.env.example .env
```

2. Заполните значения. Минимально достаточно:

```dotenv
HUB_PORT=3000
DB_FILE=smart_hub.db
DEFAULT_STUN_SERVER=stun.cloudflare.com:3478
```

3. Запустите сервер:

```bash
cargo run --release
```

4. Откройте `http://127.0.0.1:3000`.

При первом запуске создаётся SQLite-база `smart_hub.db` и профиль `home`. Устройства в локальной сети появляются автоматически после broadcast-обнаружения; кнопка сканирования в интерфейсе запускает дополнительный проход по подсети.

> `.env` читается из текущего рабочего каталога. Запускайте `cargo run` из корня проекта, где лежит `.env`.

### Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `HUB_PORT` | `3000` | TCP-порт веб-интерфейса и API |
| `DB_FILE` | `smart_hub.db` | Путь к SQLite-базе |
| `DEFAULT_VPS_URL` | пусто | Адрес VPS-релея по умолчанию |
| `RELAY_SECRET` | пусто | Общий секрет для заголовка `X-Relay-Secret` |
| `AUTH_SALT` | `smarthub-salt` | Соль для хеширования пароля доступа. Обязательно задайте своё значение |
| `DEFAULT_STUN_SERVER` | `stun.cloudflare.com:3478` | STUN-сервер |
| `HIDDEN_DEVICE_IDS` | пусто | ID скрытых устройств через запятую |
| `EWELINK_APP_ID` | пусто | App ID для eWeLink |
| `EWELINK_APP_SECRET` | пусто | App Secret для eWeLink |

`EWELINK_APP_ID` и `EWELINK_APP_SECRET` нужны только для облачной авторизации eWeLink. Не коммитьте реальные значения.

Пароль панели, VPS-адрес и `RELAY_SECRET` также можно задать из интерфейса: вкладка «Сеть» → «Настройки VPS и пароля доступа». После установки пароля все защищённые маршруты требуют `Authorization: Bearer <пароль-или-токен>`.

---

## Быстрый старт: VPS-релей

```bash
cd vps-relay
RELAY_SECRET='long-random-secret' PORT=4000 cargo run --release
```

Сервер слушает одновременно TCP и UDP на одном порту. UDP используется для STUN/rendezvous и P2P, TCP — для HTTP-релея и прокси к облачным API.

На хабе укажите:

- `DEFAULT_VPS_URL=http://<vps-ip>:4000` или HTTPS-адрес reverse-proxy;
- тот же `RELAY_SECRET`.

Откройте на VPS порты `4000/tcp` и `4000/udp`. Для публичного использования ставьте релей за TLS reverse-proxy (Caddy/Nginx) и ограничивайте доступ файрволом.

---

## Сборка Android APK

Все команды выполняются из `mobile-client/src-tauri`.

1. Установите Android-таргеты и переменные окружения (см. раздел «Требования»).
2. Сгенерируйте Android-проект:

```bash
cd mobile-client/src-tauri
cargo tauri android init --ci
```

3. Соберите release APK:

```bash
cargo tauri android build --apk
```

Результат:

```text
mobile-client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk
```

APK получается unsigned. Для установки подпишите его:

```bash
UNSIGNED=mobile-client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk
ALIGNED=/tmp/SmartHub-aligned.apk
OUT=dist/SmartHub-0.1.0-universal-release.apk

mkdir -p dist
"$ANDROID_HOME/build-tools/34.0.0/zipalign" -p -f 4 "$UNSIGNED" "$ALIGNED"
"$ANDROID_HOME/build-tools/34.0.0/apksigner" sign \
  --ks "$HOME/.android/smarthub-release.jks" \
  --ks-key-alias smarthub \
  --out "$OUT" "$ALIGNED"
"$ANDROID_HOME/build-tools/34.0.0/apksigner" verify --verbose "$OUT"
```

Если keystore ещё нет:

```bash
keytool -genkeypair \
  -keystore "$HOME/.android/smarthub-release.jks" \
  -alias smarthub \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=SmartHub Mobile, OU=Mobile, O=SmartHub, C=RU"
```

Храните keystore и пароль **вне репозитория** и сделайте резервную копию: без него нельзя выпускать обновления поверх установленного APK. Каталоги `gen/android/`, `dist/`, `*.apk`, `*.jks`, `*.keystore` уже исключены из Git.

### Встроенный адрес VPS

Мобильный клиент умеет брать `DEFAULT_VPS_URL` на этапе компиляции:

```bash
DEFAULT_VPS_URL="https://smart-hub.example.com" cargo tauri android build --apk
```

Без этого адрес задаётся вручную в приложении. Не встраивайте в APK приватные ключи и пароли.

### Другие платформы

- Отдельная desktop-сборка Tauri: `cargo tauri build` из `mobile-client/src-tauri` (нужны системные зависимости WebKitGTK и др.).
- iOS-проект в репозитории не настроен и не проверялся.

---

## API

Все ответы — JSON. Если пароль не задан, защищённые маршруты открыты; если задан — требуется Bearer-токен.

| Метод | Маршрут | Назначение |
|---|---|---|
| `GET` | `/` | Веб-интерфейс |
| `GET` | `/api/ping` | Проверка хаба, профиль, статус сети |
| `POST` | `/api/auth/login` | Получение токена по паролю |
| `GET` | `/api/remote/config` | Настройки удалённого доступа |
| `POST` | `/api/remote/config` | Сохранение VPS, секрета, пароля, STUN |
| `GET` | `/api/devices` | Список устройств |
| `GET` | `/api/devices/:id/history` | История телеметрии |
| `POST` | `/api/scan/lan` | Запуск сканирования LAN |
| `POST` | `/api/sync/openapi` | Синхронизация Tuya OpenAPI |
| `POST` | `/api/sync/ewelink` | Синхронизация eWeLink |
| `DELETE` | `/api/devices/:id` | Удаление/скрытие устройства |
| `POST` | `/api/devices/:id/key` | Установка локального ключа |
| `GET` | `/api/devices/:id/status` | Опрос состояния |
| `POST` | `/api/devices/:id/control` | Отправка команды |
| `POST` | `/api/cameras/add` | Добавление камеры |
| `POST` | `/api/cameras/:id/config` | Настройка камеры |
| `GET/POST` | `/api/cameras/:id/snapshot` | Снимок и детекция движения |
| `GET/POST` | `/api/profiles` | Список и создание профилей |
| `POST` | `/api/profiles/switch` | Переключение профиля |
| `PUT/DELETE` | `/api/profiles/:id` | Переименование и удаление профиля |
| `GET/POST` | `/api/automations` | Список и сохранение правил |
| `POST` | `/api/automations/:id/toggle` | Включение/выключение правила |
| `DELETE` | `/api/automations/:id` | Удаление правила |
| `POST` | `/api/db/reset` | Очистка телеметрии / профиля / БД |

Публичные маршруты без авторизации: `/`, `/api/ping`, `/api/auth/login`, `/static/*`.

---

## Структура проекта

```text
.
├── Cargo.toml                  # бэкенд SmartHub
├── src/
│   ├── main.rs                 # HTTP-сервер, маршруты, профили, синхронизация
│   ├── state.rs                # состояние устройств и профилей
│   ├── discovery.rs            # UDP/mDNS/ONVIF/ARP-обнаружение
│   ├── tuya.rs                 # локальный протокол Tuya 3.3/3.4/3.5
│   ├── ewelink.rs              # eWeLink: логин, облако, локальный HTTP
│   ├── cloud_sync.rs           # Tuya OpenAPI
│   ├── cameras.rs              # RTSP/HTTP-снимки и детекция движения
│   ├── automation.rs           # движок правил
│   ├── remote.rs               # STUN, P2P, VPS, авторизация
│   ├── db.rs                   # SQLite: настройки, телеметрия, правила
│   └── .env.example            # шаблон конфигурации
├── static/index.html           # единый веб-интерфейс (браузер и APK)
├── vps-relay/                  # VPS-релей
└── mobile-client/src-tauri/    # Tauri 2 Android-клиент
```

Локальные данные, создаваемые при работе:

- `smart_hub.db` — настройки, профили, телеметрия, автоматизации;
- `devices_cache_<profile>.json` — кэш устройств и облачных сессий;
- `.env` — конфигурация и секреты.

Все они исключены из Git. Не добавляйте их принудительно (`git add -f`).

---

## Безопасность

- Пароль панели хранится как SHA-256 от `AUTH_SALT + ":" + пароль`. Задайте уникальный `AUTH_SALT`.
- `RELAY_SECRET` передаётся в заголовке `X-Relay-Secret`; при пустом значении проверка отключена. Используйте длинный случайный секрет.
- По умолчанию хаб не использует TLS. Не публикуйте порт `3000` напрямую в интернет: используйте VPN, SSH-туннель или reverse-proxy с HTTPS.
- CORS настроен как `Access-Control-Allow-Origin: *` для работы клиентов в локальной сети. Ограничьте доступ на уровне сети.
- Локальные ключи Tuya, `access_secret` и пароли камер лежат в SQLite/кэше в открытом виде (так требует протокол). Защитите файлы ОС и каталог проекта.
- В журналах пароли RTSP/HTTP маскируются, но сторонние библиотеки и `ffmpeg` могут писать свои сообщения.
- Проверяйте APK и keystore: приватный ключ подписи не должен попадать в Git.

---

## Диагностика

| Проблема | Что проверить |
|---|---|
| Устройства не находятся | Хаб и устройства в одной подсети; UDP `6666/6667/7000` не блокируются; для eWeLink — mDNS `5353` |
| Устройство онлайн, но не управляется | Правильный `local_key`; Tuya `3.3/3.4/3.5`; устройство не занято облаком |
| Камера не отдаёт кадр | Включены RTSP/ONVIF в приложении камеры; пароль `admin`; установлен `ffmpeg`; порт `554` доступен |
| Нет движения с камеры | `ffmpeg` установлен; чувствительность в настройках камеры; первый кадр используется как эталон |
| Удалённый доступ не работает | На VPS открыты `4000/tcp` и `4000/udp`; совпадает `RELAY_SECRET`; VPS-адрес указан с `http://` или `https://` |
| P2P не поднимается | Симметричный NAT/CGNAT: используется fallback через VPS — это нормально |
| Android-сборка падает | Заданы `ANDROID_HOME`, `NDK_HOME`, `JAVA_HOME`; приняты лицензии SDK (`sdkmanager --licenses`); установлен NDK `26.1.10909125` |
| APK не устанавливается | APK подписан (`apksigner verify`); версия Android ≥ минимальной из манифеста; удалена предыдущая сборка с другим ключом |

Проверка подписи:

```bash
"$ANDROID_HOME/build-tools/34.0.0/apksigner" verify --verbose --print-certs \
  dist/SmartHub-0.1.0-universal-release.apk
```

Проверка сборки бэкенда:

```bash
cargo check
cargo build --release
```

---

## Ограничения

- Локальное управление Tuya/eWeLink рассчитано на устройства, доступные в той же сети.
- Некоторые устройства требуют облачной привязки; локальный ключ может меняться после перепривязки.
- Детекция движения — эвристика по яркости, без ML-моделей; возможны ложные срабатывания при изменении освещения.
- Android-клиент не содержит собственного локального сервера: он обращается к уже запущенному хабу.
- Релей не выполняет роль полноценного VPN и не шифрует трафик сам по себе.

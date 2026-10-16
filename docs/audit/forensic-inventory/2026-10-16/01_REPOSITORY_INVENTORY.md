# 01. Инвентарь репозитория (фазы 0 и 1)

## 0. Идентичность и базовая линия

| Параметр | Значение | Как установлено |
|---|---|---|
| Проверяемый корень | `/home/claude/nexus-review` (локальная копия в среде аудита) | `ls`, сравнение с архивом |
| Git | Отсутствует: `fatal: not a git repository` | `git status` |
| GitHub `ptrvalina/nexus-sign` | Недоступен: у сессии нет привязанного аккаунта GitHub | `add_repo` → «link your GitHub account» |
| Ветка, коммит, автор последнего коммита | Не установить (нет `.git`) | — |
| Совпадение с последним архивом для владельца | Совпадает с `nexus-sign-2.0.0-rc.2-phones-wifi.zip` (346 файлов) по составу; отличается один файл: `auth-core/scripts/run-local.sh` (ожидание PostgreSQL 180 с вместо 60 с, локальная правка 12.10, в архив и на GitHub не попала) | `diff -rq` |
| Версия | `2.0.0-rc.2` в `VERSION`, `auth-core/package.json`, `auth-core/openapi.yaml`, `sandbox/openapi.yaml`, `NEXUSSignVersion.swift`, `NEXUSSignVersion.kt`; `android-sdk/build.gradle.kts` читает `VERSION` | `grep`, `check-repository.sh` → ok |
| Версии демо-приложений | `versionName 1.0` (Android), `MARKETING_VERSION 1.0` (iOS) — отдельная нумерация | `grep` |
| Незакоммиченные / неотслеживаемые изменения | Не установить без git | — |
| Вложенные репозитории, сабмодули | Нет | `find` |
| Посторонние копии рядом (вне репозитория) | `/home/claude/rel/nexus-sign` (1.3.0), `/home/claude/sandbox`, `sandbox-review`, `pkg` — старые копии. Аудит их не использовал | `cat VERSION` |
| `node_modules` | Символическая ссылка на набор, собранный ранее из исходников с GitHub (не из npm). `@types/*` — заглушки версий `*.9999` | `npm ls` |

### Пакетные менеджеры и lockfile

| Область | Менеджер | Lockfile | Замечание |
|---|---|---|---|
| auth-core | npm | **нет** `package-lock.json` | CI (`ci.yml`, шаг «Lockfile is committed»), `Dockerfile:10` и `release.yml` его требуют. CHANGELOG.md:80 прямо говорит, что lockfile не входит в кандидат. Владелец сообщал о зелёном CI и успешном `npm ci` у себя, значит на GitHub lockfile, по всей видимости, есть — CONFLICTING_EVIDENCE (FI-009) |
| android-sdk, demo/android | Gradle 8 (wrapper в `android-sdk`), AGP 8.5.2, Kotlin 1.9.24 | Нет `verification-metadata.xml` | NXS-039 |
| ios-sdk | Swift Package Manager | Нет зависимостей | — |
| sandbox | Только стандартная библиотека Python | — | — |

### Среды выполнения и инструменты

| Инструмент | Требуется | Доступен в аудите |
|---|---|---|
| Node.js | ≥ 22 | 22.22.2 |
| TypeScript | 5.x | 5.9.3 |
| PostgreSQL | 16 | 16.13 (локальный кластер) |
| Redis | 7 | 7.0.15 |
| SoftHSM2 | Для HSM-тестов | Нет (архив Ubuntu недоступен) |
| Docker | Для образов | Демон не запущен |
| Swift / Xcode | iOS | Нет |
| Android SDK | Android | Нет; Kotlin-компилятор есть, сборка на заглушках API |
| Python | ≥ 3.10 | 3.11.15 |

### CI и поставка

| Файл | Задачи |
|---|---|
| `.github/workflows/ci.yml` | auth-core (Node 22 и 24), integration (PostgreSQL, Redis, SoftHSM), e2e, container-images, ios-sdk, ios-demo, android-sdk, android-demo, sandbox — 10 задач |
| `.github/workflows/security.yml` | CodeQL с порогом `gate.mjs`, SBOM CycloneDX, Trivy (зависимости и образ), npm audit, gitleaks — 4 задачи |
| `.github/workflows/release.yml` | Образ Auth Core, SBOM, build provenance (OIDC) |
| `.github/dependabot.yml` | Обновления зависимостей |

Все actions закреплены по SHA. Задачи `ios-demo` и `android-demo` добавлены после последнего зелёного прогона, о котором сообщал владелец: тогда было 12 проверок, а сейчас определено 14. Результат этих двух задач неизвестен.

### Контейнеры и конфигурация

| Файл | Назначение | Замечание |
|---|---|---|
| `auth-core/Dockerfile` | Двухстадийная сборка, пользователь `nexus`, без npm в рантайме, HEALTHCHECK | База по тегу `node:22-alpine` (NXS-040, FI-020) |
| `auth-core/docker-compose.yml` | PostgreSQL и Redis для локального запуска | Только разработка |
| `sandbox/Dockerfile`, `sandbox/deploy/*` | Хостинг песочницы | База `python:3.12-slim` по тегу |
| `auth-core/.env.example`, `sandbox/deploy/.env.example` | Шаблоны | Секретов нет (проверено) |

### Точки входа

| Тип | Точка входа |
|---|---|
| Документация | `README.md`, `docs/README.md`, `auth-core/README.md`, `ios-sdk/README.md`, `android-sdk/README.md`, `demo/README.md`, `sandbox/README.md` |
| Тесты | `npm run check:all`, `npm run test:integration`, `npm run smoke-test`, `swift test`, `gradlew testDebugUnitTest`, `python -m unittest discover -s tests` |
| Сервис | `auth-core/src/server.ts` |
| CLI | `registerClient`, `createAdminUser`, `setClientCertificates`, `sealCredentialBaseline` |

## 1. Инвентарь файлов и компонентов

Полный перечень с классификацией (компонент, язык, строки, назначение, сгенерирован или нет, чувствительность, SHA-256): `01a_FILE_INVENTORY.csv`, 346 строк.

| Компонент | Код | Тесты | Прочее | Строк кода |
|---|---|---|---|---|
| auth-core/src | 73 TS + `schema.sql` | — | — | 9 273 + 588 |
| auth-core/test | — | 39 (15 модульных наборов, 10 интеграционных, 5 вспомогательных, 9 фикстур аттестации Android) | — | 3 759 |
| auth-core/test-vectors | — | 12 (4 файла векторов, генераторы, проверки) | — | 1 267 |
| auth-core/migrations | 17 SQL (002–018) | — | README | 935 |
| auth-core/scripts | 8 (верификатор доказательств, e2e, run-local, проверки) | — | — | 1 041 |
| auth-core/public/admin | 2 (HTML, JS) | — | — | 505 |
| ios-sdk | 16 Swift | 9 (5 наборов и 4 копии векторов) | Package.swift, README | 4 623 |
| android-sdk | 17 Kotlin и ресурсы | 8 | Gradle, wrapper | 4 490 |
| sandbox | 5 Python (сервер), 2 (tools), 3 (web) | 4 | Dockerfile, OpenAPI | 3 575 |
| demo | bank-backend 2, ios 4, android 5 | — | проекты сборки | 946 |
| docs | — | — | 53 Markdown (до аудита) | — |
| .github | 3 workflow, gate.mjs | — | шаблоны | 587 |

### Дубли, мёртвый код, неиспользуемое

| Проверка | Результат |
|---|---|
| Неиспользуемые зависимости Auth Core | Нет: каждая из 10 runtime-зависимостей импортируется в `src` |
| Неиспользуемые таблицы | Нет: все 15 таблиц `schema.sql` используются в `src` |
| Маршруты и OpenAPI | Совпадают (39 маршрутов, `check-openapi-routes.mjs`) |
| TODO/FIXME/HACK | Нет в `src`, SDK и demo |
| Устаревший брендинг (VoxTel и др.) | Не найден |
| Дублирующие реализации | Намеренные: протокол реализован в TypeScript (Auth Core), Swift, Kotlin и Python (песочница) с общими векторами. В песочнице собственная реализация P-256 на чистом Python (`sandbox/server/p256.py`) — только для песочницы, не для продуктива |
| Копии векторов | 4 файла векторов, по одной копии в `ios-sdk/Tests/NEXUSSignTests/Resources`; совпадение проверяет `check-vector-copies.mjs` (ok) |
| Устаревшие комментарии | `mtlsGateway.ts:9-13` (про токены устройств), двойной docstring в `env.ts:166-175` (FI-023) |
| Лицензия и сторонние уведомления | `LICENSE` — проприетарная. Файла уведомлений о сторонних лицензиях нет (FI-028) |
| Владельцы | `CODEOWNERS` есть |

### Предлагаемая очистка (ничего не удалено)

| Что | Почему | Влияние |
|---|---|---|
| Исправить комментарии `mtlsGateway.ts:9-13`, `env.ts:166-175` | Не соответствуют поведению | Нет |
| Добавить `auth-core/package-lock.json` | Требуется CI и Dockerfile | Сборка становится воспроизводимой |
| Перенести правку `run-local.sh` (180 с) в репозиторий | Сейчас только локально | Нет |
| Удалить посторонние копии `/home/claude/rel`, `sandbox`, `sandbox-review`, `pkg` в рабочей среде | Не часть репозитория, риск перепутать | Нет для репозитория |
| Добавить `THIRD_PARTY_NOTICES` | Лицензионная чистота поставки | Нет |

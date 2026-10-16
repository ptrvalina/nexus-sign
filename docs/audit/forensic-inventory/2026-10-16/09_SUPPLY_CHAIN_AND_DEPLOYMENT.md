# 09. Цепочка поставки и развёртывание (фаза 8)

Значения секретов в отчёте не приводятся.

## Зависимости и воспроизводимость

| Пункт | Состояние | Свидетельство | Находка |
|---|---|---|---|
| Lockfile npm | Отсутствует в проверяемой копии | `find`; CHANGELOG.md:80 | FI-009 |
| Закрепление версий | В `package.json` диапазоны `^`. Без lockfile установка не детерминирована | `auth-core/package.json` | FI-009 |
| Скрипты установки | CI ставит с `--ignore-scripts`, затем собирает `pkcs11js` (`npm rebuild`) | `ci.yml` | — |
| Уязвимые зависимости | Не проверено в этом аудите: реестр npm заблокирован (403) | Журнал прокси | FI-029 |
| Набор зависимостей в аудите | Собран ранее из исходников GitHub по тегам; `@types/*` — заглушки | `manifest.json` набора, `npm ls` | — |
| Gradle | Wrapper проверяется в CI (`gradle/actions/setup-gradle`); `verification-metadata.xml` нет | `ci.yml` | FI-021 |
| Swift Package | Внешних зависимостей нет | `Package.swift` | — |
| GitHub Actions | Все закреплены по SHA | `ci.yml`, `security.yml`, `release.yml` | — |
| Dependabot | Настроен | `.github/dependabot.yml` | — |

## Сканирование и происхождение

| Пункт | Реализация | Исполнено здесь |
|---|---|---|
| Сканирование секретов | gitleaks по всей истории, allowlist в `.gitleaks.toml`; `check-repository.sh` | `check-repository.sh`: ok. Поиск закрытых ключей и токенов grep-шаблонами: только плейсхолдер `-----BEGIN PRIVATE KEY-----` в `test/production-posture.test.mjs:73` |
| SBOM | CycloneDX (`@cyclonedx/cyclonedx-npm@6.0.1`) в `security.yml` и `release.yml` | Нет |
| SAST | CodeQL с порогом: `gate.mjs` падает на находке ≥ 7.0, не внесённой в `reviewed-findings.tsv` | Нет |
| Сканирование образа | Trivy (файловая система и образ) | Нет |
| Происхождение | `actions/attest-build-provenance` (подпись через OIDC) | Нет |

## Контейнеры

| Пункт | Auth Core | Песочница |
|---|---|---|
| База | `node:22-alpine` по тегу (FI-020) | `python:3.12-slim` по тегу |
| Не-root | `USER nexus` | `USER sandbox` |
| Пакетные менеджеры в рантайме | Удалены npm, npx, corepack, yarn | — |
| Компиляторы в рантайме | Нет (только на стадии сборки) | — |
| Health check | `wget /healthz` | Health в CI |
| Привилегии | Особых capabilities не требуется; ограничения задаются при развёртывании | — |
| Сборка в этом аудите | Не выполнена (нет Docker) | Не выполнена |

## Конфигурация и секреты

| Переменная или группа | Тип | Риск |
|---|---|---|
| `DEVICE_SECRET_ENCRYPTION_KEY`, `WEBHOOK_SECRET_ENCRYPTION_KEY`, `ADMIN_SECRET_ENCRYPTION_KEY` | Мастер-ключи AES-256 в окружении | Не в HSM, без ротации (FI-005) |
| `PKCS11_PIN` | Учётные данные HSM | Должен приходить из менеджера секретов банка |
| `APNS_PRIVATE_KEY_PEM`, `FCM_SERVICE_ACCOUNT_JSON`, `GOOGLE_SERVICE_ACCOUNT_JSON` | Учётные данные внешних сервисов | Ротация — процедура банка |
| `DATABASE_URL`, `REDIS_URL` | Строки подключения с паролями | В продуктиве обязательны TLS (`DATABASE_SSL`, `rediss://`) |

Проверка окружения: zod при старте; `productionBlockers` отказывает в запуске в продуктиве при 20+ условиях, проверено тестами (`production-posture` — 12, `production-startup` — 3). Опасные для разработки настройки вне продуктива требуют явного `ALLOW_INSECURE_DEVELOPMENT=true`.

Различение конфигураций:

- `.env.example` — шаблоны.
- `.env.local-run` (создаётся `run-local.sh`) и `~/nexus-local-credentials.txt` — локальная разработка, вне репозитория (`.gitignore`).
- `docker-compose.yml` с паролем `nexus` — только разработка.
- Продуктивной конфигурации в репозитории нет, и это правильно.

## Сеть и TLS

- Auth Core не завершает TLS сам. Ожидается шлюз банка с mTLS, `TRUSTED_PROXY_IPS` и заголовками отпечатка сертификата (`mtlsGateway.ts`).
- Вебхуки: только HTTPS, список разрешённых хостов, запрет приватных адресов, адрес закреплён против DNS rebinding (`webhookUrlPolicy.ts`).
- Демо-стенд: по инструкции порт устройства открыт в Wi-Fi через `netsh portproxy` и правило брандмауэра. Это делает FI-016 практическим риском на время демо. После демо оба нужно удалить (`demo/README.md:44`).

## Миграции и откат

- Новая установка: `schema.sql` (идемпотентна; CI применяет дважды), затем `roles.sql`.
- Обновление: миграции 002–018 по порядку, от имени `nexus_owner`.
- Скриптов отката нет; откат возможен только восстановлением из резервной копии, и эта процедура не проверена (FI-027, FI-026).

## Права CI

- `permissions: contents: read` по умолчанию; `release.yml` дополнительно запрашивает `id-token` и `attestations: write` для provenance.
- Секретов в workflow нет: CI генерирует одноразовые ключи на каждый прогон.

## Подпись релизов и мобильная подпись

| Пункт | Состояние |
|---|---|
| Образ Auth Core | Provenance через OIDC; подписи образа (cosign) нет |
| SDK iOS / Android | Публикации и подписи артефактов нет (FI-022) |
| Демо iOS | Подпись Personal Team владельца, профиль на 7 дней; App Attest недоступен |
| Демо Android | Отладочная подпись (debug APK) |

## Готовность к развёртыванию

- Документация по развёртыванию, мониторингу, DR и 9 runbook есть — DOCUMENTED_ONLY.
- Ни одного развёртывания вне локальной машины не зафиксировано.
- Для технического пилота нужны:
  - образ, собранный CI по зафиксированному коммиту;
  - staging с mTLS-шлюзом, HSM (хотя бы SoftHSM) и TLS к PostgreSQL и Redis;
  - учения по восстановлению.

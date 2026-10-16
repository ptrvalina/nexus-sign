# 10. Документация против реализации (фаза 9)

В целом документация точна и сдержанна. Ограничения названы прямо: открытые пункты NXS-019, 021, 025, 028, 039 и 040, список того, что проверяется вне среды сборки (`docs/operations/release.md`), требования к продуктиву (`README.md:120`). Ниже — расхождения и места, требующие правки. Исторические записи CHANGELOG менять не нужно.

## Утверждения и их подтверждение

| Утверждение | Где | Подтверждение | Оценка |
|---|---|---|---|
| «Approval that a third party can verify… An auditor checks all of it offline with a small script that contains no NEXUS-SIGN server code» | `README.md:43` | `verify-evidence.mjs` импортирует только `scripts/lib/evidence.mjs`, а тот — только `node:crypto`. Подделки обнаруживаются (исполнено) | Подтверждено. Добавить, что обрезку хвоста видно только с головой цепочки, сохранённой банком |
| «The phone refuses to sign what it did not show… builds the confirmation screen and biometric prompt from those bytes only» | `README.md:44` | Код обоих SDK; Android-разбор исполнен на JVM | Частично: верно по происхождению текста, но видимость IBAN в системном окне не гарантирована при длинных полях (FI-003) |
| «Step-up checks that cannot be downgraded or skipped. Audio and video verification…» | `README.md:45`, схема `README.md:18` | Конечный автомат проверен (e2e) | Вводит в заблуждение без оговорки: аудио и видео как канала в продукте нет, результат — утверждение банка (FI-001, FI-032). Нужна одна фраза со ссылкой на NXS-019 |
| «Adaptive verification (Push -> Audio -> Video) bound to the signature» | `auth-core/README.md:13` | То же | Та же правка |
| «No tokens and no cloud after enrolment» | `README.md:46` | Подписанные запросы, BOOTSTRAP только для регистрации (e2e) | Подтверждено. Квитанции push аутентифицируются HMAC, а не подписью — описано в secure-push.md |
| «Push that nobody in between can read… Apple, Google and the database never see its text» | `README.md:48` | AES-GCM с ключом устройства; ключ на сервере зашифрован мастер-ключом | Верно для БД без мастер-ключа. Добавить, что Auth Core с мастер-ключом может расшифровать (FI-005) |
| «Entirely inside the bank… the only outside services are Apple and Google attestation… APNs and FCM» | `README.md:49` | Внешние вызовы в коде: App Attest root (вне продуктива), Play Integrity, APNs, FCM | Подтверждено |
| «Private keys are hardware-backed and non-exportable (Secure Enclave, StrongBox, TEE)» | `README.md:99` | Код; не исполнено на устройствах | Не подтверждено на устройствах. Материал офлайн-ключа попадает в память приложения: на Android при регистрации, на iOS при каждом офлайн-подтверждении (FI-031) — уточнить |
| «Production startup is fail-closed…» | `README.md:103`, `auth-core/README.md:20` | 24 условия в `productionPosture.ts`, тесты 12 + 3 | Подтверждено |
| «The stable 9-digit NEXUS ID is independent of MSISDN, SIM…» | `README.md:98` | Случайное 9-значное, телефон не хранится | Подтверждено |
| «Integration suites… SoftHSM 2.7 — 68 passed» (07.10) | `docs/operations/release.md` | В этом аудите 58 + 10 пропущено (нет SoftHSM) | Не перепроверено. Соответствует по числу (58 + 10 = 68) |
| «The lockfile is not part of this candidate» | `CHANGELOG.md:80`, `release.md` | Lockfile отсутствует в копии | Подтверждено. Если на GitHub lockfile уже есть, документ устарел |
| «The iOS and Android changes were not compiled or tested in the environment that produced this candidate» | `CHANGELOG.md` (rc.1/rc.2) | Верно и сейчас для iOS | Подтверждено |
| Команды проверки в README | `README.md:90-93` | `sandbox/scripts/test.sh` существует; `./gradlew` есть в `android-sdk` | Корректны |
| Демо: «HTTPS on the home Wi-Fi… nothing is exposed to the internet» | `demo/README.md:35` | Верно для интернета; в локальной сети порт открыт без аутентификации (FI-016) | Добавить предупреждение |

## Расхождения в коде и комментариях

| Место | Расхождение | Правка |
|---|---|---|
| `auth-core/src/middleware/mtlsGateway.ts:9-13` | «authenticated by their own short-lived, customer-scoped tokens» — с rc.2 устройства подписывают запросы | «authenticated by device request signatures (or, for enrolment, a single-use BOOTSTRAP token)» |
| `auth-core/src/config/env.ts:166-175` | Два подряд комментария к `ANDROID_KEY_SECURITY_POLICY` | Оставить второй |
| `docs/operations/release.md` | Не упоминает демо, `run-local.sh` и задачи CI `ios-demo` и `android-demo` | Добавить в раздел CI |
| `auth-core/scripts/run-local.sh` | Ожидание 60 с в архиве и на GitHub, 180 с только локально | Внести правку в репозиторий |

## Отсутствующие документы

| Документ | Зачем |
|---|---|
| Матрица поддерживаемых устройств и результатов испытаний | G5 |
| Протокол испытаний на HSM банка и ключевой церемонии | G6 |
| Юридическая оценка доказательной силы подписи и офлайн-кода | G10 |
| Отчёт об учениях по восстановлению | G9 |
| `THIRD_PARTY_NOTICES` | Лицензии |

## Чего нет в документации и коде одновременно

- Утверждений о сертификациях (PCI, ISO, eIDAS, PSD2 SCA) в репозитории нет. Юридическая сила не заявлена.
- Утверждений о формальной верификации нет.
- Неподтверждённых утверждений о «100% безопасности» нет.

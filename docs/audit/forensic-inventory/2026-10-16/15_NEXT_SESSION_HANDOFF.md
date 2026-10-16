# 15. Передача следующей инженерной сессии

## Состояние аудита

Все фазы 0–12 выполнены в пределах доступной среды; отчёты 00–15 в этом каталоге. Не выполнено из-за среды:

- iOS: сборка и тесты;
- Android: настоящая сборка через AGP;
- тесты SoftHSM и HSM;
- Docker-образы;
- npm audit, Trivy, CodeQL, gitleaks;
- испытания на физических устройствах.

Аудит шёл по локальной копии без `.git`. Первое действие следующей сессии — получить доступ к GitHub-репозиторию и повторить проверки на конкретном SHA.

## Точные команды для повтора

Из корня клона:

```bash
cd auth-core
npm ci --ignore-scripts && npm rebuild pkcs11js     # нужен package-lock.json (FI-009)
npm run typecheck && npm run build && npm run check:all
# интеграция: PostgreSQL 16 (суперпользователь), Redis 7, SoftHSM2
INTEGRATION_DATABASE_URL=postgres://postgres:<pw>@localhost:5432/postgres \
INTEGRATION_REDIS_URL=redis://localhost:6379 \
SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so SOFTHSM2_UTIL=/usr/bin/softhsm2-util \
npm run test:integration
# сквозной сценарий: как задача CI auth-core-e2e; при локальной БД schema и roles.sql применять от суперпользователя
node scripts/e2e-smoke.mjs http://localhost:8080
# проверка подделок доказательств: выгрузить /v1/nexus-identities/{id}/evidence, затем
node scripts/verify-evidence.mjs chain.json --public-keys=keys.pem --expect-head=<seq>:<hash>
cd ../sandbox && python -m unittest discover -s tests
cd ../ios-sdk && swift test                                   # macOS
cd ../android-sdk && sh ./gradlew testDebugUnitTest assembleRelease
cd ../demo/android && sh ../../android-sdk/gradlew assembleDebug
xcodebuild -project demo/ios/NEXUSSignDemo.xcodeproj -scheme NEXUSSignDemo -sdk iphoneos -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

Стенды этого аудита лежат в каталоге scratchpad среды и в репозиторий не входят:

- `audit/e2e.sh` — e2e;
- `audit/tamper.sh` — подделки;
- `audit/demo/run.sh` — демо-банк, имитатор телефона и проба истечения срока;
- `kt/run.sh` — Android на JVM-заглушках.

## Что смотреть дальше

| Файл | Зачем |
|---|---|
| `ios-sdk/Sources/NEXUSSign/SignedTransaction.swift` | Исполнить векторы в Swift; проверить FI-003 |
| `ios-sdk/Sources/NEXUSSign/KeyManager.swift:210-250` | Атрибуты ключей на устройстве |
| `android-sdk/src/main/kotlin/com/nexis/nexussign/NEXUSSignSDK.kt:525-560` | Поведение BiometricPrompt, длина описания |
| `auth-core/src/crypto/pkcs11HsmAdapter.ts` | Испытание на SoftHSM и на HSM банка |
| `auth-core/src/services/adaptiveVerificationService.ts:158-216` | Точка внедрения подписанного результата (FI-002) |
| `auth-core/src/crypto/secretBox.ts` | Связка ключей и ротация (FI-005) |
| `auth-core/src/services/authorizationRecord.ts:55-60` | Отображение EXPIRED (FI-013) |
| `demo/bank-backend/demo-bank.mjs:91-107,205` | Код сопряжения (FI-016) |

## Решения, которые должен принять владелец

1. Аудио и видео: строить, интегрировать провайдера, оставить как внешний шлюз банка с подписанным результатом или исключить из заявленного объёма (07).
2. Допустимые сценарии офлайн-кода, учитывая, что HMAC может вычислить сервер (FI-004).
3. Нужен ли TLS-пиннинг по умолчанию (FI-006).
4. Порог для проверки целостности устройства при каждой операции (FI-007).
5. Разрешение на начало исправлений по `12_REMEDIATION_ROADMAP.md`.

## Текущий практический контекст

- Демо на iPhone остановилось 12.10: Xcode не видел телефон. Нужен кабель с передачей данных, «Доверять», режим разработчика, затем Personal Team и уникальный bundle id (`com.aliaksei.nexussign.demo`).
- Android-демо отложено.
- На компьютере владельца открыт порт 8443 в Wi-Fi (portproxy и правило брандмауэра) и установлен профиль локального CA на iPhone. После демо: удалить оба и снова включить режим блокировки (Lockdown Mode). Пока порт открыт, действует FI-016.
- Локальная правка `run-local.sh` (ожидание 180 с) ещё не в репозитории.

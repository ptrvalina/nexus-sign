# 06. Мобильные SDK (фаза 3, часть «Native mobile SDKs»)

Ни один SDK не исполнялся на реальном устройстве. Всё ниже, что помечено «Requires physical-device verification», не доказано.

## iOS SDK (`ios-sdk`, Swift, iOS 15+)

| Аспект | Реализация | Статус | Свидетельство |
|---|---|---|---|
| Сборка и модульные тесты | 5 наборов, 21 тест (`func test…`) | BLOCKED_BY_ENVIRONMENT | Swift недоступен. Задача CI `ios-sdk` есть; результат для проверяемой копии получить нельзя |
| Генерация и хранение ключей | Secure Enclave, `kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; ключ подписи и офлайн-ключ с `.biometryCurrentSet`, ключ аутентификации с `.privateKeyUsage` (`KeyManager.swift:115-250`) | IMPLEMENTED_NOT_VERIFIED | Код; Requires physical-device verification |
| Аппаратная поддержка ключей | Только Secure Enclave, программного запасного варианта нет | IMPLEMENTED_NOT_VERIFIED | Код |
| Биометрия | `LAContext` с `localizedReason` = текст из подписываемых байтов (`NEXUSSignSDK.swift:104`); смена набора биометрии делает ключ недействительным | IMPLEMENTED_NOT_VERIFIED | Код |
| Аттестация | App Attest (`AttestationProvider.swift`); не выявляет jailbreak и отладчик (строка 7) | IMPLEMENTED_NOT_VERIFIED | С бесплатным Apple ID недоступна: статус `UNKNOWN` |
| Безопасное локальное состояние | Keychain, группы доступа настраиваются | IMPLEMENTED_NOT_VERIFIED | Код |
| Аутентификация в сети | Подпись каждого запроса ключом аутентификации | IMPLEMENTED_NOT_VERIFIED | Векторы `device-protocols-v1.json` (в Swift не исполнялись) |
| Проверка TLS | Системная; HTTP только для loopback (`NEXUSSignConfig.swift:51`); пиннинга нет | PARTIALLY_IMPLEMENTED | FI-006 |
| Разбор QR и deep links | QR `NXS1.` + base64url канонических байтов; deep links в SDK нет (это задача хоста) | IMPLEMENTED_NOT_VERIFIED | Код |
| Фон и завершение работы | Двухфазная замена ключей (`SDKState.swift`) | IMPLEMENTED_NOT_VERIFIED | Код |
| Офлайн-режим | ECDH с ключом Secure Enclave; общий секрет попадает в память приложения при каждом подтверждении (FI-031); HMAC-код | IMPLEMENTED_NOT_VERIFIED | Код |
| Миграция устройства | Через восстановление по фразе или замену с переидентификацией | IMPLEMENTED_NOT_VERIFIED | Серверная часть [V] |
| Обработка ошибок | `NEXUSSignError.swift`, 115 строк | IMPLEMENTED_NOT_VERIFIED | Код |
| Локализация и доступность | Тексты окна задаёт хост; локализаций в SDK нет; доступность не оценивалась | PARTIALLY_IMPLEMENTED | Код |
| Безопасный показ параметров | `confirmationText` из разобранных байтов (`SignedTransaction.swift:39-45`) | PARTIALLY_IMPLEMENTED | FI-003 |
| Защита от jailbreak и хуков | Нет | MISSING | FI-007 |
| Демо-приложение | `demo/ios` (SwiftUI, 4 файла); проект написан вручную, ни разу не собран | IMPLEMENTED_NOT_VERIFIED | Xcode у владельца 12.10 остановился на подписи |

## Android SDK (`android-sdk`, Kotlin, minSdk 28, compileSdk 34)

| Аспект | Реализация | Статус | Свидетельство |
|---|---|---|---|
| Сборка и модульные тесты | 7 наборов, 34 теста | PARTIALLY_IMPLEMENTED (проверка) | Скомпилировано против рукописных заглушек API Android на JVM: 30 из 34 прошли; 4 теста `SecurePushTest` упали с `NotImplementedError` в заглушке `kotlinx.serialization` (ограничение стенда, не дефект SDK). Настоящая сборка Gradle/AGP не выполнялась |
| Генерация и хранение ключей | Android Keystore; StrongBox при наличии, иначе TEE (`KeyManager.kt:239-290`); ключ подписи и офлайн-ключ требуют биометрию при каждом использовании через `CryptoObject` | IMPLEMENTED_NOT_VERIFIED | Requires physical-device verification |
| Определение аппаратной поддержки | Отчёт устройства информативен; решение принимает Auth Core по цепочке аттестации ключа | VERIFIED_IMPLEMENTED (серверная часть) | Тесты `android-key-attestation` на реальных цепочках [V] |
| Биометрия | `BiometricPrompt`, `AUTH_BIOMETRIC_STRONG`, `setInvalidatedByBiometricEnrollment(true)` | IMPLEMENTED_NOT_VERIFIED | Код |
| Аттестация | Аттестация ключа и Play Integrity | IMPLEMENTED_NOT_VERIFIED | Нужен проект Google Cloud |
| Проверка TLS | Системная; HTTP только для loopback и, по флагу, `10.0.2.2` (`NEXUSSignConfig.kt:71-72`) | PARTIALLY_IMPLEMENTED | FI-006 |
| Офлайн-режим | Программная ECDH-пара в памяти, производный ключ импортируется в Keystore | IMPLEMENTED_NOT_VERIFIED | FI-031 |
| Двухфазная замена ключей | `KeySlots.kt` | VERIFIED_IMPLEMENTED (JVM) | `KeySlotsTest` 4/4 |
| Строгий разбор подписываемых байтов | `SignedTransaction.kt` | VERIFIED_IMPLEMENTED (JVM) | `SignedTransactionTest` 5/5 на общих векторах |
| Восстановление | `RecoveryPhrase.kt`, `RecoveryProtocol.kt` | VERIFIED_IMPLEMENTED (JVM) | 6/6 и 6/6 на векторах |
| Протокол устройства | `DeviceProtocol.kt` | VERIFIED_IMPLEMENTED (JVM) | 4/4 |
| Secure push | `SecurePush.kt` | BLOCKED_BY_ENVIRONMENT | 2/6 (4 упали на заглушке) |
| Безопасный показ параметров | `confirmationText` (`SignedTransaction.kt:43-48`) | PARTIALLY_IMPLEMENTED | FI-003 |
| Защита от root и наложений | Нет | MISSING | FI-007 |
| Демо-приложение | `demo/android` (2 файла Kotlin), `adb reverse` на порт 8091 | IMPLEMENTED_NOT_VERIFIED | APK ни разу не собран |

## Общий вывод

| Вопрос | Ответ |
|---|---|
| Компилируются ли SDK | Android: да, против заглушек API (не через AGP). iOS: не проверено |
| Работают ли на устройствах | Не проверено ни на одном устройстве |
| Совпадает ли разбор с сервером | Android на JVM: да, по общим векторам. Swift: не исполнялся |
| Что нужно для пилота | Матрица устройств: iPhone с Face ID и Touch ID, Android с StrongBox и только с TEE, разные версии ОС. Сценарии: регистрация, подпись, отказ биометрии, смена биометрии, восстановление, офлайн, push. Проверка видимости IBAN при длинных именах (FI-003) |

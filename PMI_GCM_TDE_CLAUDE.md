# Программная методика испытаний (ПМИ)

## Поддержка режима шифрования AES/GCM в TDE Apache Cassandra

**Объект испытаний:** ветка `tde_gcm_cipher_support` (изменения TDE относительно
`trunk`).

**Документ подготовлен:** Claude, по фактическому составу изменений и тестов
ветки. Дополняет `README_GCM_TDE_CLAUDE.md`.

---

## 1. Общие сведения

### 1.1. Наименование

Методика испытаний функции прозрачного шифрования данных (Transparent Data
Encryption, TDE) в аутентифицированном режиме `AES/GCM/NoPadding` для файлов
commitlog и hints Apache Cassandra.

### 1.2. Назначение объекта испытаний

Ветка переводит шифрование файлов Cassandra на AEAD-режим GCM (обеспечивающий
конфиденциальность и контроль целостности), сохраняя режим `AES/CBC/PKCS5Padding`
только для чтения ранее записанных файлов. Дополнительно вводятся провайдеры
ключей `JKSKeyInlineBase64Provider` и `VaultKeyProvider`.

### 1.3. Область действия

Испытаниям подлежат:

- шифрование/расшифровка блоков (`EncryptionUtils`, `CipherFactory`,
  `EncryptionContext`);
- запись/чтение зашифрованного commitlog (`EncryptedSegment`,
  `CommitLogSegmentReader`);
- запись/чтение зашифрованных hints (`EncryptedHintsWriter`,
  `EncryptedChecksummedDataInput`, `HintsDescriptor`);
- валидация конфигурации TDE;
- провайдеры ключей `JKSKeyInlineBase64Provider`, `VaultKeyProvider`.

Шифрование SSTable в область испытаний не входит (веткой не изменяется).

---

## 2. Цель испытаний

Подтвердить, что:

1. Новые зашифрованные файлы создаются только в режиме GCM с индивидуальным IV
   на каждый блок.
2. GCM обеспечивает контроль целостности: любое искажение ciphertext, IV или
   служебных длин блока приводит к отказу расшифровки (`IOException`), а не к
   выдаче искажённых данных.
3. Ранее записанные CBC-файлы читаются корректно.
4. Конфигурация с CBC при включённом TDE отклоняется при старте узла.
5. Некорректная конфигурация GCM (неверный `iv_length`) отклоняется.
6. Провайдеры ключей `JKSKeyInlineBase64Provider` и `VaultKeyProvider`
   возвращают корректные ключи и предсказуемо обрабатывают ошибки.

---

## 3. Требования, подлежащие проверке

| ID | Требование | Источник в коде |
|----|-----------|------------------|
| Т-01 | Значения TDE по умолчанию: `cipher = AES/GCM/NoPadding`, `iv_length = 12` | `TransparentDataEncryptionOptions` |
| Т-02 | Для GCM обязателен `iv_length = 12`, иначе `ConfigurationException` | `EncryptionContext.validate` |
| Т-03 | Шифрование новых данных с CBC запрещено | `EncryptionContext.validateCipherForNewEncryptedData` |
| Т-04 | Конфигурация с включённым TDE и CBC отклоняется при старте | `DatabaseDescriptor` → `validateForNewEncryptedData` |
| Т-05 | GCM использует индивидуальный IV на каждый блок | `EncryptionUtils`, `EncryptedSegment` |
| Т-06 | Заголовок блока (длины + IV) входит в AAD; его подмена ломает расшифровку | `EncryptionUtils.encryptAndWrite/decrypt` |
| Т-07 | GCM round-trip корректен для одного и нескольких блоков | `EncryptionUtils`, `CipherFactory` |
| Т-08 | Расшифровка устойчива к «коротким» чтениям канала (`readFully`) | `EncryptionUtils.readFully` |
| Т-09 | Недопустимые длины блока/IV отклоняются с `IOException` | `EncryptionUtils.validateEncryptedBlockLengths` |
| Т-10 | Существующие CBC-файлы читаются | `EncryptionContext.getDecryptor` |
| Т-11 | Тег аутентификации GCM = 128 бит | `CipherFactory.GCM_TAG_LENGTH_BITS` |
| Т-12 | commitlog GCM: последовательное чтение и seek | `CommitLogSegmentReader.EncryptedSegmenter` |
| Т-13 | hints GCM: запись/чтение; чтение существующих CBC hints | `EncryptedHintsWriter`, `EncryptedChecksummedDataInput` |
| Т-14 | `JKSKeyInlineBase64Provider` читает keystore из base64 (JCEKS/PKCS12) | `JKSKeyInlineBase64Provider` |
| Т-15 | `VaultKeyProvider` получает ключи из Vault (AppRole) | `VaultKeyProvider` |
| Т-16 | В заголовок файла добавляется `encIVLength`; для GCM `encIV` не пишется | `EncryptionContext.toHeaderParameters` |

---

## 4. Средства и условия проведения испытаний

### 4.1. Технические средства

- ОС: Linux (x86-64).
- JDK: OpenJDK 17 (`JAVA_HOME=/usr/lib/jvm/java-17-openjdk` или аналог).
- Система сборки: Apache Ant.
- Исходный код ветки `tde_gcm_cipher_support`.

### 4.2. Программные средства

- Фреймворк модульного тестирования JUnit (в составе проекта).
- Тестовые keystore, генерируемые `EncryptionContextGenerator`.
- Для Т-15 при интеграционной проверке — доступный экземпляр HashiCorp Vault с
  настроенным AppRole (для модульного уровня — эмуляция/мок в тесте).

### 4.3. Порядок подготовки

1. Переключиться на ветку: `git checkout tde_gcm_cipher_support`.
2. Собрать проект: `ant build` (при первом запуске `ant jar`).
3. Убедиться, что рабочая директория чистая от посторонних артефактов
   (`log*`, `junitvmwatcher*.properties`, `dependency-reduced-pom.xml`,
   `modules/`) — они не должны влиять на прогон.

### 4.4. Общий формат запуска теста

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=<полное.имя.Класса>
```

---

## 5. Методика испытаний

Каждый пункт содержит: цель, покрываемые требования, автотест (при наличии),
шаги и ожидаемый результат. Испытание считается пройденным, если фактический
результат совпадает с ожидаемым.

### 5.1. Группа A. Криптографическое ядро (EncryptionUtils, CipherFactory)

Класс автотестов: `org.apache.cassandra.security.EncryptionUtilsTest`,
`org.apache.cassandra.security.CipherFactoryTest`.

| № | Цель / требование | Автотест | Шаги | Ожидаемый результат |
|---|-------------------|----------|------|---------------------|
| A-1 | GCM round-trip на нескольких блоках (Т-05, Т-07) | `EncryptionUtilsTest.gcmFullRoundTripWithMultipleBlocks` | Зашифровать несколько блоков через `EncryptionContext`, прочитать обратно | Расшифрованные данные побайтно равны исходным; у каждого блока свой IV |
| A-2 | Накопление ciphertext при коротких чтениях канала (Т-08) | `gcmDecryptAccumulatesCipherTextAcrossShortReads`, `readFullyAccumulatesAcrossShortReads` | Читать из канала, отдающего данные малыми порциями | Данные дочитываются полностью и расшифровываются корректно |
| A-3 | Подмена ciphertext (Т-06) | `gcmTamperedCipherTextThrowsIOException` | Изменить байт в области ciphertext, расшифровать | `IOException` (провал проверки тега) |
| A-4 | Подмена IV блока (Т-06) | `gcmTamperedIVThrowsIOException` | Изменить байт IV в заголовке блока | `IOException` |
| A-5 | Подмена длины plaintext (Т-06) | `gcmTamperedPlainTextLengthThrowsIOException` | Изменить поле `plaintext_length` | `IOException` |
| A-6 | Порча поля `encrypted_length` (Т-09) | `gcmCorruptEncryptedLengthThrowsIOException` | Задать некорректную длину блока | `IOException` (валидация длин) |
| A-7 | Усечённый ciphertext (Т-08, Т-09) | `gcmTruncatedCipherTextThrowsIOException` | Обрезать файл в области ciphertext | `IOException` |
| A-8 | Преждевременный конец файла (Т-08) | `readFullyThrowsOnPrematureEof` | Читать больше байт, чем есть в канале | `IOException` |
| A-9 | GCM требует `iv_length = 12` (Т-02) | `gcmRequiresStandardIVLength` | Создать контекст GCM с `iv_length ≠ 12` | `ConfigurationException` |
| A-10 | CBC-энкриптор запрещён для новых данных (Т-03) | `cbcEncryptorRejectedForNewEncryptedData` | Вызвать `getEncryptor()` при CBC | `ConfigurationException` |
| A-11 | Включённый CBC-конфиг отклоняется (Т-03, Т-04) | `cbcEnabledConfigRejectedForNewEncryptedData` | `validateForNewEncryptedData` с CBC и `enabled=true` | `ConfigurationException` |
| A-12 | Выключенный TDE с CBC допустим для чтения (Т-10) | `cbcDisabledConfigAllowedForExistingEncryptedData` | `validateForNewEncryptedData` с CBC и `enabled=false` | Исключения нет |
| A-13 | CBC-декриптор разрешён для существующих данных (Т-10) | `cbcDecryptorAllowedForExistingEncryptedData` | Построить `getDecryptor()` для CBC | Декриптор создаётся, исключения нет |
| A-14 | Восстановленный из заголовка GCM-контекст берёт `iv_length = 12` по умолчанию (Т-16) | `gcmReconstructedContextDefaultsToStandardIVLength` | Восстановить контекст без `encIVLength` | `iv_length = 12` |
| A-15 | GCM round-trip с 256-битным ключом; тег 128 бит (Т-07, Т-11) | `CipherFactoryTest.gcmRoundTripWith256BitKey` | Зашифровать/расшифровать AES-256 GCM | Данные восстановлены корректно |

### 5.2. Группа B. Commitlog

Класс автотестов: `org.apache.cassandra.db.commitlog.SegmentReaderTest`.

| № | Цель / требование | Автотест | Шаги | Ожидаемый результат |
|---|-------------------|----------|------|---------------------|
| B-1 | Последовательное чтение GCM-сегмента (Т-12) | `encryptedGcmSegmenterRead` | Записать зашифрованный сегмент, прочитать последовательно | Прочитанные данные равны исходным |
| B-2 | Seek по GCM-сегменту (Т-12) | `encryptedGcmSegmenterSeek` | Читать сегмент с позиционированием | Данные по смещениям корректны |
| B-3 | Регресс CBC-чтения (Т-10) | `underlyingEncryptedSegmenterTest(..., false)` (read/seek) | Прочитать CBC-сегмент | Поведение не изменилось, данные корректны |

### 5.3. Группа C. Hints

Класс автотестов: `org.apache.cassandra.hints.HintsEncryptionTest`.

| № | Цель / требование | Автотест | Шаги | Ожидаемый результат |
|---|-------------------|----------|------|---------------------|
| C-1 | Запись/чтение GCM hints (Т-13) | `encryptedHints` | Записать hints в GCM, прочитать обратно, сверить CRC | Hints восстановлены; CRC сходится |
| C-2 | Чтение существующих CBC hints (Т-10, Т-13) | `readsExistingCBCEncryptedHints` | Прочитать заранее подготовленный CBC-фикстур | Hints корректно десериализованы |

### 5.4. Группа D. Провайдеры ключей

Класс автотестов: `org.apache.cassandra.security.JKSKeyInlineBase64ProviderTest`.

| № | Цель / требование | Автотест | Шаги | Ожидаемый результат |
|---|-------------------|----------|------|---------------------|
| D-1 | Ключ из inline base64 с паролем ключа (Т-14) | `getSecretKey_WithKeyPassword` | Запросить ключ | Возвращён корректный ключ |
| D-2 | Ключ без отдельного пароля ключа (Т-14) | `getSecretKey_WithoutKeyPassword` | Запросить ключ, `key_password` не задан | Используется `keystore_password`; ключ возвращён |
| D-3 | Некорректный base64 (Т-14) | `constructor_WithMalformedBase64_ThrowsRuntimeException` | Передать битую строку | `RuntimeException` при инициализации |
| D-4 | Не-keystore байты (Т-14) | `constructor_WithNonKeystoreBytes_ThrowsRuntimeException` | Передать валидный base64, но не keystore | `RuntimeException` |
| D-5 | Отсутствующий alias (Т-14) | `getSecretKey_WithMissingAlias_ThrowsIOException` | Запросить несуществующий alias | `IOException` |
| D-6 | Тип keystore PKCS12 (Т-14) | `getSecretKey_WithPkcs12StoreType` | `store_type: PKCS12` | Ключ возвращён |

### 5.5. Группа E. VaultKeyProvider (Т-15)

Модульных тестов в ветке нет — проверка выполняется по методике ниже.
Рекомендуется провести на интеграционном стенде с реальным Vault; при
отсутствии стенда — зафиксировать как отложенную проверку.

| № | Цель | Шаги | Ожидаемый результат |
|---|------|------|---------------------|
| E-1 | Получение ключа из Vault (режим `keystore`) | Настроить AppRole; задать `endpoint`, `role_id`, `secret_id`, `store_type`, `keystore_password`, `keystore_key_alias`; запросить ключ | Ключ получен, TDE работает |
| E-2 | Ошибка аутентификации | Указать неверный `secret_id` | Ошибка аутентификации, ключ не выдан, диагностируемое сообщение |
| E-3 | Отсутствующий секрет | Указать несуществующий путь `key_alias` | Ошибка, ключ не выдан |

### 5.6. Группа F. Интеграционная проверка старта узла (Т-04)

| № | Цель | Шаги | Ожидаемый результат |
|---|------|------|---------------------|
| F-1 | Отклонение CBC-конфигурации при старте | В `cassandra.yaml` задать `enabled: true`, `cipher: AES/CBC/PKCS5Padding`; запустить узел | Узел не стартует, `ConfigurationException` о недопустимости CBC для новых данных |
| F-2 | Успешный старт с GCM | Задать `cipher: AES/GCM/NoPadding`, `iv_length: 12`, валидный key provider; запустить узел | Узел стартует, шифрование активно |
| F-3 | Совместимость чтения после перехода | На узле со старыми CBC-файлами перейти на GCM (старый ключ доступен) | Новые файлы — GCM; старые CBC читаются |

---

## 6. Порядок прогона автотестов

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.EncryptionUtilsTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.CipherFactoryTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.db.commitlog.SegmentReaderTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.hints.HintsEncryptionTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.JKSKeyInlineBase64ProviderTest
```

Результаты прогонов JUnit сохраняются в `build/test/output`. Для протокола
испытаний используются XML/лог-отчёты соответствующих классов.

---

## 7. Критерии приёмки

Испытания считаются успешно завершёнными, если:

1. Все автотесты групп A–D завершились без ошибок и падений (0 failures,
   0 errors).
2. Интеграционные проверки групп F выполнены с ожидаемым результатом.
3. Проверки группы E выполнены на интеграционном стенде либо обоснованно
   отложены с фиксацией в протоколе.
4. Не выявлено расхождений между фактическим и ожидаемым поведением по
   требованиям Т-01…Т-16.

---

## 8. Замечания и риски

1. **Дефект в `EncryptedSegment.additionalHeaderParameters()`.** В текущем
   состоянии ветки строка `map.put(ENCRYPTION_IV, Hex.bytesToHex(cipher.getIV()))`
   вызывается безусловно до проверки `usesPerBlockIV()`. Для GCM `cipher == null`,
   что приводит к `NullPointerException` на пути записи заголовка GCM-сегмента
   commitlog. **Проверки B-1/B-2 могут не воспроизвести дефект**, если в них
   заголовок формируется иным путём, — поэтому перед приёмкой требуется:
   - устранить безусловный вызов (оставить только ветку `!usesPerBlockIV()`);
   - повторно прогнать группу B на реальном сценарии записи GCM commitlog.
   До устранения этот пункт фиксируется как открытый дефект.

2. **Ротация ключа GCM.** Безопасность GCM требует не превышать ~`2^32`
   зашифрованных блоков на один ключ. Эксплуатационную процедуру ротации
   (см. `README_GCM_TDE_CLAUDE.md`) следует проверить организационно; в объём
   автотестов она не входит.

3. **Отсутствие модульных тестов `VaultKeyProvider`.** Группа E опирается на
   интеграционный стенд; при его недоступности покрытие Т-15 остаётся неполным.

---

## 9. Трассировка «требование → испытание»

| Требование | Испытания |
|-----------|-----------|
| Т-01 | (проверяется конфигурационно; косвенно A-9, A-14, F-2) |
| Т-02 | A-9 |
| Т-03 | A-10, A-11 |
| Т-04 | A-11, F-1 |
| Т-05 | A-1, B-1, B-2 |
| Т-06 | A-3, A-4, A-5 |
| Т-07 | A-1, A-15 |
| Т-08 | A-2, A-7, A-8 |
| Т-09 | A-6, A-7 |
| Т-10 | A-12, A-13, B-3, C-2, F-3 |
| Т-11 | A-15 |
| Т-12 | B-1, B-2 |
| Т-13 | C-1, C-2 |
| Т-14 | D-1…D-6 |
| Т-15 | E-1…E-3 |
| Т-16 | A-14 |

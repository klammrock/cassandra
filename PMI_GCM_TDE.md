# Программа и методика испытаний GCM TDE

## 1. Назначение

Настоящая программа и методика испытаний (ПМИ) описывает порядок проверки ветки
`tde_gcm_cipher_support`, в которой Transparent Data Encryption (TDE) для новых
commitlog и hints переведена на `AES/GCM/NoPadding`, а
`AES/CBC/PKCS5Padding` оставлена только для чтения существующих зашифрованных
файлов.

ПМИ предназначена для разработчика или инженера сопровождения, выполняющего
локальную проверку ветки перед слиянием, демонстрацией или эксплуатационным
прогоном.

## 2. Объект испытаний

Проверяются следующие компоненты:

- `org.apache.cassandra.security.EncryptionContext`
- `org.apache.cassandra.security.CipherFactory`
- `org.apache.cassandra.security.EncryptionUtils`
- `org.apache.cassandra.db.commitlog.EncryptedSegment`
- `org.apache.cassandra.db.commitlog.CommitLogSegmentReader.EncryptedSegmenter`
- `org.apache.cassandra.hints.HintsDescriptor`
- `org.apache.cassandra.hints.EncryptedHintsWriter`
- `org.apache.cassandra.hints.EncryptedChecksummedDataInput`
- `org.apache.cassandra.security.JKSKeyInlineBase64Provider`
- `org.apache.cassandra.security.VaultKeyProvider`
- параметры `transparent_data_encryption_options` в `conf/cassandra.yaml` и
  `conf/cassandra_latest.yaml`

## 3. Цели испытаний

Испытания должны подтвердить, что:

- новая конфигурация TDE по умолчанию использует `AES/GCM/NoPadding` и
  `iv_length: 12`;
- GCM использует новый IV для каждого зашифрованного блока;
- GCM-аутентификация обнаруживает повреждение ciphertext, IV и AAD-заголовка;
- commitlog и hints с GCM корректно записываются и читаются;
- существующие CBC hints и commitlog-секции остаются читаемыми;
- создание новых зашифрованных данных с CBC запрещено;
- key provider'ы возвращают AES-ключи и корректно обрабатывают ошибки;
- не происходит регрессий в существующем пути CBC-чтения.

## 4. Условия испытаний

Рекомендуемый стенд:

- ОС: Linux.
- JDK: Java 17.
- Система сборки: Ant из репозитория Cassandra.
- Рабочая директория: корень репозитория Cassandra.
- Ветка: `tde_gcm_cipher_support`.

Перед запуском зафиксировать состояние:

```bash
git branch --show-current
git rev-parse HEAD
git status --short
java -version
ant -version
```

Ожидается, что текущая ветка равна `tde_gcm_cipher_support`.

## 5. Общие критерии приемки

Испытания считаются успешными, если:

- все обязательные unit-тесты завершаются успешно;
- негативные проверки завершаются ожидаемой ошибкой, а не успешной записью или
  чтением поврежденных данных;
- GCM-файлы читаются без потери данных;
- CBC-файлы читаются, но CBC-конфигурация для новых данных отклоняется;
- в логах нет ошибок загрузки key provider'а, ошибок JCE, `NullPointerException`
  и необработанных исключений;
- при ручном интеграционном прогоне Cassandra стартует, пишет данные, выполняет
  flush/sync и успешно рестартует с replay commitlog.

## 6. Обязательная программа испытаний

### PMI-001. Проверка конфигурации по умолчанию

Цель: подтвердить, что дефолт TDE изменен на GCM.

Шаги:

```bash
rg -n "cipher: AES/GCM/NoPadding|iv_length: 12|AES/CBC/PKCS5Padding" conf/cassandra.yaml conf/cassandra_latest.yaml src/java/org/apache/cassandra/config/TransparentDataEncryptionOptions.java
```

Ожидаемый результат:

- в `TransparentDataEncryptionOptions` указаны `cipher = "AES/GCM/NoPadding"` и
  `iv_length = 12`;
- в `conf/cassandra.yaml` и `conf/cassandra_latest.yaml` пример TDE использует
  `AES/GCM/NoPadding`;
- CBC описан как режим только для чтения существующих encrypted commitlog/hints.

### PMI-002. Сборка измененных классов

Цель: убедиться, что изменения компилируются.

Шаги:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant jar
```

Ожидаемый результат:

- сборка завершается с кодом `0`;
- отсутствуют ошибки компиляции в пакетах `security`, `commitlog`, `hints`,
  `config`.

### PMI-003. Базовая криптография и формат GCM-блока

Цель: проверить round-trip, per-block IV, короткие чтения и негативные сценарии
расшифровки.

Шаги:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.EncryptionUtilsTest
```

Ожидаемый результат:

- `gcmFullRoundTripWithMultipleBlocks` проходит успешно;
- `gcmDecryptAccumulatesCipherTextAcrossShortReads` проходит успешно;
- тесты повреждения ciphertext, IV, plaintext length, encrypted length и
  усеченного ciphertext завершаются ожидаемым `IOException`;
- `gcmRequiresStandardIVLength` завершается ожидаемым
  `ConfigurationException`;
- `cbcEncryptorRejectedForNewEncryptedData` и
  `cbcEnabledConfigRejectedForNewEncryptedData` завершаются ожидаемым
  `ConfigurationException`;
- `cbcDisabledConfigAllowedForExistingEncryptedData` и
  `cbcDecryptorAllowedForExistingEncryptedData` проходят успешно.

### PMI-004. CipherFactory

Цель: проверить создание JCE cipher'ов для GCM и отсутствие регрессии кеша CBC.

Шаги:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.CipherFactoryTest
```

Ожидаемый результат:

- `gcmRoundTripWith256BitKey` проходит успешно;
- CBC round-trip проходит успешно;
- кеширование cipher'ов для CBC сохраняет прежнее поведение;
- для GCM не используется переиспользование cipher'а с прежним IV.

### PMI-005. Commitlog segment reader

Цель: проверить чтение зашифрованных commitlog-секций для CBC и GCM.

Шаги:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.db.commitlog.SegmentReaderTest
```

Ожидаемый результат:

- `encryptedSegmenterRead` и `encryptedSegmenterSeek` проходят успешно для CBC;
- `encryptedGcmSegmenterRead` и `encryptedGcmSegmenterSeek` проходят успешно
  для GCM;
- логическая длина sync-секции совпадает с исходной plaintext-длиной;
- seek внутри расшифрованного потока возвращает исходные байты.

### PMI-006. Hints encryption

Цель: проверить запись и чтение GCM hints, а также чтение старых CBC hints.

Шаги:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.hints.HintsEncryptionTest
```

Ожидаемый результат:

- `encryptedHints` проходит успешно;
- `readsExistingCBCEncryptedHints` проходит успешно;
- для GCM `EncryptedHintsWriter.getCipher()` и
  `EncryptedChecksummedDataInput.getCipher()` возвращают `null`, потому что IV
  хранится в каждом блоке;
- checksum-файл hints соответствует CRC всего файла;
- десериализованные hints совпадают с исходными.

### PMI-007. Inline base64 keystore provider

Цель: проверить загрузку keystore из base64-строки.

Шаги:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.JKSKeyInlineBase64ProviderTest
```

Ожидаемый результат:

- JCEKS keystore читается с отдельным `key_password`;
- JCEKS keystore читается без `key_password`, используя
  `keystore_password`;
- PKCS12 keystore читается успешно;
- поврежденный base64 и не-keystore данные приводят к ожидаемому
  `RuntimeException`;
- отсутствующий alias приводит к ожидаемому `IOException`.

### PMI-008. Набор обязательных unit-тестов одной командой

Цель: получить единый результат по основному набору TDE GCM.

Шаги:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.EncryptionUtilsTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.CipherFactoryTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.db.commitlog.SegmentReaderTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.hints.HintsEncryptionTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.JKSKeyInlineBase64ProviderTest
```

Ожидаемый результат:

- каждая команда завершается с кодом `0`;
- в отчет заносятся длительность, commit hash и список успешно пройденных
  классов.

## 7. Ручные интеграционные испытания

Эти проверки выполняются после успешного прохождения обязательных unit-тестов.
Они нужны для подтверждения, что ветка работает не только на уровне отдельных
утилит, но и в процессе Cassandra.

### PMI-101. Старт Cassandra с включенным GCM TDE

Цель: проверить загрузку конфигурации и key provider'а.

Подготовка:

- создать отдельные временные директории для `data_file_directories`,
  `commitlog_directory`, `saved_caches_directory` и `hints_directory`;
- подготовить keystore с AES-ключом alias `testing:1`;
- включить:

```yaml
transparent_data_encryption_options:
  enabled: true
  chunk_length_kb: 64
  cipher: AES/GCM/NoPadding
  key_alias: testing:1
  iv_length: 12
```

Шаги:

1. Запустить Cassandra в foreground на тестовой конфигурации.
2. Убедиться, что в логах есть инициализация `CipherFactory`.
3. Подключиться через `cqlsh`.
4. Создать keyspace и таблицу.
5. Записать набор строк размером больше одного TDE chunk.
6. Выполнить `nodetool flush`.
7. Остановить Cassandra штатно.

Ожидаемый результат:

- Cassandra стартует без `ConfigurationException`;
- в логах нет `NullPointerException` и ошибок загрузки ключа;
- данные записываются и читаются до остановки.

Особое внимание:

- в текущем состоянии ветки нужно проверить путь создания encrypted commitlog;
- если возникает `NullPointerException` в
  `EncryptedSegment.additionalHeaderParameters()`, результат фиксируется как
  дефект ветки, потому что для GCM `cipher` должен быть `null`.

### PMI-102. Replay GCM commitlog после рестарта

Цель: проверить чтение GCM commitlog с IV на каждый блок.

Шаги:

1. На стенде из PMI-101 записать данные.
2. Остановить Cassandra без удаления commitlog.
3. Запустить Cassandra повторно с тем же key provider'ом.
4. Дождаться завершения commitlog replay.
5. Прочитать ранее записанные строки через CQL.

Ожидаемый результат:

- commitlog replay завершается без ошибок расшифровки;
- данные доступны после рестарта;
- в логах нет ошибок `failed to decrypt commit log block`.

### PMI-103. GCM hints end-to-end

Цель: проверить запись и чтение hints в GCM-формате.

Шаги:

1. Запустить два тестовых узла с включенным GCM TDE.
2. Создать keyspace с replication factor `2`.
3. Остановить один узел.
4. На работающем узле выполнить записи, которые должны породить hints.
5. Убедиться, что hints-файлы созданы.
6. Запустить остановленный узел.
7. Дождаться доставки hints.
8. Проверить наличие данных на обоих узлах.

Ожидаемый результат:

- hints создаются и читаются без ошибок;
- доставка hints завершается успешно;
- данные появляются на ранее остановленном узле;
- checksum hints проходит проверку.

### PMI-104. Чтение старых CBC hints

Цель: подтвердить обратную совместимость с hints, созданными старым CBC-форматом.

Шаги:

1. Подготовить CBC hints-файл с descriptor, содержащим `encCipher`,
   `encKeyAlias`, `encIVLength`, `encIV`.
2. Убедиться, что key provider содержит ключ старого alias.
3. Запустить чтение hints через ветку `tde_gcm_cipher_support`.
4. Проверить десериализованные hints.

Ожидаемый результат:

- CBC hints читаются успешно;
- `EncryptedChecksummedDataInput` использует ненулевой CBC `Cipher`;
- содержимое hints совпадает с исходными данными.

### PMI-105. Запрет новой CBC-конфигурации

Цель: подтвердить, что CBC нельзя использовать для записи новых encrypted data.

Шаги:

1. Включить TDE.
2. Указать:

```yaml
cipher: AES/CBC/PKCS5Padding
iv_length: 16
```

3. Запустить Cassandra.

Ожидаемый результат:

- запуск завершается ошибкой конфигурации;
- сообщение содержит смысл: CBC поддерживается только для чтения существующих
  encrypted files, для новых данных нужно использовать `AES/GCM/NoPadding`.

### PMI-106. Ротация ключа

Цель: проверить чтение файлов со старым alias и запись новых файлов с новым
alias.

Шаги:

1. Запустить Cassandra с GCM TDE и `key_alias: testing:1`.
2. Записать данные и создать commitlog/hints.
3. Добавить в key provider новый ключ `testing:2`, не удаляя `testing:1`.
4. Изменить конфигурацию на `key_alias: testing:2`.
5. Перезапустить Cassandra.
6. Записать новые данные.
7. Проверить чтение старых и новых данных.

Ожидаемый результат:

- старые файлы читаются по alias `testing:1` из заголовков;
- новые файлы пишутся с alias `testing:2`;
- удаление старого ключа до исчезновения старых файлов считается ошибкой
  процедуры эксплуатации.

## 8. Опциональные испытания VaultKeyProvider

Эти испытания требуют доступного HashiCorp Vault или тестового mock-сервера,
возвращающего совместимые JSON-ответы. В текущей ветке готовый unit-тест для
`VaultKeyProvider` не добавлен, поэтому проверка является отдельной
интеграционной процедурой.

### PMI-201. Vault secret_type key

Цель: проверить получение AES-ключа напрямую из Vault secret.

Подготовка Vault:

- включить AppRole;
- создать role и secret_id;
- положить секрет KV v1 или KV v2 с полем `key`;
- значение `key` закодировать в `base64`, `hex` или `raw`;
- длина декодированного ключа должна быть 16, 24 или 32 байта.

Конфигурация:

```yaml
key_provider:
  - class_name: org.apache.cassandra.security.VaultKeyProvider
    parameters:
      - endpoint: "https://vault.example.com:8200"
        role_id: "<role-id>"
        secret_id: "<secret-id>"
        secret_type: key
        key_field: key
        key_encoding: base64
```

Ожидаемый результат:

- provider выполняет AppRole login;
- token кешируется после первого успешного login;
- ключ возвращается как AES `SecretKeySpec`;
- при неверной длине ключа возвращается `IOException`.

### PMI-202. Vault secret_type keystore

Цель: проверить получение keystore из Vault secret и извлечение ключа из него.

Подготовка Vault:

- положить в secret поле `keystore` с закодированным JCEKS/PKCS12 keystore;
- указать корректный `keystore_password`;
- указать `keystore_key_alias`, если alias внутри keystore отличается от
  внешнего `key_alias`.

Ожидаемый результат:

- keystore декодируется;
- ключ извлекается через `KeyStore#getKey(...)`;
- для JCEKS alias приводится к нижнему регистру;
- ошибки пароля, alias и формата keystore возвращаются как `IOException`.

## 9. Негативные испытания

### PMI-301. Неверная длина GCM IV

Шаги:

1. Указать `cipher: AES/GCM/NoPadding`.
2. Указать `iv_length: 16`.
3. Создать `EncryptionContext` или запустить Cassandra.

Ожидаемый результат:

- конфигурация отклоняется с `ConfigurationException`;
- сообщение указывает, что для `AES/GCM/NoPadding` требуется `iv_length: 12`.

### PMI-302. Повреждение ciphertext

Шаги:

1. Записать GCM-блок через `EncryptionUtils.encryptAndWrite(...)`.
2. Изменить один байт ciphertext.
3. Выполнить decrypt.

Ожидаемый результат:

- decrypt завершается `IOException`;
- поврежденные данные не возвращаются вызывающему коду.

### PMI-303. Повреждение IV

Шаги:

1. Записать GCM-блок.
2. Изменить один байт IV в заголовке блока.
3. Выполнить decrypt.

Ожидаемый результат:

- decrypt завершается `IOException`;
- ошибка фиксирует нарушение аутентификации GCM.

### PMI-304. Повреждение длины блока

Шаги:

1. Записать GCM-блок.
2. Изменить `encrypted_length` или `plaintext_length`.
3. Выполнить decrypt.

Ожидаемый результат:

- некорректные длины отклоняются до выделения чрезмерной памяти или в ходе GCM
  authentication check;
- decrypt завершается `IOException`.

### PMI-305. Усеченный файл

Шаги:

1. Записать GCM-блок.
2. Усечь файл на один или несколько байт.
3. Выполнить decrypt.

Ожидаемый результат:

- чтение завершается `IOException`;
- сообщение указывает на преждевременный конец encrypted block.

## 10. Проверка артефактов после испытаний

После каждого прогона сохранить:

- branch name;
- commit hash;
- команды запуска;
- stdout/stderr Ant;
- логи Cassandra;
- результат `git status --short`;
- список созданных commitlog/hints-файлов;
- итог по каждому test case: `PASS`, `FAIL`, `BLOCKED`, `NOT RUN`.

Рекомендуемый шаблон строки результата:

```text
PMI-003 | PASS | EncryptionUtilsTest | commit=<hash> | duration=<time> | notes=<notes>
```

## 11. Критерии остановки испытаний

Испытания нужно остановить и зафиксировать дефект, если обнаружено:

- `NullPointerException` или другая необработанная ошибка в GCM commitlog/hints
  пути;
- успешное чтение поврежденного GCM-блока без ошибки;
- возможность писать новые encrypted data с CBC;
- невозможность читать валидные старые CBC hints или commitlog-секции при
  наличии нужного ключа;
- расхождение исходных и прочитанных данных;
- ошибка загрузки ключа при корректной конфигурации key provider'а.

## 12. Минимальный приемочный набор

Для быстрой приемки ветки достаточно выполнить:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.EncryptionUtilsTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.CipherFactoryTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.db.commitlog.SegmentReaderTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.hints.HintsEncryptionTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.JKSKeyInlineBase64ProviderTest
```

Если эти тесты прошли, но ручные интеграционные сценарии не выполнялись, статус
ветки следует фиксировать как "unit-проверка пройдена, end-to-end не проверен".

## 13. Известный риск текущего состояния ветки

В текущем состоянии ветки в `EncryptedSegment.additionalHeaderParameters()` есть
подозрительное безусловное обращение к `cipher.getIV()` перед проверкой
`usesPerBlockIV()`. Для GCM `cipher` намеренно равен `null`, так как IV
генерируется на каждый блок.

Поэтому перед успешной приемкой end-to-end commitlog-сценариев необходимо
отдельно подтвердить PMI-101 и PMI-102. Если при создании encrypted commitlog
возникает `NullPointerException`, это блокирующий дефект для GCM commitlog.

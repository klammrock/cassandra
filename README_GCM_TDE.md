# GCM TDE в этой ветке

Этот документ описывает реализацию Transparent Data Encryption (TDE) из ветки
`tde_gcm_cipher_support`. Ветка переводит новые зашифрованные commitlog и hints
на `AES/GCM/NoPadding`, оставляя `AES/CBC/PKCS5Padding` только для чтения уже
существующих файлов.

## Что изменено

- Значения по умолчанию TDE в `TransparentDataEncryptionOptions` и
  `conf/cassandra.yaml` изменены на:
  - `cipher: AES/GCM/NoPadding`
  - `iv_length: 12`
- Для новых зашифрованных данных CBC запрещен. Если TDE включен с CBC-шифром,
  `DatabaseDescriptor` вызывает `EncryptionContext.validateForNewEncryptedData(...)`
  и конфигурация отклоняется.
- Старые CBC-файлы остаются читаемыми: контекст с CBC можно восстановить из
  заголовков commitlog/hints, если TDE в текущей конфигурации выключен или
  используется только для чтения старых файлов.
- Для GCM используется отдельный IV на каждый зашифрованный блок, а не один IV
  на весь файл.
- Заголовок GCM-блока добавляется в AAD, поэтому подмена длины блока, IV или
  ciphertext должна приводить к ошибке расшифровки.
- Добавлены key provider'ы:
  - `org.apache.cassandra.security.JKSKeyInlineBase64Provider`
  - `org.apache.cassandra.security.VaultKeyProvider`

## Поддерживаемые файлы

Реализация TDE в этой ветке применяется к тем же типам файлов, что и текущий
код Cassandra для file-level encryption:

- commitlog
- hints

SSTable-шифрование этим изменением не добавляется.

## Рекомендуемая конфигурация

Минимальный пример для GCM с обычным JCEKS/JKS key provider:

```yaml
transparent_data_encryption_options:
  enabled: true
  chunk_length_kb: 64
  cipher: AES/GCM/NoPadding
  key_alias: testing:1
  iv_length: 12
  key_provider:
    - class_name: org.apache.cassandra.security.JKSKeyProvider
      parameters:
        - keystore: conf/.keystore
          keystore_password: cassandra
          store_type: JCEKS
          key_password: cassandra
```

Практические требования:

- Для `AES/GCM/NoPadding` должен быть задан `iv_length: 12`.
- Длина authentication tag фиксирована в коде: 128 бит
  (`CipherFactory.GCM_TAG_LENGTH_BITS`).
- Для AES-256 используйте 256-битный ключ в keystore.
- Ключ с текущим `key_alias` используется для новых операций шифрования.
  Старые ключи нужно оставлять доступными провайдеру, потому что alias из
  заголовка файла используется при расшифровке старых данных.
- Для GCM ключ нужно ротировать задолго до записи `2^32` зашифрованных блоков
  одним ключом.

## Формат зашифрованного блока

Перед шифрованием данные сжимаются LZ4 через `EncryptionContext.getCompressor()`.
Размер блока задается `chunk_length_kb`.

Логический формат блока после изменений:

```text
int encrypted_length
int plaintext_length
int iv_length        # только для GCM/per-block IV
byte[iv_length] iv   # только для GCM/per-block IV
byte[encrypted_length] ciphertext
```

Для GCM в AAD передается тот же заголовок блока:

```text
encrypted_length || plaintext_length || iv_length || iv
```

Это означает, что GCM проверяет не только ciphertext, но и служебные длины и IV.
При повреждении или подмене таких данных `EncryptionUtils.decrypt(...)`
заворачивает ошибку JCE в `IOException`.

Для CBC старый формат сохраняется при чтении: IV берется из заголовка файла,
а в каждом блоке остаются только `encrypted_length`, `plaintext_length` и
ciphertext.

## Commitlog

Запись выполняет `EncryptedSegment`:

1. Берет данные текущей sync-секции commitlog.
2. Делит их на блоки размером `chunk_length_kb`.
3. Сжимает каждый блок.
4. Шифрует блок.
5. Для GCM создает новый encryptor и новый IV для каждого блока.
6. Учитывает фактически записанный размер блока через разницу позиций channel,
   чтобы в размере сегмента учитывались и GCM IV-заголовки.

Чтение выполняет `CommitLogSegmentReader.EncryptedSegmenter`:

- для GCM decryptor создается на каждый блок после чтения IV из блока;
- для CBC decryptor создается один раз из IV, восстановленного из заголовка
  commitlog;
- после расшифровки блок распаковывается и отдается через
  `EncryptedFileSegmentInputStream`.

## Hints

Запись выполняет `EncryptedHintsWriter`:

- hints сначала сжимаются, затем шифруются;
- для GCM `EncryptionUtils.encryptAndWrite(..., EncryptionContext, CRC32)`
  пишет в файл и заголовок блока, и ciphertext, одновременно обновляя общий CRC;
- для CBC используется старый путь с одним `Cipher` на файл.

Чтение выполняет `EncryptedChecksummedDataInput`:

- для GCM `Cipher` в descriptor отсутствует, потому что IV хранится в каждом
  блоке;
- для CBC `Cipher` восстанавливается из IV в descriptor;
- позиционирование учитывает исходную позицию в файле и позицию внутри
  распакованного буфера.

`HintsDescriptor.createEncryption(...)` при GCM записывает в descriptor только
параметры шифрования (`encCipher`, `encKeyAlias`, `encIVLength`). `encIV` для
GCM на уровне descriptor не нужен.

## Совместимость с CBC

CBC в этой ветке имеет статус read-only:

- Новые зашифрованные commitlog/hints нельзя создавать с CBC.
- Включенная конфигурация TDE с `AES/CBC/PKCS5Padding` отклоняется при старте.
- Старые CBC-файлы можно читать, если в их заголовке есть:
  - `encCipher`
  - `encKeyAlias`
  - `encIVLength`
  - `encIV`
- Key provider должен уметь вернуть ключ по старому alias.

Это сделано, чтобы не продолжать запись новых данных в режиме без
аутентификации ciphertext.

## JKSKeyInlineBase64Provider

`JKSKeyInlineBase64Provider` читает keystore не из файла, а из base64-строки в
конфигурации. Это удобно для окружений, где секреты доставляются в Cassandra
как значения конфигурации.

Пример:

```yaml
transparent_data_encryption_options:
  enabled: true
  chunk_length_kb: 64
  cipher: AES/GCM/NoPadding
  key_alias: testing:1
  iv_length: 12
  key_provider:
    - class_name: org.apache.cassandra.security.JKSKeyInlineBase64Provider
      parameters:
        - keystore: "<base64-encoded-keystore>"
          keystore_password: "store-password"
          store_type: JCEKS
          key_password: "key-password"
```

Параметры:

- `keystore`: base64-представление keystore.
- `keystore_password`: пароль keystore.
- `store_type`: тип keystore, например `JCEKS` или `PKCS12`.
- `key_password`: пароль записи ключа. Если не задан, используется
  `keystore_password`.

Для `JCEKS` alias приводится к нижнему регистру, повторяя поведение Java
keystore.

## VaultKeyProvider

`VaultKeyProvider` получает ключи из HashiCorp Vault через AppRole. Значение
`key_alias` трактуется как путь секрета в Vault.

Обязательные параметры:

- `endpoint`: URL Vault без `/v1`.
- `role_id`: AppRole role_id.
- `secret_id`: AppRole secret_id.

Необязательные параметры:

- `auth_path`: путь AppRole login, по умолчанию `auth/approle/login`.
- `namespace`: Vault namespace, если используется Vault Enterprise.
- `request_timeout_ms`: timeout HTTP-запросов, по умолчанию `10000`.
- `secret_type`: `key` или `keystore`, по умолчанию `key`.

### Vault secret_type: key

В режиме `key` провайдер ожидает AES-ключ прямо в секрете. Поддерживаются формы
ответа KV v1 (`data.key`) и KV v2 (`data.data.key`).

```yaml
transparent_data_encryption_options:
  enabled: true
  chunk_length_kb: 64
  cipher: AES/GCM/NoPadding
  key_alias: secret/data/cassandra/tde/testing-1
  iv_length: 12
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

Параметры режима `key`:

- `key_field`: поле с ключом, по умолчанию `key`.
- `key_encoding`: `base64`, `hex` или `raw`, по умолчанию `base64`.

После декодирования длина ключа должна быть 16, 24 или 32 байта.

### Vault secret_type: keystore

В режиме `keystore` секрет Vault содержит закодированный keystore, а ключ
извлекается из него через `KeyStore#getKey(...)`.

```yaml
transparent_data_encryption_options:
  enabled: true
  chunk_length_kb: 64
  cipher: AES/GCM/NoPadding
  key_alias: secret/data/cassandra/tde/keystore
  iv_length: 12
  key_provider:
    - class_name: org.apache.cassandra.security.VaultKeyProvider
      parameters:
        - endpoint: "https://vault.example.com:8200"
          role_id: "<role-id>"
          secret_id: "<secret-id>"
          secret_type: keystore
          keystore_field: keystore
          keystore_encoding: base64
          store_type: JCEKS
          keystore_password: "store-password"
          keystore_key_alias: testing:1
          key_password: "key-password"
```

Параметры режима `keystore`:

- `keystore_field`: поле с keystore, по умолчанию `keystore`.
- `keystore_encoding`: `base64`, `hex` или `raw`, по умолчанию `base64`.
- `store_type`: тип keystore, по умолчанию `JCEKS`.
- `keystore_password`: обязательный пароль keystore.
- `keystore_key_alias`: alias ключа внутри keystore. Если не задан, используется
  внешний `key_alias`.
- `key_password`: пароль записи ключа. Если не задан, используется
  `keystore_password`.

## Ротация ключей

Для ротации:

1. Добавьте новый ключ в выбранный key provider.
2. Измените `transparent_data_encryption_options.key_alias` на новый alias.
3. Перезапустите узел с новой конфигурацией.
4. Не удаляйте старые ключи, пока на диске могут оставаться commitlog или hints,
   зашифрованные старым alias.

Новые файлы будут писаться новым ключом. Старые файлы читаются по alias из их
заголовков.

## Проверки в тестах

Ветка добавляет и расширяет unit-тесты для следующих сценариев:

- `EncryptionUtilsTest`: GCM round-trip на нескольких блоках, короткие чтения,
  повреждение ciphertext, IV, длины plaintext и длины encrypted-блока.
- `CipherFactoryTest`: GCM round-trip с 256-битным ключом.
- `SegmentReaderTest`: чтение и seek по encrypted commitlog-секциям для CBC и
  GCM.
- `HintsEncryptionTest`: запись/чтение GCM hints и чтение существующих CBC
  hints.
- `JKSKeyInlineBase64ProviderTest`: чтение JCEKS/PKCS12 keystore из inline
  base64 и ошибки некорректного keystore/alias.

Примеры запуска отдельных тестов:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.EncryptionUtilsTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.CipherFactoryTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.db.commitlog.SegmentReaderTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.hints.HintsEncryptionTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.JKSKeyInlineBase64ProviderTest
```

## Текущее замечание по ветке

В `EncryptedSegment.additionalHeaderParameters()` в текущем состоянии ветки есть
подозрительное безусловное обращение к `cipher.getIV()` перед проверкой
`usesPerBlockIV()`. Для GCM `cipher` в `EncryptedSegment` намеренно равен
`null`, потому что IV генерируется на каждый блок. Если этот путь вызывается при
создании GCM commitlog-сегмента, возможен `NullPointerException`. Перед
эксплуатационным прогоном GCM commitlog стоит исправить это место и прогнать
commitlog-тесты.

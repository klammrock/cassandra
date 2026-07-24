# TDE на AES/GCM в ветке `tde_gcm_cipher_support`

Документ описывает изменения Transparent Data Encryption (TDE) в текущей ветке
git. Ветка переводит шифрование файлов Cassandra (commitlog и hints) с
`AES/CBC/PKCS5Padding` на аутентифицированный режим `AES/GCM/NoPadding`. CBC
остаётся поддержан только для чтения ранее записанных файлов.

Документ написан Claude по фактическому diff ветки относительно `trunk` и
дополняет уже существующий `README_GCM_TDE.md`.

## Кратко: что и зачем

- **По умолчанию теперь GCM.** `AES/GCM/NoPadding` — это AEAD-режим: он не
  только шифрует данные, но и проверяет их целостность (authentication tag).
  CBC такой проверки не даёт, поэтому подмену или повреждение зашифрованных
  байт CBC молча не замечает.
- **CBC переведён в режим «только чтение».** Новые зашифрованные файлы с CBC
  создавать нельзя; включённый TDE с CBC отклоняется при старте узла. Старые
  CBC-файлы читаются как раньше.
- **IV генерируется на каждый блок (для GCM).** В CBC один IV на файл хранился
  в заголовке; в GCM повторное использование пары «ключ + IV» недопустимо,
  поэтому IV записывается в заголовок каждого зашифрованного блока.
- **Заголовок блока входит в AAD.** Для GCM длины и IV блока попадают в
  Additional Authenticated Data, то есть их подмена ломает расшифровку.
- **Добавлены два провайдера ключей:** `JKSKeyInlineBase64Provider` (keystore
  прямо в конфиге в base64) и `VaultKeyProvider` (ключи из HashiCorp Vault).

Область действия не расширяется: как и раньше, шифруются только **commitlog** и
**hints**. SSTable этой веткой не затрагиваются.

## Изменения по файлам

| Файл | Суть изменения |
|------|----------------|
| `config/TransparentDataEncryptionOptions.java` | Значения по умолчанию: `cipher = AES/GCM/NoPadding`, `iv_length = 12`. |
| `config/DatabaseDescriptor.java` | При загрузке контекста вызывается `EncryptionContext.validateForNewEncryptedData(...)` — конфиг с CBC при включённом TDE отклоняется. |
| `security/EncryptionContext.java` | Определение AEAD/CBC, `usesPerBlockIV()`, валидация `iv_length`, новый параметр заголовка `encIVLength`, перегрузка `getDecryptor(byte[] iv)`. |
| `security/CipherFactory.java` | Для GCM используется `GCMParameterSpec` с тегом 128 бит; GCM-шифры не кэшируются в thread-local. |
| `security/EncryptionUtils.java` | Формат блока с per-block IV, AAD для GCM, обновление CRC, строгий `readFully`, валидация длин блока. |
| `db/commitlog/EncryptedSegment.java` | Запись commitlog: для GCM `cipher == null`, новый IV на блок; учёт размера блока по позиции channel. |
| `db/commitlog/CommitLogSegmentReader.java` | Чтение commitlog: для GCM decryptor строится на каждый блок из его IV. |
| `hints/EncryptedHintsWriter.java`, `hints/EncryptedChecksummedDataInput.java`, `hints/HintsDescriptor.java`, `hints/HintsReader.java` | Запись/чтение hints для GCM (IV в блоке, CRC), descriptor без общего IV для GCM. |
| `security/JKSKeyInlineBase64Provider.java` | Новый провайдер: keystore из base64-строки. |
| `security/VaultKeyProvider.java` | Новый провайдер: ключи из HashiCorp Vault (AppRole). |

Тесты: `EncryptionUtilsTest`, `CipherFactoryTest`, `SegmentReaderTest`,
`HintsEncryptionTest`, `JKSKeyInlineBase64ProviderTest`, а также расширения
`AlteredHints` и `EncryptionContextGenerator`.

## Как это работает

### Определение режима

Режим определяется по строке трансформации (без учёта регистра):

- `EncryptionContext.isAEAD(t)` — содержит `/GCM/`;
- `EncryptionContext.isCBCCipher(t)` — содержит `/CBC/`.

Если режим AEAD, `EncryptionContext.usesPerBlockIV()` возвращает `true`, и весь
код записи/чтения переключается на путь «IV в каждом блоке».

### Валидация конфигурации

`EncryptionContext.validate(...)` требует для `AES/GCM/NoPadding` строго
`iv_length: 12` (константа `GCM_IV_LENGTH`), иначе — `ConfigurationException`.

`EncryptionContext.validateCipherForNewEncryptedData(...)` запрещает CBC для
новых данных. Она вызывается в двух местах:

1. при старте узла через `DatabaseDescriptor` (если TDE включён);
2. внутри `EncryptionContext.getEncryptor()` — то есть на любой попытке
   зашифровать новый блок.

Расшифровка (`getDecryptor`) этой проверки не делает, поэтому старые CBC-файлы
читаются.

### Формат зашифрованного блока

Перед шифрованием блок сжимается LZ4 (`EncryptionContext.getCompressor()`),
размер блока — `chunk_length_kb`.

**CBC (чтение старых файлов):**

```text
int  encrypted_length      // длина ciphertext
int  plaintext_length      // длина сжатых данных
byte[encrypted_length] ciphertext
```

IV для CBC берётся один на файл из заголовка commitlog/hints.

**GCM (новый формат):**

```text
int  encrypted_length      // ciphertext + auth tag
int  plaintext_length
int  iv_length             // == 12
byte[iv_length] iv         // уникальный IV этого блока
byte[encrypted_length] ciphertext
```

Для GCM первые `encrypted_length || plaintext_length || iv_length || iv`
передаются в `cipher.updateAAD(...)` и при записи, и при чтении. Значит, GCM
аутентифицирует не только сам ciphertext, но и служебные длины и IV: любая их
подмена приведёт к ошибке `doFinal`, которую `EncryptionUtils.decrypt(...)`
оборачивает в `IOException`.

Ключевые методы: `EncryptionUtils.encryptAndWrite(...)` (перегрузки с `Cipher`,
с `EncryptionContext`, и с `EncryptionContext + CRC32`) и
`EncryptionUtils.decrypt(...)` (аналогичные перегрузки).

### Защитные проверки при чтении

Ветка добавляет в `EncryptionUtils` устойчивость к битым/враждебным файлам:

- `readFully(...)` — дочитывает буфер полностью; при преждевременном конце
  файла бросает `IOException` (раньше частичное `channel.read` могло дать
  тихую порчу данных);
- `validateEncryptedBlockLengths(...)` — длины блока должны быть
  положительными, `encrypted_length >= plaintext_length` и не больше
  `2 × commitlog_segment_size`;
- длина IV блока проверяется на диапазон `1..256`, иначе `IOException`.

### CipherFactory и GCM

- Для GCM применяется `GCMParameterSpec(128, iv)` вместо `IvParameterSpec` —
  тег аутентификации 128 бит (`CipherFactory.GCM_TAG_LENGTH_BITS`,
  рекомендованный максимум).
- GCM-шифры **не кэшируются** в `cipherThreadLocal`: для каждого блока создаётся
  новый `Cipher` с новым IV, кэш здесь бесполезен и опасен.

## Commitlog

**Запись — `EncryptedSegment`:**

- для GCM поле `cipher` равно `null` (encryptor создаётся на каждый блок внутри
  `EncryptionUtils.encryptAndWrite(..., EncryptionContext)`), для CBC — один
  `cipher` на сегмент;
- размер блока учитывается как `channel.position() - blockStart`, то есть в
  учёт размера сегмента честно попадают и байты per-block IV (для CBC поведение
  учёта не меняется).

**Чтение — `CommitLogSegmentReader.EncryptedSegmenter`:**

- для GCM `cipher == null`, decryptor строится на каждый блок из его IV;
- для CBC decryptor строится один раз из IV в заголовке commitlog;
- после расшифровки блок распаковывается и отдаётся через
  `EncryptedFileSegmentInputStream`.

## Hints

**Запись — `EncryptedHintsWriter`:** hints сжимаются, затем шифруются; для GCM
используется перегрузка `encryptAndWrite(..., EncryptionContext, CRC32)`,
которая одновременно пишет заголовок блока и ciphertext и обновляет общий CRC32.

**Чтение — `EncryptedChecksummedDataInput`:** для GCM в descriptor нет общего
`Cipher` (IV лежит в каждом блоке); для CBC `Cipher` восстанавливается из IV в
descriptor.

**`HintsDescriptor.createEncryption(...)`:** для GCM в заголовок пишутся только
`encCipher`, `encKeyAlias`, `encIVLength`; общий `encIV` для GCM не нужен.

## Параметры заголовка файла

`EncryptionContext.toHeaderParameters()` пишет:

| Ключ | Назначение | GCM | CBC |
|------|------------|-----|-----|
| `encCipher` | строка трансформации | да | да |
| `encKeyAlias` | alias ключа | да | да |
| `encIVLength` | длина IV (**новый ключ**) | да | да |
| `encIV` | IV файла | нет | да |

При восстановлении контекста из заголовка `encIVLength` разбирается методом
`parseIVLength(...)`: если значение отсутствует, для GCM берётся `12`, для
остального — `iv_length` из текущей конфигурации.

## Конфигурация

### GCM с обычным JKS/JCEKS-провайдером

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

Требования:

- для `AES/GCM/NoPadding` обязателен `iv_length: 12`;
- длина тега аутентификации фиксирована в коде — 128 бит;
- для AES-256 в keystore нужен 256-битный ключ;
- старые ключи должны оставаться доступными провайдеру, пока на диске есть
  файлы, зашифрованные их alias (alias берётся из заголовка файла);
- ключ следует ротировать заранее — задолго до `2^32` зашифрованных блоков
  одним ключом (ограничение безопасности GCM).

### JKSKeyInlineBase64Provider

Читает keystore не из файла, а из base64-строки в конфиге. Удобно, когда
секреты доставляются как значения конфигурации.

```yaml
  key_provider:
    - class_name: org.apache.cassandra.security.JKSKeyInlineBase64Provider
      parameters:
        - keystore: "<keystore в base64>"
          keystore_password: "store-password"
          store_type: JCEKS
          key_password: "key-password"
```

- `keystore` — base64-представление keystore;
- `keystore_password` — пароль keystore;
- `store_type` — например `JCEKS` или `PKCS12`;
- `key_password` — пароль записи ключа; если не задан, берётся
  `keystore_password`;
- для `JCEKS` alias приводится к нижнему регистру (как в самом Java keystore).

### VaultKeyProvider

Получает ключи из HashiCorp Vault через AppRole; `key_alias` трактуется как
путь секрета в Vault.

```yaml
  key_alias: secret/data/cassandra/tde/keystore
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

Обязательные: `endpoint` (URL без `/v1`), `role_id`, `secret_id`. В режиме
`keystore`: `keystore_field` (по умолчанию `keystore`), `keystore_encoding`
(`base64`/`hex`/`raw`, по умолчанию `base64`), `store_type` (по умолчанию
`JCEKS`), `keystore_password` (обязателен), `keystore_key_alias` (иначе внешний
`key_alias`), `key_password` (иначе `keystore_password`).

## Совместимость и миграция

- Новые commitlog/hints пишутся только GCM.
- Старые CBC-файлы читаются, если в заголовке есть `encCipher`, `encKeyAlias`,
  `encIVLength`, `encIV`, а провайдер отдаёт ключ по старому alias.
- Включённый TDE с CBC узел не запустит — сначала нужно перейти на GCM.

Ротация ключа:

1. добавьте новый ключ в провайдер;
2. смените `key_alias` на новый;
3. перезапустите узел;
4. не удаляйте старые ключи, пока на диске есть файлы под старым alias.

## Запуск тестов

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.EncryptionUtilsTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.CipherFactoryTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.db.commitlog.SegmentReaderTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.hints.HintsEncryptionTest
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ant test -Dtest.name=org.apache.cassandra.security.JKSKeyInlineBase64ProviderTest
```

## Известная проблема в текущем состоянии ветки

В `EncryptedSegment.additionalHeaderParameters()` строка
`map.put(ENCRYPTION_IV, Hex.bytesToHex(cipher.getIV()))` вызывается
**безусловно**, ещё до проверки `usesPerBlockIV()`:

```java
Map<String, String> map = encryptionContext.toHeaderParameters();
map.put(EncryptionContext.ENCRYPTION_IV, Hex.bytesToHex(cipher.getIV())); // NPE для GCM: cipher == null
if (!encryptionContext.usesPerBlockIV())
    map.put(EncryptionContext.ENCRYPTION_IV, Hex.bytesToHex(cipher.getIV()));
return map;
```

Для GCM `cipher` в `EncryptedSegment` намеренно `null`, поэтому первый вызов
`cipher.getIV()` даёт `NullPointerException`. Похоже, при рефакторинге строку
продублировали, а исходную безусловную не убрали. Перед боевым использованием
GCM для commitlog это место нужно исправить (убрать безусловную строку) и
прогнать commitlog-тесты.

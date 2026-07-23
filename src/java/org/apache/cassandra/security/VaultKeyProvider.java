/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.cassandra.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;

import org.apache.cassandra.config.TransparentDataEncryptionOptions;
import org.apache.cassandra.utils.Hex;
import org.apache.cassandra.utils.JsonUtils;

/**
 * A Vault AppRole-backed key provider for transparent data encryption.
 *
 * The TDE key alias is treated as the Vault secret path. The secret value is expected in
 * {@code key_field}, defaulting to {@code key}. Both KV v1 ({@code data.key}) and KV v2
 * ({@code data.data.key}) response shapes are supported. For {@code secret_type: keystore},
 * the secret is expected to contain an encoded keystore blob and the key is read with
 * {@link KeyStore#getKey(String, char[])}.
 */
public class VaultKeyProvider implements KeyProvider
{
    private static final String PROP_ENDPOINT = "endpoint";
    private static final String PROP_ROLE_ID = "role_id";
    private static final String PROP_SECRET_ID = "secret_id";
    private static final String PROP_AUTH_PATH = "auth_path";
    private static final String PROP_SECRET_TYPE = "secret_type";
    private static final String PROP_KEY_FIELD = "key_field";
    private static final String PROP_KEY_ENCODING = "key_encoding";
    private static final String PROP_KEYSTORE_FIELD = "keystore_field";
    private static final String PROP_KEYSTORE_ENCODING = "keystore_encoding";
    private static final String PROP_KEYSTORE_TYPE = "store_type";
    private static final String PROP_KEYSTORE_PASSWORD = "keystore_password";
    private static final String PROP_KEYSTORE_KEY_ALIAS = "keystore_key_alias";
    private static final String PROP_KEY_PASSWORD = "key_password";
    private static final String PROP_NAMESPACE = "namespace";
    private static final String PROP_REQUEST_TIMEOUT_MS = "request_timeout_ms";

    private static final String DEFAULT_AUTH_PATH = "auth/approle/login";
    private static final String DEFAULT_SECRET_TYPE = "key";
    private static final String DEFAULT_KEY_FIELD = "key";
    private static final String DEFAULT_KEY_ENCODING = "base64";
    private static final String DEFAULT_KEYSTORE_FIELD = "keystore";
    private static final String DEFAULT_KEYSTORE_ENCODING = "base64";
    private static final String DEFAULT_KEYSTORE_TYPE = "JCEKS";
    private static final int DEFAULT_REQUEST_TIMEOUT_MS = 10000;

    private final HttpClient client;
    private final String endpoint;
    private final String roleId;
    private final String secretId;
    private final String authPath;
    private final String secretType;
    private final String keyField;
    private final String keyEncoding;
    private final String keystoreField;
    private final String keystoreEncoding;
    private final String keystoreType;
    private final String keystorePassword;
    private final String keystoreKeyAlias;
    private final String keyPassword;
    private final String namespace;
    private final Duration requestTimeout;

    private volatile String token;

    public VaultKeyProvider(TransparentDataEncryptionOptions options)
    {
        endpoint = required(options, PROP_ENDPOINT).replaceAll("/+$", "");
        roleId = required(options, PROP_ROLE_ID);
        secretId = required(options, PROP_SECRET_ID);
        authPath = trimSlashes(optional(options, PROP_AUTH_PATH, DEFAULT_AUTH_PATH));
        secretType = optional(options, PROP_SECRET_TYPE, DEFAULT_SECRET_TYPE);
        keyField = optional(options, PROP_KEY_FIELD, DEFAULT_KEY_FIELD);
        keyEncoding = optional(options, PROP_KEY_ENCODING, DEFAULT_KEY_ENCODING);
        keystoreField = optional(options, PROP_KEYSTORE_FIELD, DEFAULT_KEYSTORE_FIELD);
        keystoreEncoding = optional(options, PROP_KEYSTORE_ENCODING, DEFAULT_KEYSTORE_ENCODING);
        keystoreType = optional(options, PROP_KEYSTORE_TYPE, DEFAULT_KEYSTORE_TYPE);
        keystorePassword = options.get(PROP_KEYSTORE_PASSWORD);
        keystoreKeyAlias = options.get(PROP_KEYSTORE_KEY_ALIAS);
        keyPassword = options.get(PROP_KEY_PASSWORD);
        namespace = options.get(PROP_NAMESPACE);
        requestTimeout = Duration.ofMillis(Integer.parseInt(optional(options, PROP_REQUEST_TIMEOUT_MS,
                                                                     Integer.toString(DEFAULT_REQUEST_TIMEOUT_MS))));
        client = HttpClient.newBuilder()
                           .connectTimeout(requestTimeout)
                           .build();
    }

    public Key getSecretKey(String alias) throws IOException
    {
        if ("keystore".equalsIgnoreCase(secretType))
            return readKeyFromKeystore(alias);
        if (!"key".equalsIgnoreCase(secretType))
            throw new IOException("unsupported Vault secret_type: " + secretType);

        byte[] key = decodeKey(readKeyMaterial(alias));
        validateAesKeyLength(alias, key);
        return new SecretKeySpec(key, "AES");
    }

    private String readKeyMaterial(String alias) throws IOException
    {
        Map<?, ?> secret = readSecret(alias);
        Object value = secret.get(keyField);
        if (!(value instanceof String) || ((String) value).isEmpty())
            throw new IOException("Vault secret " + alias + " does not contain non-empty field " + keyField);
        return (String) value;
    }

    private Key readKeyFromKeystore(String alias) throws IOException
    {
        Map<?, ?> secret = readSecret(alias);
        Object value = secret.get(keystoreField);
        if (!(value instanceof String) || ((String) value).isEmpty())
            throw new IOException("Vault secret " + alias + " does not contain non-empty field " + keystoreField);

        byte[] keystoreBytes = decodeMaterial((String) value, keystoreEncoding, "keystore");
        char[] storePassword = password(keystorePassword, PROP_KEYSTORE_PASSWORD);
        char[] entryPassword = keyPassword == null || keyPassword.isEmpty() ? storePassword : keyPassword.toCharArray();
        String entryAlias = keystoreKeyAlias == null || keystoreKeyAlias.isEmpty() ? alias : keystoreKeyAlias;

        try
        {
            KeyStore keyStore = KeyStore.getInstance(keystoreType);
            keyStore.load(new ByteArrayInputStream(keystoreBytes), storePassword);
            if (keyStore.getType().equalsIgnoreCase("jceks"))
                entryAlias = entryAlias.toLowerCase();

            Key key = keyStore.getKey(entryAlias, entryPassword);
            if (key == null)
                throw new IOException("key " + entryAlias + " was not found in Vault keystore secret " + alias);
            return key;
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new IOException("unable to load key " + entryAlias + " from Vault keystore secret " + alias, e);
        }
    }

    private Map<?, ?> readSecret(String alias) throws IOException
    {
        Map<?, ?> body = vaultGet(trimSlashes(alias));
        Map<?, ?> data = mapValue(body, "data");
        if (data == null)
            throw new IOException("Vault secret " + alias + " does not contain a data object");

        Map<?, ?> kv2Data = mapValue(data, "data");
        return kv2Data != null ? kv2Data : data;
    }

    private Map<?, ?> vaultGet(String path) throws IOException
    {
        HttpRequest.Builder builder = requestBuilder(endpoint + "/v1/" + encodePath(path))
                                      .GET()
                                      .header("X-Vault-Token", login());
        return send(builder.build(), "read Vault secret " + path);
    }

    private String login() throws IOException
    {
        String existing = token;
        if (existing != null)
            return existing;

        synchronized (this)
        {
            if (token != null)
                return token;

            Map<String, String> payload = Map.of(PROP_ROLE_ID, roleId, PROP_SECRET_ID, secretId);
            HttpRequest request = requestBuilder(endpoint + "/v1/" + authPath)
                                  .POST(HttpRequest.BodyPublishers.ofString(JsonUtils.writeAsJsonString(payload)))
                                  .build();
            Map<?, ?> body = send(request, "authenticate to Vault");
            Map<?, ?> auth = mapValue(body, "auth");
            Object clientToken = auth == null ? null : auth.get("client_token");
            if (!(clientToken instanceof String) || ((String) clientToken).isEmpty())
                throw new IOException("Vault authentication response did not include auth.client_token");

            token = (String) clientToken;
            return token;
        }
    }

    private HttpRequest.Builder requestBuilder(String uri)
    {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(uri))
                                                 .timeout(requestTimeout)
                                                 .header("Content-Type", "application/json");
        if (namespace != null && !namespace.isEmpty())
            builder.header("X-Vault-Namespace", namespace);
        return builder;
    }

    private Map<?, ?> send(HttpRequest request, String action) throws IOException
    {
        HttpResponse<String> response;
        try
        {
            response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while attempting to " + action, e);
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300)
            throw new IOException("failed to " + action + ": Vault returned HTTP " + response.statusCode());

        Object json = JsonUtils.decodeJson(response.body());
        if (!(json instanceof Map))
            throw new IOException("failed to " + action + ": Vault response was not a JSON object");
        return (Map<?, ?>) json;
    }

    private byte[] decodeKey(String encoded) throws IOException
    {
        return decodeMaterial(encoded, keyEncoding, "key");
    }

    private byte[] decodeMaterial(String encoded, String encoding, String materialName) throws IOException
    {
        try
        {
            switch (encoding.toLowerCase())
            {
                case "base64":
                    return Base64.getDecoder().decode(encoded);
                case "hex":
                    return Hex.hexToBytes(encoded);
                case "raw":
                    return encoded.getBytes(StandardCharsets.UTF_8);
                default:
                    throw new IOException("unsupported Vault " + materialName + " encoding: " + encoding);
            }
        }
        catch (IllegalArgumentException e)
        {
            throw new IOException("failed to decode Vault " + materialName + " material as " + encoding, e);
        }
    }

    private static void validateAesKeyLength(String alias, byte[] key) throws IOException
    {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new IOException("Vault key " + alias + " has invalid AES key length " + key.length);
    }

    private static Map<?, ?> mapValue(Map<?, ?> map, String key)
    {
        Object value = map.get(key);
        return value instanceof Map ? (Map<?, ?>) value : null;
    }

    private static String required(TransparentDataEncryptionOptions options, String key)
    {
        String value = options.get(key);
        if (value == null || value.isEmpty())
            throw new IllegalArgumentException("missing required Vault key provider parameter: " + key);
        return value;
    }

    private static String optional(TransparentDataEncryptionOptions options, String key, String defaultValue)
    {
        String value = options.get(key);
        return value == null || value.isEmpty() ? defaultValue : value;
    }

    private static char[] password(String value, String key) throws IOException
    {
        if (value == null || value.isEmpty())
            throw new IOException("missing required Vault key provider parameter: " + key);
        return value.toCharArray();
    }

    private static String trimSlashes(String value)
    {
        return value.replaceAll("^/+", "").replaceAll("/+$", "");
    }

    private static String encodePath(String path)
    {
        String[] parts = path.split("/");
        StringBuilder encoded = new StringBuilder(path.length());
        for (int i = 0; i < parts.length; i++)
        {
            if (i > 0)
                encoded.append('/');
            encoded.append(URLEncoder.encode(parts[i], StandardCharsets.UTF_8));
        }
        return encoded.toString();
    }
}

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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

import org.apache.cassandra.config.ParameterizedClass;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;

public class JKSKeyInlineBase64ProviderTest
{
    @Test
    public void getSecretKey_WithKeyPassword() throws Exception
    {
        TransparentDataEncryptionOptions tdeOptions = createInlineBase64EncryptionOptions("JCEKS",
                                                                                          EncryptionContextGenerator.KEY_ALIAS_1,
                                                                                          "store-password",
                                                                                          "key-password");
        JKSKeyInlineBase64Provider provider = new JKSKeyInlineBase64Provider(tdeOptions);

        Assert.assertNotNull(provider.getSecretKey(tdeOptions.key_alias));
    }

    @Test
    public void getSecretKey_WithoutKeyPassword() throws Exception
    {
        TransparentDataEncryptionOptions tdeOptions = createInlineBase64EncryptionOptions("JCEKS",
                                                                                          EncryptionContextGenerator.KEY_ALIAS_1,
                                                                                          "store-password",
                                                                                          null);
        JKSKeyInlineBase64Provider provider = new JKSKeyInlineBase64Provider(tdeOptions);

        Assert.assertNotNull(provider.getSecretKey(tdeOptions.key_alias));
    }

    @Test
    public void constructor_WithMalformedBase64_ThrowsRuntimeException()
    {
        TransparentDataEncryptionOptions tdeOptions = createInlineBase64EncryptionOptions("%%%");

        try
        {
            new JKSKeyInlineBase64Provider(tdeOptions);
            Assert.fail("Expected malformed inline keystore to fail");
        }
        catch (RuntimeException e)
        {
            Assert.assertEquals("couldn't load inline keystore", e.getMessage());
        }
    }

    @Test
    public void constructor_WithNonKeystoreBytes_ThrowsRuntimeException()
    {
        TransparentDataEncryptionOptions tdeOptions = createInlineBase64EncryptionOptions(Base64.getEncoder()
                                                                                                .encodeToString("not a keystore".getBytes(StandardCharsets.UTF_8)));

        try
        {
            new JKSKeyInlineBase64Provider(tdeOptions);
            Assert.fail("Expected non-keystore inline data to fail");
        }
        catch (RuntimeException e)
        {
            Assert.assertEquals("couldn't load inline keystore", e.getMessage());
        }
    }

    @Test
    public void getSecretKey_WithMissingAlias_ThrowsIOException() throws Exception
    {
        TransparentDataEncryptionOptions tdeOptions = createInlineBase64EncryptionOptions("JCEKS",
                                                                                          EncryptionContextGenerator.KEY_ALIAS_1,
                                                                                          "store-password",
                                                                                          null);
        JKSKeyInlineBase64Provider provider = new JKSKeyInlineBase64Provider(tdeOptions);

        try
        {
            provider.getSecretKey(EncryptionContextGenerator.KEY_ALIAS_2);
            Assert.fail("Expected missing alias to fail");
        }
        catch (IOException e)
        {
            Assert.assertEquals("key " + EncryptionContextGenerator.KEY_ALIAS_2 + " was not found in keystore", e.getMessage());
        }
    }

    @Test
    public void getSecretKey_WithPkcs12StoreType() throws Exception
    {
        TransparentDataEncryptionOptions tdeOptions = createInlineBase64EncryptionOptions("PKCS12",
                                                                                          EncryptionContextGenerator.KEY_ALIAS_1,
                                                                                          "store-password",
                                                                                          null);
        JKSKeyInlineBase64Provider provider = new JKSKeyInlineBase64Provider(tdeOptions);

        Assert.assertNotNull(provider.getSecretKey(tdeOptions.key_alias));
    }

    private TransparentDataEncryptionOptions createInlineBase64EncryptionOptions(String storeType,
                                                                                 String keyAlias,
                                                                                 String storePassword,
                                                                                 String keyPassword) throws Exception
    {
        Map<String, String> params = baseParams(storePassword);
        params.put(JKSKeyInlineBase64Provider.PROP_KEYSTORE, createBase64Keystore(storeType, keyAlias, storePassword, keyPassword));
        params.put(JKSKeyInlineBase64Provider.PROP_KEYSTORE_TYPE, storeType);
        if (keyPassword != null)
            params.put(JKSKeyInlineBase64Provider.PROP_KEY_PW, keyPassword);

        ParameterizedClass keyProvider = new ParameterizedClass(JKSKeyInlineBase64Provider.class.getName(), params);
        return new TransparentDataEncryptionOptions("AES/CBC/PKCS5Padding", keyAlias, keyProvider);
    }

    private TransparentDataEncryptionOptions createInlineBase64EncryptionOptions(String keystore)
    {
        Map<String, String> params = baseParams("store-password");
        params.put(JKSKeyInlineBase64Provider.PROP_KEYSTORE, keystore);
        params.put(JKSKeyInlineBase64Provider.PROP_KEYSTORE_TYPE, "JCEKS");

        ParameterizedClass keyProvider = new ParameterizedClass(JKSKeyInlineBase64Provider.class.getName(), params);
        return new TransparentDataEncryptionOptions("AES/CBC/PKCS5Padding", EncryptionContextGenerator.KEY_ALIAS_1, keyProvider);
    }

    private Map<String, String> baseParams(String storePassword)
    {
        Map<String, String> params = new HashMap<>();
        params.put(JKSKeyInlineBase64Provider.PROP_KEYSTORE_PW, storePassword);
        return params;
    }

    private String createBase64Keystore(String storeType, String keyAlias, String storePassword, String keyPassword) throws Exception
    {
        String entryPassword = keyPassword == null ? storePassword : keyPassword;
        KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(null, storePassword.toCharArray());
        keyStore.setEntry(keyAlias,
                          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
                          new KeyStore.PasswordProtection(entryPassword.toCharArray()));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, storePassword.toCharArray());
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }
}

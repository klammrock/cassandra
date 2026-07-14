/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.apache.cassandra.security;

import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.apache.cassandra.config.ParameterizedClass;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;

public class EncryptionContextGenerator
{
    public static final String KEY_ALIAS_1 = "testing:1";
    public static final String KEY_ALIAS_2 = "testing:2";
    private static final byte[] AES_256_KEY = new byte[32];

    static
    {
        Arrays.fill(AES_256_KEY, (byte) 0x5a);
    }

    public static EncryptionContext createContext(boolean init)
    {
        return createContext(null, init);
    }

    public static EncryptionContext createContext(byte[] iv, boolean init)
    {
        return new EncryptionContext(createEncryptionOptions(), iv, init);
    }

    public static TransparentDataEncryptionOptions createEncryptionOptions()
    {
        Map<String,String> params = new HashMap<>();
        params.put("keystore", "test/conf/cassandra.keystore");
        params.put("keystore_password", "cassandra");
        params.put("store_type", "JCEKS");
        ParameterizedClass keyProvider = new ParameterizedClass(JKSKeyProvider.class.getName(), params);

        return new TransparentDataEncryptionOptions("AES/CBC/PKCS5Padding", KEY_ALIAS_1, keyProvider);
    }

    public static TransparentDataEncryptionOptions createGCMEncryptionOptions()
    {
        ParameterizedClass keyProvider = new ParameterizedClass(StaticKeyProvider.class.getName(), new HashMap<>());
        TransparentDataEncryptionOptions options = new TransparentDataEncryptionOptions("AES/GCM/NoPadding", KEY_ALIAS_1, keyProvider);
        options.iv_length = 12;
        return options;
    }

    public static EncryptionContext createDisabledContext()
    {
        return new EncryptionContext();
    }

    public static class StaticKeyProvider implements KeyProvider
    {
        public StaticKeyProvider(TransparentDataEncryptionOptions options)
        {
        }

        public Key getSecretKey(String keyAlias) throws IOException
        {
            return new SecretKeySpec(AES_256_KEY, "AES");
        }
    }
}

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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;

import org.apache.cassandra.config.TransparentDataEncryptionOptions;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.io.compress.ICompressor;
import org.apache.cassandra.io.compress.LZ4Compressor;
import org.apache.cassandra.utils.Hex;

/**
 * A (largely) immutable wrapper for the application-wide file-level encryption settings.
 */
public class EncryptionContext
{
    public static final String ENCRYPTION_CIPHER = "encCipher";
    public static final String ENCRYPTION_KEY_ALIAS = "encKeyAlias";
    public static final String ENCRYPTION_IV = "encIV";
    public static final String ENCRYPTION_IV_LENGTH = "encIVLength";
    public static final int GCM_IV_LENGTH = 12;

    private final TransparentDataEncryptionOptions tdeOptions;
    private final ICompressor compressor;
    private final CipherFactory cipherFactory;

    private final byte[] iv;
    private final int chunkLength;
    private final boolean perBlockIV;

    public EncryptionContext()
    {
        this(new TransparentDataEncryptionOptions());
    }

    public EncryptionContext(TransparentDataEncryptionOptions tdeOptions)
    {
        this(tdeOptions, null, true);
    }

    @VisibleForTesting
    public EncryptionContext(TransparentDataEncryptionOptions tdeOptions, byte[] iv, boolean init)
    {
        validate(tdeOptions);
        this.tdeOptions = tdeOptions;
        compressor = LZ4Compressor.create(Collections.<String, String>emptyMap());
        chunkLength = tdeOptions.chunk_length_kb * 1024;
        this.iv = iv;
        perBlockIV = isAEAD(tdeOptions.cipher);

        // always attempt to load the cipher factory, as we could be in the situation where the user has disabled encryption,
        // but has existing commitlogs and sstables on disk that are still encrypted (and still need to be read)
        CipherFactory factory = null;

        if (tdeOptions.enabled && init)
        {
            try
            {
                factory = new CipherFactory(tdeOptions);
            }
            catch (Exception e)
            {
                throw new ConfigurationException("failed to load key provider for transparent data encryption", e);
            }
        }

        cipherFactory = factory;
    }

    public ICompressor getCompressor()
    {
        return compressor;
    }

    public Cipher getEncryptor() throws IOException
    {
        validateCipherForNewEncryptedData(tdeOptions.cipher);
        return cipherFactory.getEncryptor(tdeOptions.cipher, tdeOptions.key_alias);
    }

    public Cipher getDecryptor() throws IOException
    {
        if (iv == null || iv.length == 0)
            throw new IllegalStateException("no initialization vector (IV) found in this context");
        return getDecryptor(iv);
    }

    public Cipher getDecryptor(byte[] iv) throws IOException
    {
        if (iv == null || iv.length == 0)
            throw new IllegalStateException("no initialization vector (IV) found in this context");
        return cipherFactory.getDecryptor(tdeOptions.cipher, tdeOptions.key_alias, iv);
    }

    public boolean isEnabled()
    {
        return tdeOptions.enabled;
    }

    public int getChunkLength()
    {
        return chunkLength;
    }

    public int getIVLength()
    {
        return tdeOptions.iv_length;
    }

    public byte[] getIV()
    {
        return iv;
    }

    public boolean usesPerBlockIV()
    {
        return perBlockIV;
    }

    /**
     * @return true if the cipher transformation uses an AEAD mode that requires a {@link GCMParameterSpec} (rather than
     * a plain {@link IvParameterSpec}) and a unique IV for every encryption operation. Currently only GCM.
     */
    public static boolean isAEAD(String transformation)
    {
        // isGCMCipher
        return transformation != null && transformation.toUpperCase(Locale.ROOT).contains("/GCM/");
    }

    public static boolean isCBCCipher(String transformation)
    {
        return transformation != null && transformation.toUpperCase(Locale.ROOT).contains("/CBC/");
    }

    public static void validateForNewEncryptedData(TransparentDataEncryptionOptions tdeOptions)
    {
        validate(tdeOptions);
        if (tdeOptions.enabled)
            validateCipherForNewEncryptedData(tdeOptions.cipher);
    }

    public TransparentDataEncryptionOptions getTransparentDataEncryptionOptions()
    {
        return tdeOptions;
    }

    public boolean equals(Object o)
    {
        return o instanceof EncryptionContext && equals((EncryptionContext) o);
    }

    public boolean equals(EncryptionContext other)
    {
        return Objects.equal(tdeOptions, other.tdeOptions)
               && Objects.equal(compressor, other.compressor)
               && Arrays.equals(iv, other.iv);
    }

    public Map<String, String> toHeaderParameters()
    {
        Map<String, String> map = new HashMap<>(4);
        // add compression options, someday ...
        if (tdeOptions.enabled)
        {
            map.put(ENCRYPTION_CIPHER, tdeOptions.cipher);
            map.put(ENCRYPTION_KEY_ALIAS, tdeOptions.key_alias);
            map.put(ENCRYPTION_IV_LENGTH, Integer.toString(tdeOptions.iv_length));

            if (iv != null && iv.length > 0)
                map.put(ENCRYPTION_IV, Hex.bytesToHex(iv));
        }
        return map;
    }

    /**
     * If encryption headers are found in the {@code parameters},
     * those headers are merged with the application-wide {@code encryptionContext}.
     */
    public static EncryptionContext createFromMap(Map<?, ?> parameters, EncryptionContext encryptionContext)
    {
        if (parameters == null || parameters.isEmpty())
            return new EncryptionContext(new TransparentDataEncryptionOptions(false));

        String keyAlias = (String)parameters.get(ENCRYPTION_KEY_ALIAS);
        String cipher = (String)parameters.get(ENCRYPTION_CIPHER);
        String ivString = (String)parameters.get(ENCRYPTION_IV);
        if (keyAlias == null || cipher == null)
            return new EncryptionContext(new TransparentDataEncryptionOptions(false));

        TransparentDataEncryptionOptions tdeOptions = new TransparentDataEncryptionOptions(cipher, keyAlias, encryptionContext.getTransparentDataEncryptionOptions().key_provider);
        tdeOptions.iv_length = parseIVLength(parameters.get(ENCRYPTION_IV_LENGTH), encryptionContext, cipher);
        byte[] iv = ivString != null ? Hex.hexToBytes(ivString) : null;
        return new EncryptionContext(tdeOptions, iv, true);
    }

    private static void validate(TransparentDataEncryptionOptions tdeOptions)
    {
        if (tdeOptions.enabled && isAEAD(tdeOptions.cipher) && tdeOptions.iv_length != GCM_IV_LENGTH)
            throw new ConfigurationException("transparent data encryption with AES/GCM/NoPadding requires iv_length: " + GCM_IV_LENGTH);
    }

    private static void validateCipherForNewEncryptedData(String cipher)
    {
        if (isCBCCipher(cipher))
            throw new ConfigurationException("transparent data encryption with CBC ciphers is only supported for reading existing encrypted files; use AES/GCM/NoPadding for new encrypted data");
    }

    private static int parseIVLength(Object value, EncryptionContext encryptionContext, String cipher)
    {
        if (value == null)
            return isAEAD(cipher) ? GCM_IV_LENGTH : encryptionContext.getTransparentDataEncryptionOptions().iv_length;

        if (value instanceof Number)
            return ((Number) value).intValue();

        return Integer.parseInt(value.toString());
    }
}

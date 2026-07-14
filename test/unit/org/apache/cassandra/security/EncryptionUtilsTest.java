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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.apache.cassandra.io.util.File;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.io.compress.ICompressor;
import org.apache.cassandra.io.compress.LZ4Compressor;
import org.apache.cassandra.io.util.FileUtils;
import org.apache.cassandra.io.util.RandomAccessReader;

public class EncryptionUtilsTest
{
    @BeforeClass
    public static void initDD()
    {
        DatabaseDescriptor.daemonInitialization();
    }

    final Random random = new Random();
    ICompressor compressor;
    TransparentDataEncryptionOptions tdeOptions;

    @Before
    public void setup()
    {
        compressor = LZ4Compressor.create(new HashMap<>());
        tdeOptions = EncryptionContextGenerator.createEncryptionOptions();
    }

    @Test
    public void compress() throws IOException
    {
        byte[] buf = new byte[(1 << 13) - 13];
        random.nextBytes(buf);
        ByteBuffer compressedBuffer = EncryptionUtils.compress(ByteBuffer.wrap(buf), ByteBuffer.allocate(0), true, compressor);
        ByteBuffer uncompressedBuffer = EncryptionUtils.uncompress(compressedBuffer, ByteBuffer.allocate(0), true, compressor);
        Assert.assertArrayEquals(buf, uncompressedBuffer.array());
    }

    @Test
    public void encrypt() throws BadPaddingException, ShortBufferException, IllegalBlockSizeException, IOException
    {
        byte[] buf = new byte[(1 << 12) - 7];
        random.nextBytes(buf);

        // encrypt
        CipherFactory cipherFactory = new CipherFactory(tdeOptions);
        Cipher encryptor = cipherFactory.getEncryptor(tdeOptions.cipher, tdeOptions.key_alias);

        File f = FileUtils.createTempFile("commitlog-enc-utils-", ".tmp");
        f.deleteOnExit();
        FileChannel channel = f.newReadWriteChannel();
        EncryptionUtils.encryptAndWrite(ByteBuffer.wrap(buf), channel, true, encryptor);
        channel.close();

        // decrypt
        Cipher decryptor = cipherFactory.getDecryptor(tdeOptions.cipher, tdeOptions.key_alias, encryptor.getIV());
        ByteBuffer decryptedBuffer = EncryptionUtils.decrypt(RandomAccessReader.open(f), ByteBuffer.allocate(0), true, decryptor);

        // normally, we'd just call BB.array(), but that gives you the *entire* backing array, not with any of the offsets (position,limit) applied.
        // thus, just for this test, we copy the array and perform an array-level comparison with those offsets
        decryptedBuffer.limit(buf.length);
        byte[] b = new byte[buf.length];
        System.arraycopy(decryptedBuffer.array(), 0, b, 0, buf.length);
        Assert.assertArrayEquals(buf, b);
    }

    @Test
    public void fullRoundTrip() throws IOException, BadPaddingException, ShortBufferException, IllegalBlockSizeException
    {
        // compress
        byte[] buf = new byte[(1 << 12) - 7];
        random.nextBytes(buf);
        ByteBuffer compressedBuffer = EncryptionUtils.compress(ByteBuffer.wrap(buf), ByteBuffer.allocate(0), true, compressor);

        // encrypt
        CipherFactory cipherFactory = new CipherFactory(tdeOptions);
        Cipher encryptor = cipherFactory.getEncryptor(tdeOptions.cipher, tdeOptions.key_alias);
        File f = FileUtils.createTempFile("commitlog-enc-utils-", ".tmp");
        f.deleteOnExit();
        FileChannel channel = f.newReadWriteChannel();
        EncryptionUtils.encryptAndWrite(compressedBuffer, channel, true, encryptor);

        // decrypt
        Cipher decryptor = cipherFactory.getDecryptor(tdeOptions.cipher, tdeOptions.key_alias, encryptor.getIV());
        ByteBuffer decryptedBuffer = EncryptionUtils.decrypt(RandomAccessReader.open(f), ByteBuffer.allocate(0), true, decryptor);

        // uncompress
        ByteBuffer uncompressedBuffer = EncryptionUtils.uncompress(decryptedBuffer, ByteBuffer.allocate(0), true, compressor);
        Assert.assertArrayEquals(buf, uncompressedBuffer.array());
    }

    @Test
    public void gcmFullRoundTripWithMultipleBlocks() throws IOException
    {
        EncryptionContext encryptionContext = new EncryptionContext(EncryptionContextGenerator.createGCMEncryptionOptions());
        byte[][] buffers = new byte[3][];
        File f = FileUtils.createTempFile("commitlog-gcm-enc-utils-", ".tmp");
        f.deleteOnExit();

        try (FileChannel channel = f.newReadWriteChannel())
        {
            for (int ii = 0; ii < buffers.length; ii++)
            {
                buffers[ii] = new byte[(1 << 12) + ii];
                random.nextBytes(buffers[ii]);
                ByteBuffer compressedBuffer = EncryptionUtils.compress(ByteBuffer.wrap(buffers[ii]), ByteBuffer.allocate(0), true, compressor);
                EncryptionUtils.encryptAndWrite(compressedBuffer, channel, true, encryptionContext);
            }
        }

        try (RandomAccessReader reader = RandomAccessReader.open(f))
        {
            for (byte[] buf : buffers)
            {
                ByteBuffer decryptedBuffer = EncryptionUtils.decrypt(reader, ByteBuffer.allocate(0), true, encryptionContext);
                ByteBuffer uncompressedBuffer = EncryptionUtils.uncompress(decryptedBuffer, ByteBuffer.allocate(0), true, compressor);
                byte[] roundTripped = new byte[buf.length];
                System.arraycopy(uncompressedBuffer.array(), 0, roundTripped, 0, buf.length);
                Assert.assertArrayEquals(buf, roundTripped);
            }
        }
    }

    @Test
    public void gcmDecryptAccumulatesCipherTextAcrossShortReads() throws IOException
    {
        EncryptionContext encryptionContext = new EncryptionContext(EncryptionContextGenerator.createGCMEncryptionOptions());
        byte[] buf = new byte[(1 << 12) - 7];
        random.nextBytes(buf);
        ByteBuffer compressedBuffer = EncryptionUtils.compress(ByteBuffer.wrap(buf), ByteBuffer.allocate(0), true, compressor);

        File f = FileUtils.createTempFile("commitlog-gcm-short-read-", ".tmp");
        f.deleteOnExit();
        try (FileChannel channel = f.newReadWriteChannel())
        {
            EncryptionUtils.encryptAndWrite(compressedBuffer, channel, true, encryptionContext);
        }

        byte[] encrypted = Files.readAllBytes(f.toPath());
        ByteBuffer decryptedBuffer = EncryptionUtils.decrypt(dribblingChannel(encrypted, 3), ByteBuffer.allocate(0), true, encryptionContext);
        ByteBuffer uncompressedBuffer = EncryptionUtils.uncompress(decryptedBuffer, ByteBuffer.allocate(0), true, compressor);
        byte[] roundTripped = new byte[buf.length];
        System.arraycopy(uncompressedBuffer.array(), 0, roundTripped, 0, buf.length);
        Assert.assertArrayEquals(buf, roundTripped);
    }

    @Test(expected = IOException.class)
    public void gcmTamperedCipherTextThrowsIOException() throws IOException
    {
        assertGcmTamperFails(file -> file.length() - 1);
    }

    @Test(expected = IOException.class)
    public void gcmTamperedIVThrowsIOException() throws IOException
    {
        assertGcmTamperFails(file -> EncryptionUtils.ENCRYPTED_BLOCK_HEADER_SIZE + 4);
    }

    @Test(expected = IOException.class)
    public void gcmTamperedPlainTextLengthThrowsIOException() throws IOException
    {
        assertGcmTamperFails(file -> 7);
    }

    @Test(expected = IOException.class)
    public void gcmCorruptEncryptedLengthThrowsIOException() throws IOException
    {
        assertGcmTamperFails((channel, file) -> overwriteInt(channel, 0, Integer.MAX_VALUE));
    }

    @Test(expected = IOException.class)
    public void gcmTruncatedCipherTextThrowsIOException() throws IOException
    {
        assertGcmTamperFails((channel, file) -> channel.truncate(channel.size() - 1));
    }

    private void assertGcmTamperFails(TamperOffset tamperOffset) throws IOException
    {
        assertGcmTamperFails((channel, file) -> flipByte(channel, tamperOffset.get(file)));
    }

    private void assertGcmTamperFails(BlockTamper tamper) throws IOException
    {
        EncryptionContext encryptionContext = new EncryptionContext(EncryptionContextGenerator.createGCMEncryptionOptions());
        byte[] buf = new byte[(1 << 12) - 7];
        random.nextBytes(buf);
        ByteBuffer compressedBuffer = EncryptionUtils.compress(ByteBuffer.wrap(buf), ByteBuffer.allocate(0), true, compressor);

        File f = FileUtils.createTempFile("commitlog-gcm-tampered-", ".tmp");
        f.deleteOnExit();
        try (FileChannel channel = f.newReadWriteChannel())
        {
            EncryptionUtils.encryptAndWrite(compressedBuffer, channel, true, encryptionContext);
            tamper.apply(channel, f);
        }

        try (RandomAccessReader reader = RandomAccessReader.open(f))
        {
            EncryptionUtils.decrypt(reader, ByteBuffer.allocate(0), true, encryptionContext);
        }
    }

    private static void flipByte(FileChannel channel, long offset) throws IOException
    {
        channel.position(offset);
        ByteBuffer oneByte = ByteBuffer.allocate(1);
        channel.read(oneByte);
        oneByte.flip();
        oneByte.put(0, (byte) (oneByte.get(0) ^ 0x01));
        oneByte.position(0);
        channel.position(offset);
        channel.write(oneByte);
    }

    private static void overwriteInt(FileChannel channel, long offset, int value) throws IOException
    {
        ByteBuffer bytes = ByteBuffer.allocate(4);
        bytes.putInt(value);
        bytes.flip();
        channel.position(offset);
        channel.write(bytes);
    }

    private interface TamperOffset
    {
        long get(File file);
    }

    private interface BlockTamper
    {
        void apply(FileChannel channel, File file) throws IOException;
    }

    @Test
    public void readFullyAccumulatesAcrossShortReads() throws IOException
    {
        byte[] expected = new byte[37];
        random.nextBytes(expected);

        Assert.assertArrayEquals(expected, EncryptionUtils.readFully(dribblingChannel(expected, 1), expected.length));
        Assert.assertArrayEquals(expected, EncryptionUtils.readFully(dribblingChannel(expected, 3), expected.length));
    }

    @Test(expected = IOException.class)
    public void readFullyThrowsOnPrematureEof() throws IOException
    {
        byte[] expected = new byte[5];
        random.nextBytes(expected);

        EncryptionUtils.readFully(dribblingChannel(expected, 1), expected.length + 1);
    }

    @Test(expected = ConfigurationException.class)
    public void gcmRequiresStandardIVLength()
    {
        TransparentDataEncryptionOptions options = EncryptionContextGenerator.createGCMEncryptionOptions();
        options.iv_length = 16;

        new EncryptionContext(options);
    }

    @Test
    public void gcmReconstructedContextDefaultsToStandardIVLength()
    {
        EncryptionContext encryptionContext = new EncryptionContext(EncryptionContextGenerator.createGCMEncryptionOptions());
        Map<String, String> params = new HashMap<>();
        params.put(EncryptionContext.ENCRYPTION_CIPHER, "AES/GCM/NoPadding");
        params.put(EncryptionContext.ENCRYPTION_KEY_ALIAS, EncryptionContextGenerator.KEY_ALIAS_1);

        EncryptionContext reconstructed = EncryptionContext.createFromMap(params, encryptionContext);
        Assert.assertEquals(EncryptionContext.GCM_IV_LENGTH, reconstructed.getIVLength());
    }

    private static ReadableByteChannel dribblingChannel(byte[] data, int maxPerRead)
    {
        return new ReadableByteChannel()
        {
            private int position;

            public int read(ByteBuffer dst)
            {
                if (position >= data.length)
                    return -1;
                int read = Math.min(Math.min(maxPerRead, dst.remaining()), data.length - position);
                dst.put(data, position, read);
                dst.flip();
                position += read;
                return read;
            }

            public boolean isOpen()
            {
                return true;
            }

            public void close()
            {
            }
        };
    }
}

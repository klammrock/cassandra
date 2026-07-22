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
package org.apache.cassandra.hints;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.zip.CRC32;
import javax.crypto.Cipher;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.Files;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;
import org.apache.cassandra.db.partitions.PartitionUpdate;
import org.apache.cassandra.io.util.DataOutputBuffer;
import org.apache.cassandra.io.util.DataOutputPlus;
import org.apache.cassandra.io.util.File;
import org.apache.cassandra.security.CipherFactory;
import org.apache.cassandra.security.EncryptionContext;
import org.apache.cassandra.security.EncryptionContextGenerator;
import org.apache.cassandra.security.EncryptionUtils;
import org.apache.cassandra.utils.Hex;

import static org.apache.cassandra.utils.FBUtilities.updateChecksum;
import static org.apache.cassandra.utils.FBUtilities.updateChecksumInt;

public class HintsEncryptionTest extends AlteredHints
{
    EncryptionContext encryptionContext;

    @Before
    public void setup()
    {
        encryptionContext = new EncryptionContext(EncryptionContextGenerator.createGCMEncryptionOptions());
        DatabaseDescriptor.setEncryptionContext(encryptionContext);
    }

    @Test
    public void encryptedHints() throws Exception
    {
        multiFlushAndDeserializeTest();
    }

    @Test
    public void readsExistingCBCEncryptedHints() throws Exception
    {
        TransparentDataEncryptionOptions cbcOptions = EncryptionContextGenerator.createEncryptionOptions();
        EncryptionContext cbcContext = new EncryptionContext(cbcOptions);
        DatabaseDescriptor.setEncryptionContext(cbcContext);

        Cipher encryptor = new CipherFactory(cbcOptions).getEncryptor(cbcOptions.cipher, cbcOptions.key_alias);
        ImmutableMap<String, Object> encryptionParams = ImmutableMap.<String, Object>builder()
                                                                    .put(EncryptionContext.ENCRYPTION_CIPHER, cbcOptions.cipher)
                                                                    .put(EncryptionContext.ENCRYPTION_KEY_ALIAS, cbcOptions.key_alias)
                                                                    .put(EncryptionContext.ENCRYPTION_IV_LENGTH, cbcOptions.iv_length)
                                                                    .put(EncryptionContext.ENCRYPTION_IV, Hex.bytesToHex(encryptor.getIV()))
                                                                    .build();

        HintsDescriptor descriptor = new HintsDescriptor(UUID.randomUUID(),
                                                         System.currentTimeMillis(),
                                                         ImmutableMap.<String, Object>of(HintsDescriptor.ENCRYPTION, encryptionParams));
        List<Hint> hints = new ArrayList<>();
        long timestamp = System.currentTimeMillis();
        for (int i = 0; i < 5; i++)
            hints.add(createHint(i, timestamp + i));

        File directory = new File(Files.createTempDir());
        writeCBCEncryptedHints(directory, descriptor, cbcContext, encryptor, hints);

        try (HintsReader reader = HintsReader.open(descriptor.file(directory)))
        {
            Assert.assertTrue(reader.getInput() instanceof EncryptedChecksummedDataInput);
            EncryptedChecksummedDataInput encryptedInput = (EncryptedChecksummedDataInput) reader.getInput();
            Assert.assertNotNull(encryptedInput.getCipher());
            Assert.assertFalse(descriptor.getEncryptionContext().usesPerBlockIV());

            List<Hint> deserialized = new ArrayList<>();
            for (HintsReader.Page page : reader)
            {
                Iterator<Hint> iterator = page.hintsIterator();
                while (iterator.hasNext())
                    deserialized.add(iterator.next());
            }

            Assert.assertEquals(hints.size(), deserialized.size());
            for (int i = 0; i < hints.size(); i++)
                HintsTestUtil.assertHintsEqual(hints.get(i), deserialized.get(i));
        }
    }

    boolean looksLegit(HintsWriter writer)
    {
        if (!(writer instanceof EncryptedHintsWriter))
            return false;

        EncryptedHintsWriter encryptedHintsWriter = (EncryptedHintsWriter)writer;
        return encryptedHintsWriter.getCipher() == null &&
               encryptionContext.getCompressor().getClass().isInstance(encryptedHintsWriter.getCompressor());
    }

    boolean looksLegit(ChecksummedDataInput checksummedDataInput)
    {
        if (!(checksummedDataInput instanceof EncryptedChecksummedDataInput))
            return false;

        EncryptedChecksummedDataInput encryptedDataInput = (EncryptedChecksummedDataInput)checksummedDataInput;

        return encryptedDataInput.getCipher() == null &&
               encryptionContext.getCompressor().getClass().isInstance(encryptedDataInput.getCompressor());
    }

    ImmutableMap<String, Object> params()
    {
        ImmutableMap<String, Object> compressionParams = ImmutableMap.<String, Object>builder()
                                                         .putAll(encryptionContext.toHeaderParameters())
                                                         .build();
        return ImmutableMap.<String, Object>builder()
               .put(HintsDescriptor.ENCRYPTION, compressionParams)
               .build();
    }

    private static void writeCBCEncryptedHints(File directory, HintsDescriptor descriptor, EncryptionContext context, Cipher encryptor, List<Hint> hints) throws IOException
    {
        try (FileChannel channel = FileChannel.open(descriptor.file(directory).toPath(), StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
             DataOutputBuffer descriptorBuffer = DataOutputBuffer.scratchBuffer.get())
        {
            descriptor.serialize(descriptorBuffer);
            channel.write(descriptorBuffer.unsafeGetBufferAndFlip());

            ByteBuffer plain = ByteBuffer.allocate(HintsWriteExecutor.WRITE_BUFFER_SIZE);
            for (Hint hint : hints)
                appendSerializedHint(plain, hint, descriptor.messagingVersion());

            plain.flip();
            ByteBuffer compressed = EncryptionUtils.compress(plain, ByteBuffer.allocate(0), true, context.getCompressor());
            EncryptionUtils.encryptAndWrite(compressed, channel, true, encryptor);
        }
    }

    private static void appendSerializedHint(ByteBuffer buffer, Hint hint, int messagingVersion) throws IOException
    {
        try (DataOutputBuffer hintOutput = new DataOutputBuffer())
        {
            serializeHintForLegacyCBCFixture(hint, hintOutput, messagingVersion);

            ByteBuffer serializedHint = hintOutput.buffer();
            int hintSize = serializedHint.remaining();
            CRC32 crc = new CRC32();
            buffer.putInt(hintSize);
            updateChecksumInt(crc, hintSize);
            buffer.putInt((int) crc.getValue());

            int hintStart = buffer.position();
            buffer.put(serializedHint);
            updateChecksum(crc, buffer, hintStart, hintSize);
            buffer.putInt((int) crc.getValue());
        }
    }

    private static void serializeHintForLegacyCBCFixture(Hint hint, DataOutputPlus out, int messagingVersion) throws IOException
    {
        out.writeLong(hint.creationTime);
        out.writeUnsignedVInt32(hint.gcgs);
        out.writeUnsignedVInt32(hint.mutation.getPartitionUpdates().size());
        for (PartitionUpdate partitionUpdate : hint.mutation.getPartitionUpdates())
            PartitionUpdate.serializer.serialize(partitionUpdate, out, messagingVersion);
    }
}

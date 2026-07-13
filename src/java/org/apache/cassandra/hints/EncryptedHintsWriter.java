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
import java.util.zip.CRC32;
import javax.annotation.Nullable;
import javax.crypto.Cipher;

import com.google.common.annotations.VisibleForTesting;

import org.apache.cassandra.io.compress.ICompressor;
import org.apache.cassandra.io.util.File;
import org.apache.cassandra.security.EncryptionContext;
import org.apache.cassandra.security.EncryptionUtils;

import static org.apache.cassandra.utils.FBUtilities.updateChecksum;

public class EncryptedHintsWriter extends HintsWriter
{
    @Nullable
    private final Cipher cipher;
    private final ICompressor compressor;
    private final EncryptionContext encryptionContext;
    private volatile ByteBuffer byteBuffer;

    protected EncryptedHintsWriter(File directory, HintsDescriptor descriptor, File file, FileChannel channel, int fd, CRC32 globalCRC)
    {
        super(directory, descriptor, file, channel, fd, globalCRC);
        cipher = descriptor.getCipher();
        compressor = descriptor.createCompressor();
        encryptionContext = descriptor.getEncryptionContext();
        if (cipher == null && !encryptionContext.usesPerBlockIV())
            throw new IllegalStateException("cipher must not be null for non-GCM encrypted hints");
        if (compressor == null)
            throw new IllegalStateException("compressor must not be null for encrypted hints");
    }

    protected void writeBuffer(ByteBuffer input) throws IOException
    {
        byteBuffer = EncryptionUtils.compress(input, byteBuffer, true, compressor);
        if (encryptionContext.usesPerBlockIV())
            EncryptionUtils.encryptAndWrite(byteBuffer, channel, true, encryptionContext, globalCRC);
        else
            updateChecksum(globalCRC, EncryptionUtils.encryptAndWrite(byteBuffer, channel, true, cipher));
    }

    @VisibleForTesting
    Cipher getCipher()
    {
        return cipher;
    }

    @VisibleForTesting
    ICompressor getCompressor()
    {
        return compressor;
    }
}

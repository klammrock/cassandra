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
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;

import io.netty.util.concurrent.FastThreadLocal;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.db.commitlog.EncryptedSegment;
import org.apache.cassandra.io.compress.ICompressor;
import org.apache.cassandra.io.util.ChannelProxy;
import org.apache.cassandra.io.util.FileDataInput;
import org.apache.cassandra.utils.ByteBufferUtil;

import static org.apache.cassandra.utils.FBUtilities.updateChecksum;

/**
 * Encryption and decryption functions specific to the commit log.
 * See comments in {@link EncryptedSegment} for details on the binary format.
 * The normal, and expected, invocation pattern is to compress then encrypt the data on the encryption pass,
 * then decrypt and uncompress the data on the decrypt pass.
 */
public class EncryptionUtils
{
    public static final int COMPRESSED_BLOCK_HEADER_SIZE = 4;
    public static final int ENCRYPTED_BLOCK_HEADER_SIZE = 8;
    private static final int ENCRYPTED_BLOCK_IV_LENGTH_SIZE = 4;
    private static final int MAX_ENCRYPTED_BLOCK_IV_LENGTH = 256;

    private static final FastThreadLocal<ByteBuffer> reusableBuffers = new FastThreadLocal<ByteBuffer>()
    {
        protected ByteBuffer initialValue()
        {
            return ByteBuffer.allocate(ENCRYPTED_BLOCK_HEADER_SIZE);
        }
    };

    /**
     * Compress the raw data, as well as manage sizing of the {@code outputBuffer}; if the buffer is not big enough,
     * deallocate current, and allocate a large enough buffer.
     * Write the two header lengths (plain text length, compressed length) to the beginning of the buffer as we want those
     * values encapsulated in the encrypted block, as well.
     *
     * @return the byte buffer that was actaully written to; it may be the {@code outputBuffer} if it had enough capacity,
     * or it may be a new, larger instance. Callers should capture the return buffer (if calling multiple times).
     */
    public static ByteBuffer compress(ByteBuffer inputBuffer, ByteBuffer outputBuffer, boolean allowBufferResize, ICompressor compressor) throws IOException
    {
        int inputLength = inputBuffer.remaining();
        final int compressedLength = compressor.initialCompressedBufferLength(inputLength);
        outputBuffer = ByteBufferUtil.ensureCapacity(outputBuffer, compressedLength + COMPRESSED_BLOCK_HEADER_SIZE, allowBufferResize);

        outputBuffer.putInt(inputLength);
        compressor.compress(inputBuffer, outputBuffer);
        outputBuffer.flip();

        return outputBuffer;
    }

    /**
     * Encrypt the input data, and writes out to the same input buffer; if the buffer is not big enough,
     * deallocate current, and allocate a large enough buffer.
     * Writes the cipher text and headers out to the channel, as well.
     *
     * Note: channel is a parameter as we cannot write header info to the output buffer as we assume the input and output
     * buffers can be the same buffer (and writing the headers to a shared buffer will corrupt any input data). Hence,
     * we write out the headers directly to the channel, and then the cipher text (once encrypted).
     */
    public static ByteBuffer encryptAndWrite(ByteBuffer inputBuffer, WritableByteChannel channel, boolean allowBufferResize, Cipher cipher) throws IOException
    {
        return encryptAndWrite(inputBuffer, channel, allowBufferResize, cipher, false, null);
    }

    public static ByteBuffer encryptAndWrite(ByteBuffer inputBuffer, WritableByteChannel channel, boolean allowBufferResize, EncryptionContext encryptionContext) throws IOException
    {
        return encryptAndWrite(inputBuffer, channel, allowBufferResize, encryptionContext.getEncryptor(), encryptionContext.usesPerBlockIV(), null);
    }

    private static ByteBuffer encryptAndWrite(ByteBuffer inputBuffer, WritableByteChannel channel, boolean allowBufferResize, Cipher cipher, boolean writeIV, CRC32 crc) throws IOException
    {
        final int plainTextLength = inputBuffer.remaining();
        final int encryptLength = cipher.getOutputSize(plainTextLength);
        ByteBuffer outputBuffer = inputBuffer.duplicate();
        outputBuffer = ByteBufferUtil.ensureCapacity(outputBuffer, encryptLength, allowBufferResize);

        // it's unfortunate that we need to allocate a small buffer here just for the headers, but if we reuse the input buffer
        // for the output, then we would overwrite the first n bytes of the real data with the header data.
        byte[] iv = writeIV ? cipher.getIV() : null;
        ByteBuffer headerBuffer = ByteBuffer.allocate(encryptedBlockHeaderSize(iv));
        headerBuffer.putInt(encryptLength);
        headerBuffer.putInt(plainTextLength);
        if (writeIV)
        {
            headerBuffer.putInt(iv.length);
            headerBuffer.put(iv);
        }
        headerBuffer.flip();
        if (writeIV)
            cipher.updateAAD(headerBuffer.duplicate());
        if (crc != null)
            updateChecksum(crc, headerBuffer);
        channel.write(headerBuffer);

        try
        {
            cipher.doFinal(inputBuffer, outputBuffer);
        }
        catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e)
        {
            throw new IOException("failed to encrypt commit log block", e);
        }

        outputBuffer.position(0).limit(encryptLength);
        if (crc != null)
            updateChecksum(crc, outputBuffer);
        channel.write(outputBuffer);
        outputBuffer.position(0).limit(encryptLength);

        return outputBuffer;
    }

    public static ByteBuffer encrypt(ByteBuffer inputBuffer, ByteBuffer outputBuffer, boolean allowBufferResize, Cipher cipher) throws IOException
    {
        Preconditions.checkNotNull(outputBuffer, "output buffer may not be null");
        return encryptAndWrite(inputBuffer, new ChannelAdapter(outputBuffer), allowBufferResize, cipher);
    }

    public static ByteBuffer decrypt(ReadableByteChannel channel, ByteBuffer outputBuffer, boolean allowBufferResize, EncryptionContext encryptionContext) throws IOException
    {
        return decrypt(channel, outputBuffer, allowBufferResize, null, encryptionContext);
    }

    /**
     * Decrypt the input data, as well as manage sizing of the {@code outputBuffer}; if the buffer is not big enough,
     * deallocate current, and allocate a large enough buffer.
     *
     * @return the byte buffer that was actaully written to; it may be the {@code outputBuffer} if it had enough capacity,
     * or it may be a new, larger instance. Callers should capture the return buffer (if calling multiple times).
     */
    public static ByteBuffer decrypt(ReadableByteChannel channel, ByteBuffer outputBuffer, boolean allowBufferResize, Cipher cipher) throws IOException
    {
        return decrypt(channel, outputBuffer, allowBufferResize, cipher, null);
    }

    private static ByteBuffer decrypt(ReadableByteChannel channel, ByteBuffer outputBuffer, boolean allowBufferResize, Cipher cipher, EncryptionContext encryptionContext) throws IOException
    {
        ByteBuffer metadataBuffer = ByteBuffer.wrap(readFully(channel, ENCRYPTED_BLOCK_HEADER_SIZE));
        int encryptedLength = metadataBuffer.getInt();
        // this is the length of the compressed data
        int plainTextLength = metadataBuffer.getInt();
        validateEncryptedBlockLengths(encryptedLength, plainTextLength);
        ByteBuffer aad = null;
        if (encryptionContext != null)
        {
            if (encryptionContext.usesPerBlockIV())
            {
                int ivLength = ByteBuffer.wrap(readFully(channel, ENCRYPTED_BLOCK_IV_LENGTH_SIZE)).getInt();
                if (ivLength <= 0 || ivLength > MAX_ENCRYPTED_BLOCK_IV_LENGTH)
                    throw new IOException("invalid encrypted block IV length: " + ivLength);
                byte[] iv = readFully(channel, ivLength);
                cipher = encryptionContext.getDecryptor(iv);
                aad = ByteBuffer.allocate(encryptedBlockHeaderSize(iv));
                aad.putInt(encryptedLength);
                aad.putInt(plainTextLength);
                aad.putInt(ivLength);
                aad.put(iv);
                aad.flip();
            }
            else
            {
                cipher = encryptionContext.getDecryptor();
            }
        }

        outputBuffer = ByteBufferUtil.ensureCapacity(outputBuffer, Math.max(plainTextLength, encryptedLength), allowBufferResize);
        outputBuffer.position(0).limit(encryptedLength);
        readFully(channel, outputBuffer);

        ByteBuffer dupe = outputBuffer.duplicate();
        dupe.clear();

        try
        {
            if (aad != null)
                cipher.updateAAD(aad);
            cipher.doFinal(outputBuffer, dupe);
        }
        catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e)
        {
            throw new IOException("failed to decrypt commit log block", e);
        }

        dupe.position(0).limit(plainTextLength);
        return dupe;
    }

    // path used when decrypting commit log files
    public static ByteBuffer decrypt(FileDataInput fileDataInput, ByteBuffer outputBuffer, boolean allowBufferResize, Cipher cipher) throws IOException
    {
        return decrypt(new DataInputReadChannel(fileDataInput), outputBuffer, allowBufferResize, cipher);
    }

    public static ByteBuffer decrypt(FileDataInput fileDataInput, ByteBuffer outputBuffer, boolean allowBufferResize, EncryptionContext encryptionContext) throws IOException
    {
        return decrypt(new DataInputReadChannel(fileDataInput), outputBuffer, allowBufferResize, encryptionContext);
    }

    private static int encryptedBlockHeaderSize(byte[] iv)
    {
        return iv == null
               ? ENCRYPTED_BLOCK_HEADER_SIZE
               : ENCRYPTED_BLOCK_HEADER_SIZE + ENCRYPTED_BLOCK_IV_LENGTH_SIZE + iv.length;
    }

    private static void validateEncryptedBlockLengths(int encryptedLength, int plainTextLength) throws IOException
    {
        long maxBlockLength = Math.max(1L, DatabaseDescriptor.getCommitLogSegmentSize()) * 2L;
        if (encryptedLength <= 0 || plainTextLength <= 0 || encryptedLength < plainTextLength ||
            encryptedLength > maxBlockLength || plainTextLength > maxBlockLength)
        {
            throw new IOException("invalid encrypted block lengths: encrypted=" + encryptedLength +
                                  ", plaintext=" + plainTextLength +
                                  ", max=" + maxBlockLength);
        }
    }

    @VisibleForTesting
    static byte[] readFully(ReadableByteChannel channel, int length) throws IOException
    {
        byte[] dst = new byte[length];
        readFully(channel, dst, 0, length);
        return dst;
    }

    private static void readFully(ReadableByteChannel channel, ByteBuffer dst) throws IOException
    {
        int length = dst.remaining();
        if (dst.hasArray())
        {
            int position = dst.position();
            readFully(channel, dst.array(), dst.arrayOffset() + position, length);
            dst.position(position).limit(position + length);
        }
        else
        {
            dst.put(readFully(channel, length));
            dst.flip();
        }
    }

    private static void readFully(ReadableByteChannel channel, byte[] dst, int offset, int length) throws IOException
    {
        int readTotal = 0;
        while (readTotal < length)
        {
            int read = channel.read(ByteBuffer.wrap(dst, offset + readTotal, length - readTotal));
            if (read <= 0)
                throw new IOException("premature end of encrypted block: expected " + length + " bytes but read " + readTotal);
            readTotal += read;
        }
    }

    /**
     * Uncompress the input data, as well as manage sizing of the {@code outputBuffer}; if the buffer is not big enough,
     * deallocate current, and allocate a large enough buffer.
     *
     * @return the byte buffer that was actaully written to; it may be the {@code outputBuffer} if it had enough capacity,
     * or it may be a new, larger instance. Callers should capture the return buffer (if calling multiple times).
     */
    public static ByteBuffer uncompress(ByteBuffer inputBuffer, ByteBuffer outputBuffer, boolean allowBufferResize, ICompressor compressor) throws IOException
    {
        int outputLength = inputBuffer.getInt();
        outputBuffer = ByteBufferUtil.ensureCapacity(outputBuffer, outputLength, allowBufferResize);
        compressor.uncompress(inputBuffer, outputBuffer);
        outputBuffer.position(0).limit(outputLength);

        return outputBuffer;
    }

    public static int uncompress(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset, ICompressor compressor) throws IOException
    {
        int outputLength = readInt(input, inputOffset);
        inputOffset += 4;
        inputLength -= 4;

        if (output.length - outputOffset < outputLength)
        {
            String msg = String.format("buffer to uncompress into is not large enough; buf size = %d, buf offset = %d, target size = %s",
                                       output.length, outputOffset, outputLength);
            throw new IllegalStateException(msg);
        }

        return compressor.uncompress(input, inputOffset, inputLength, output, outputOffset);
    }

    private static int readInt(byte[] input, int inputOffset)
    {
        return  (input[inputOffset + 3] & 0xFF)
                | ((input[inputOffset + 2] & 0xFF) << 8)
                | ((input[inputOffset + 1] & 0xFF) << 16)
                | ((input[inputOffset] & 0xFF) << 24);
    }

    /**
     * A simple {@link java.nio.channels.Channel} adapter for ByteBuffers.
     */
    private static final class ChannelAdapter implements WritableByteChannel
    {
        private final ByteBuffer buffer;

        private ChannelAdapter(ByteBuffer buffer)
        {
            this.buffer = buffer;
        }

        public int write(ByteBuffer src)
        {
            int count = src.remaining();
            buffer.put(src);
            return count;
        }

        public boolean isOpen()
        {
            return true;
        }

        public void close()
        {
            // nop
        }
    }

    private static class DataInputReadChannel implements ReadableByteChannel
    {
        private final FileDataInput fileDataInput;

        private DataInputReadChannel(FileDataInput dataInput)
        {
            this.fileDataInput = dataInput;
        }

        public int read(ByteBuffer dst) throws IOException
        {
            int readLength = dst.remaining();
            // we should only be performing encrypt/decrypt operations with on-heap buffers, so calling BB.array() should be legit here
            fileDataInput.readFully(dst.array(), dst.position(), readLength);
            return readLength;
        }

        public boolean isOpen()
        {
            try
            {
                return fileDataInput.isEOF();
            }
            catch (IOException e)
            {
                return true;
            }
        }

        public void close()
        {
            // nop
        }
    }

    public static class ChannelProxyReadChannel implements ReadableByteChannel
    {
        private final ChannelProxy channelProxy;
        private volatile long currentPosition;

        public ChannelProxyReadChannel(ChannelProxy channelProxy, long currentPosition)
        {
            this.channelProxy = channelProxy;
            this.currentPosition = currentPosition;
        }

        public int read(ByteBuffer dst) throws IOException
        {
            int bytesRead = channelProxy.read(dst, currentPosition);
            dst.flip();
            currentPosition += bytesRead;
            return bytesRead;
        }

        public long getCurrentPosition()
        {
            return currentPosition;
        }

        public boolean isOpen()
        {
            return channelProxy.isCleanedUp();
        }

        public void close()
        {
            // nop
        }

        public void setPosition(long sourcePosition)
        {
            this.currentPosition = sourcePosition;
        }
    }
}

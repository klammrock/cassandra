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

import org.junit.Before;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.security.EncryptionContext;
import org.apache.cassandra.security.EncryptionContextGenerator;

public class HintsGcmEncryptionTest extends HintsEncryptionTest
{
    @Before
    public void setup()
    {
        encryptionContext = new EncryptionContext(EncryptionContextGenerator.createGCMEncryptionOptions());
        DatabaseDescriptor.setEncryptionContext(encryptionContext);
    }

    @Override
    boolean looksLegit(HintsWriter writer)
    {
        if (!(writer instanceof EncryptedHintsWriter))
            return false;

        EncryptedHintsWriter encryptedHintsWriter = (EncryptedHintsWriter) writer;
        return encryptedHintsWriter.getCipher() == null &&
               encryptionContext.getCompressor().getClass().isInstance(encryptedHintsWriter.getCompressor());
    }

    @Override
    boolean looksLegit(ChecksummedDataInput checksummedDataInput)
    {
        if (!(checksummedDataInput instanceof EncryptedChecksummedDataInput))
            return false;

        EncryptedChecksummedDataInput encryptedDataInput = (EncryptedChecksummedDataInput) checksummedDataInput;
        return encryptedDataInput.getCipher() == null &&
               encryptionContext.getCompressor().getClass().isInstance(encryptedDataInput.getCompressor());
    }

    @Override
    boolean checksumCoversEntireFile()
    {
        return true;
    }
}

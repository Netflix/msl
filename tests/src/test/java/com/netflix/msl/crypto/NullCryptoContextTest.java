/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.msl.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Random;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * Null crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NullCryptoContextTest {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        final MslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
    }
    
    @AfterClass
    public static void teardown() {
        encoder = null;
    }
    
    @Test
    public void encryptDecrypt() throws MslCryptoException {
        final Random random = new Random();
        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final NullCryptoContext cryptoContext = new NullCryptoContext();
        final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertext);
        assertArrayEquals(message, ciphertext);
        
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        assertNotNull(plaintext);
        assertArrayEquals(message, plaintext);
    }
    
    @Test
    public void wrapUnwrap() throws MslCryptoException {
        final Random random = new Random();
        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final NullCryptoContext cryptoContext = new NullCryptoContext();
        final byte[] ciphertext = cryptoContext.wrap(message, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertext);
        assertArrayEquals(message, ciphertext);
        
        final byte[] plaintext = cryptoContext.unwrap(ciphertext, encoder);
        assertNotNull(plaintext);
        assertArrayEquals(message, plaintext);
    }
    
    @Test
    public void signVerify() throws MslCryptoException {
        final Random random = new Random();
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);

        final NullCryptoContext cryptoContext = new NullCryptoContext();
        final byte[] signatureA = cryptoContext.sign(messageA, encoder, ENCODER_FORMAT);
        assertNotNull(signatureA);
        assertEquals(0, signatureA.length);
        
        assertTrue(cryptoContext.verify(messageA, signatureA, encoder));
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] signatureB = cryptoContext.sign(messageB, encoder, ENCODER_FORMAT);
        assertArrayEquals(signatureA, signatureB);
        
        assertTrue(cryptoContext.verify(messageB, signatureB, encoder));
        assertTrue(cryptoContext.verify(messageB, signatureA, encoder));
    }
}

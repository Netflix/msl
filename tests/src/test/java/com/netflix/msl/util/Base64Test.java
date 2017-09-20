/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;

import javax.xml.bind.DatatypeConverter;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.netflix.msl.util.Base64.Base64Impl;

/**
 * Base64 tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Parameterized.class)
public class Base64Test {
    /** UTF-8 charset. */
    private static final Charset CHARSET = Charset.forName("utf-8");
    
    /** Binary Base64 example. */
    private static final String BINARY_B64 = "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";
    
    /** Standard Base64 examples. */
    private static final Object[][] EXAMPLES = {
        { "The long winded author is going for a walk while the light breeze bellows in his ears.".getBytes(CHARSET),
          "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4=" },
        { "Sometimes porcupines need beds to sleep on.".getBytes(CHARSET),
          "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg==" },
        { "Even the restless dreamer enjoys home-cooked foods.".getBytes(CHARSET),
          "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu" },
        // We use DatatypeConverter here knowing BINARY_B64 is valid and that
        // DatatypeConverter is functionally correct.
        { DatatypeConverter.parseBase64Binary(BINARY_B64),
          BINARY_B64 },
    };
    
    /** Invalid Base64 examples. */
    private static final String[] INVALID_EXAMPLES = {
        "AAAAA",
        "AAAAAAA",
        "%$#@=",
        "ZZZZZZZZZZ=",
        "ZZZZZZZZZ==",
        "U29tZXRpbWVzIHBvcmN1cGluZX=gbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg==",
        "RXZlbiB0aGUgcmVzdGxlc3MgZHJ=YW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu",
        "RXZlbiB0aGUgcmVzdGxlc3MgZHJ=Y",
        "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgY幸B3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4=",
    };
    
    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
            { new Base64Jaxb() },
            { new Base64Secure() }
        });
    }
    
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    /**
     * @param impl Base64 encode/decode implementation.
     */
    public Base64Test(final Base64Impl impl) {
        Base64.setImpl(impl);
    }
    
    @Test
    public void standard() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            final Object[] example = EXAMPLES[i];
            final byte[] data = (byte[])example[0];
            final String base64 = (String)example[1];
            
            // Encode/decode.
            final String encoded = Base64.encode(data);
            final byte[] decoded = Base64.decode(base64);
            
            // Validate.
            assertEquals(base64, encoded);
            assertArrayEquals(data, decoded);
        }
    }
    
    @Test
    public void whitespace() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            final Object[] example = EXAMPLES[i];
            final byte[] data = (byte[])example[0];
            final String base64 = (String)example[1];
            
            // Modify.
            final int half = base64.length() / 2;
            final String modifiedBase64 = "  \t" + base64.substring(0, half) + "\r\n \r\n\t" + base64.substring(half) + " \t \n";
            
            // Encode/decode.
            final String encoded = Base64.encode(data);
            final byte[] decoded = Base64.decode(modifiedBase64);
            
            // Validate.
            assertEquals(base64, encoded);
            assertArrayEquals(data, decoded);
        }
    }
    
    @Test
    public void invalidPadding() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            final Object[] example = EXAMPLES[i];
            final String base64 = (String)example[1];
            
            // Modify.
            final String modifiedBase64 = base64 + "=";
            
            // Decode.
            boolean invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (final IllegalArgumentException e) {
                invalid = true;
            }
            assertTrue(invalid);
        }
    }
    
    @Test
    public void injectedPadding() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            final Object[] example = EXAMPLES[i];
            final String base64 = (String)example[1];
            
            // Modify.
            final int half = base64.length() / 2;
            final String modifiedBase64 = base64.substring(0, half) + "=" + base64.substring(half);
            
            // Decode.
            boolean invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (final IllegalArgumentException e) {
                invalid = true;
            }
            assertTrue(invalid);
        }
    }
    
    @Test
    public void invalidCharacter() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            final Object[] example = EXAMPLES[i];
            final String base64 = (String)example[1];
            
            // Modify.
            final int half = base64.length() / 2;
            final String modifiedBase64 = base64.substring(0, half) + "|" + base64.substring(half);
            
            // Decode.
            boolean invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (final IllegalArgumentException e) {
                invalid = true;
            }
            assertTrue(invalid);
        }
    }
    
    @Test
    public void outOfRangeCharacter() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            final Object[] example = EXAMPLES[i];
            final String base64 = (String)example[1];
            
            // Modify.
            final int half = base64.length() / 2;
            final String modifiedBase64 = base64.substring(0, half) + new String(new byte[] {(byte)128}) + base64.substring(half);
            
            // Decode.
            boolean invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (final IllegalArgumentException e) {
                invalid = true;
            }
            assertTrue(invalid);
        }
    }
    
    @Test
    public void invalidLength() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            final Object[] example = EXAMPLES[i];
            final String base64 = (String)example[1];
            
            // Modify.
            final String modifiedBase64 = base64.substring(1);
            
            // Decode.
            boolean invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (final IllegalArgumentException e) {
                invalid = true;
            }
            assertTrue(invalid);
        }
    }
    
    @Test
    public void invalid() {
        for (int i = 0; i < INVALID_EXAMPLES.length; ++i) {
            final String base64 = INVALID_EXAMPLES[i];
            boolean invalid = false;
            try {
                Base64.decode(base64);
            } catch (final IllegalArgumentException e) {
                invalid = true;
            }
            assertTrue(invalid);
        }
    }
    
    @Test
    public void emptyString() {
        final String base64 = "";
        final byte[] b = Base64.decode(base64);
        assertEquals(0, b.length);
    }
}

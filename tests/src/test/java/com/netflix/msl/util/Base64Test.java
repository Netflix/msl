/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

import java.nio.charset.Charset;

import org.junit.Test;

/**
 * Base64 tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Base64Test {
    /** UTF-8 charset. */
    private static final Charset CHARSET = Charset.forName("utf-8");
    
    /** Standard Base64 examples. */
    private static final Object[][] EXAMPLES = {
        { "The long winded author is going for a walk while the light breeze bellows in his ears.".getBytes(CHARSET),
          "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4=" },
        { "Sometimes porcupines need beds to sleep on.".getBytes(CHARSET),
          "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg==" },
        { "Even the restless dreamer enjoys home-cooked foods.".getBytes(CHARSET),
          "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu" },
    };
    
    @Test
    public void standard() {
        for (int i = 0; i < EXAMPLES.length; ++i) {
            final Object[] example = EXAMPLES[i];
            final byte[] data = (byte[])example[0];
            final String base64 = (String)example[1];
            final String encoded = Base64.encode(data);
            final byte[] decoded = Base64.decode(base64);
            assertEquals(base64, encoded);
            assertArrayEquals(data, decoded);
        }
    }
}

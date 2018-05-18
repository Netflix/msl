/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.io;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.util.IOUtils;

/**
 * <p>Thrifty UTF-8 reader unit tests.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ThriftyUtf8ReaderTest {
    /** UTF-8 data file. */
    private static final String UTF_8_FILE = "/utf-8-test.txt";
    /** UTF-8 data file character count. */
    private static final int UTF_8_FILE_COUNT = 22472;

    /** UTF-8 data. */
    private static byte[] utf8data;

    @BeforeClass
    public static void setup() throws IOException {
        // Load the UTF-8 file.
        utf8data = IOUtils.readResource(UTF_8_FILE);
    }

    @Test
    public void translate() throws IOException {
        // First read one character at a time.
        final String oneString;
        {
            final ByteArrayInputStream input = new ByteArrayInputStream(utf8data);
            final ThriftyUtf8Reader reader = new ThriftyUtf8Reader(input);
            final StringBuffer sb = new StringBuffer();
            do {
                final int c = reader.read();
                if (c == -1)
                    break;
                sb.append((char)c);
            } while (true);
            oneString = sb.toString();
            reader.close();
        }

        // Second read multiple characters at a time.
        final String bulkString;
        {
            final ByteArrayInputStream input = new ByteArrayInputStream(utf8data);
            final ThriftyUtf8Reader reader = new ThriftyUtf8Reader(input);
            final StringBuffer sb = new StringBuffer();
            do {
                final char[] chars = new char[8192];
                final int count = reader.read(chars);
                if (count == -1)
                    break;
                sb.append(chars, 0, count);
            } while (true);
            bulkString = sb.toString();
            reader.close();
        }

        // Third read all the characters at once.
        final String allString;
        {
            final ByteArrayInputStream input = new ByteArrayInputStream(utf8data);
            final ThriftyUtf8Reader reader = new ThriftyUtf8Reader(input);
            final StringBuffer sb = new StringBuffer();
            do {
                final char[] chars = new char[32768];
                final int count = reader.read(chars);
                if (count == -1)
                    break;
                sb.append(chars, 0, count);
            } while (true);
            allString = sb.toString();
            reader.close();
        }

        assertEquals(UTF_8_FILE_COUNT, oneString.length());
        assertEquals(oneString, bulkString);
        assertEquals(oneString, allString);
        System.out.println(oneString);
    }
}

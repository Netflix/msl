/**
 * Copyright (c) 2013-2018 Netflix, Inc.  All rights reserved.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.util.IOUtils;

/**
 * LZW input stream tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class LZWInputStreamTest {
    /** RAW data file. */
    private static final String DATAFILE = "/pg1112.txt";
    /** Compressed data file. */
    private static final String LZWFILE = "/pg1112.lzw";
    
    /**
     * Create an LZW input stream from the provided codes.
     * 
     * @param codes the LZW codes in order.
     * @return an LZW input stream.
     */
    private static LZWInputStream createInputStream(final byte[] codes) {
        final ByteArrayInputStream lzwbuffer = new ByteArrayInputStream(codes);
        return new LZWInputStream(lzwbuffer);
    }

    /** Raw data. */
    private static byte[] rawdata;
    /** Compressed data. */
    private static byte[] lzwdata;
    
    @BeforeClass
    public static void setup() throws IOException {
        // Load the raw file.
        rawdata = IOUtils.readResource(DATAFILE);

        // Load the compressed file.
        lzwdata = IOUtils.readResource(LZWFILE);
    }
    
    @Test
    public void oneByte() throws IOException {
        final byte[] codes = { (byte)0xf1 };
        final LZWInputStream lzw = createInputStream(codes);
        
        // The decoded data should equal the code value.
        final byte data = (byte)lzw.read();
        assertEquals(codes[0], data);
        
        // End of stream.
        assertEquals(-1, lzw.read());
        lzw.close();
    }
    
    @Test
    public void twoBytes() throws IOException {
        final byte[] codes = { (byte)0x66, (byte)0x33, (byte)0x80 };
        final byte[] data = { (byte)0x66, (byte)0x67 };
        final LZWInputStream lzw = createInputStream(codes);
        
        final byte[] decompressed = new byte[data.length];
        final int read = lzw.read(decompressed);
        assertEquals(decompressed.length, read);
        assertArrayEquals(data, decompressed);
        
        assertEquals(-1, lzw.read());
        lzw.close();
    }
    
    @Test
    public void threeBytes() throws IOException {
        final byte[] codes = { (byte)0x61, (byte)0x6b, (byte)0xac, (byte)0x40 };
        final byte[] data = { (byte)0x61, (byte)0xd7, (byte)0xb1 };
        final LZWInputStream lzw = createInputStream(codes);
        
        final byte[] decompressed = new byte[data.length];
        final int read = lzw.read(decompressed);
        assertEquals(decompressed.length, read);
        assertArrayEquals(data, decompressed);
        
        assertEquals(-1, lzw.read());
        lzw.close();
    }
    
    @Test
    public void verona() throws IOException {
        // Decompress the LZW file contents.
        final LZWInputStream lzis = createInputStream(lzwdata);
        final ByteArrayOutputStream uncompressed = new ByteArrayOutputStream();
        final byte[] data = new byte[256 * 1024];
        do {
            final int read = lzis.read(data);
            if (read == -1) break;
            uncompressed.write(data, 0, read);
        } while (true);
        lzis.close();
        
        final byte[] raw = uncompressed.toByteArray();
        assertArrayEquals(rawdata, raw);
    }
    
    @Test(expected = IOException.class)
    public void closed() throws IOException {
        final byte[] codes = new byte[0];
        final LZWInputStream lzw = createInputStream(codes);
        
        try {
            lzw.close();
        } catch (final IOException e) {
            fail(e.toString());
        }
        lzw.read();
    }
}

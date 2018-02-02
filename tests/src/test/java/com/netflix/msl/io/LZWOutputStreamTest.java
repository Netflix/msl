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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.util.IOUtils;

/**
 * LZW output stream tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class LZWOutputStreamTest {
    /** RAW data file. */
    private static final String DATAFILE = "/pg1112.txt";
    /** Compressed data file. */
    private static final String LZWFILE = "/pg1112.lzw";
    
    /**
     * Return the byte value shifted to the right by the number of specified
     * bits.
     * 
     * @param b the byte value.
     * @param count number of bits to shift.
     * @return the shifted byte value.
     */
    private static byte shiftright(final byte b, final int count) {
        int value = 0 | b;
        value >>= count;
        return (byte)(value & 0xff);
    }
    
    /**
     * Return the byte value shifted to the left by the number of specified
     * bits.
     * 
     * @param b the byte value.
     * @param count number of bits to shift.
     * @return the shifted byte value.
     */
    private static byte shiftleft(final byte b, final int count) {
        int value = 0 | b;
        value <<= count;
        return (byte)(value & 0xff);
    }
    
    /** Destination buffer. */
    private final ByteArrayOutputStream lzwbuffer = new ByteArrayOutputStream();
    /** LZW output stream. */
    private LZWOutputStream lzw = new LZWOutputStream(lzwbuffer);
    
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
    
    @After
    public void reset() {
        lzwbuffer.reset();
        lzw = new LZWOutputStream(lzwbuffer);
    }
    
    @Test
    public void oneByte() throws IOException {
        // Codes are buffered until flushed.
        final byte b = 0x1f;
        lzw.write(b);
        assertEquals(0, lzwbuffer.toByteArray().length);
        
        // Codes are only buffered after another code is received.
        lzw.flush();
        assertEquals(0, lzwbuffer.toByteArray().length);
        
        // All codes should be written to the backing stream.
        lzw.close();
        final byte[] compressed = lzwbuffer.toByteArray();
        assertEquals(1, compressed.length);
        assertEquals(b, compressed[0]);
    }
    
    @Test
    public void twoBytes() throws IOException {
        final byte[] data = { (byte)0x66, (byte)0x67 };
        final byte[] codes = { (byte)0x66, (byte)0x33, (byte)0x80 };

        // Codes are buffered until flushed.
        lzw.write(data);
        assertEquals(0, lzwbuffer.toByteArray().length);
        
        // With two codes, the first one will be buffered.
        lzw.flush();
        final byte[] flushed = lzwbuffer.toByteArray();
        assertEquals(1, flushed.length);
        assertEquals(codes[0], flushed[0]);
        
        // The second code will have an increased bit length.
        lzw.close();
        final byte[] compressed = lzwbuffer.toByteArray();
        assertEquals(3, compressed.length);
        assertEquals(data[0], compressed[0]);
        assertEquals(shiftright(data[1], 1), compressed[1]);
        assertEquals(shiftleft(data[1], 7), compressed[2]);
        assertArrayEquals(codes, compressed);
    }
    
    @Test
    public void threeBytes() throws IOException {
        final byte[] data = { (byte)0x61, (byte)0xd7, (byte)0xb1 };
        final byte[] codes = { (byte)0x61, (byte)0x6b, (byte)0xac, (byte)0x40 };

        // Codes are buffered until flushed.
        lzw.write(data);
        assertEquals(0, lzwbuffer.toByteArray().length);
        
        // With two codes, the first one will be buffered.
        lzw.flush();
        final byte[] flushed = lzwbuffer.toByteArray();
        assertEquals(1, flushed.length);
        assertEquals(codes[0], flushed[0]);
        
        // Confirm the encoding.
        lzw.close();
        final byte[] compressed = lzwbuffer.toByteArray();
        assertEquals(codes.length, compressed.length);
        assertArrayEquals(codes, compressed);
    }
    
    @Test
    public void finishThreeBytes() throws IOException {
        final byte[] data = { (byte)0x61, (byte)0xd7, (byte)0xb1 };
        final byte[] codes = { (byte)0x61, (byte)0x6b, (byte)0xac, (byte)0x40 };

        // Codes are buffered until flushed.
        lzw.write(data);
        assertEquals(0, lzwbuffer.toByteArray().length);
        
        // With two codes, the first one will be buffered.
        lzw.flush();
        final byte[] flushed = lzwbuffer.toByteArray();
        assertEquals(1, flushed.length);
        assertEquals(codes[0], flushed[0]);
        
        // Finish and confirm the encoding.
        lzw.finish();
        final byte[] compressed = lzwbuffer.toByteArray();
        assertEquals(codes.length, compressed.length);
        assertArrayEquals(codes, compressed);
    }
    
    @Test
    public void verona() throws IOException {
        // Compress the raw file contents.
        final ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        final LZWOutputStream lzos = new LZWOutputStream(compressed);
        lzos.write(rawdata);
        lzos.close();
        
        final byte[] lzw = compressed.toByteArray();
        assertArrayEquals(lzwdata, lzw);
    }
    
    @Test(expected = IOException.class)
    public void closed() throws IOException {
        try {
            lzw.close();
        } catch (final IOException e) {
            fail(e.toString());
        }
        lzw.write((byte)0);
    }
}

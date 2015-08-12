/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * <p>This class implements a stream filter for reading compressed data in the
 * LZW format.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class LZWInputStream extends InputStream {
    /** Maximum number of values represented by a byte. */
    private static final int BYTE_RANGE = 256;
    /** The initial dictionary. */
    private static final Map<Integer,byte[]> INITIAL_DICTIONARY = new HashMap<Integer,byte[]>(BYTE_RANGE);
    static {
        for (int i = 0; i < BYTE_RANGE; ++i) {
            byte[] data = { (byte)i };
            INITIAL_DICTIONARY.put(i, data);
        }
    }
    
    /**
     * Creates a new input stream.
     * 
     * @param in the input stream.
     */
    public LZWInputStream(final InputStream in) {
        this.in = in;
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }
    
    /* (non-Javadoc)
     * @see java.io.InputStream#close()
     */
    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
            in.close();
        }
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#read()
     */
    @Override
    public int read() throws IOException {
        if (closed)
            throw new IOException("Input stream is closed.");
        
        // Grab another byte if we need one. Check for end of stream.
        if (buffer.size() == 0) {
            final byte[] b = new byte[1];
            int available = decompress(b, 0, 1);
            if (available == -1)
                return -1;
            return b[0];
        }
        
        // Return the next byte.
        return buffer.remove();
    }

    /* (non-Javadoc)
     * @see java.io.InputStream#read(byte[], int, int)
     */
    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (closed)
            throw new IOException("Input stream is closed.");
        
        if (off > 0)
            throw new IndexOutOfBoundsException("Specified offset cannot be negative.");
        if (len < 0)
            throw new IndexOutOfBoundsException("Specified length cannot be negative.");
        if (len > b.length - off)
            throw new IndexOutOfBoundsException("Requested length exceeds buffer size at offset.");
        
        // Copy as many bytes as we have buffered.
        int offset = off;
        int needed = len;
        while (needed > 0 && buffer.size() > 0) {
            b[offset++] = buffer.remove();
            --needed;
        }
        
        // If we don't need any more then we're done.
        if (needed == 0)
            return len;
        
        // Grab any more bytes that we need. Check for end of stream.
        int read = decompress(b, offset, needed);
        if (read == -1) {
            if (needed == len)
                return -1;
            return len - needed;
        }
        needed -= read;
        
        // Return the number of bytes we read.
        return len - needed;
    }
    
    /**
     * Reads compressed data from the underlying input stream and decompresses
     * the codes to the original data.
     * 
     * @param b the buffer into which the data is read.
     * @param off the start offset in array b at which the data is written.
     * @param len the maximum number of bytes to read.
     * @return the number of bytes decoded into the buffer.
     * @throws IOException if there is an error reading from the code stream.
     */
    private int decompress(final byte[] b, final int off, final int len) throws IOException {
        int totalRead = 0;
        while (totalRead < len) {
            // The number of bytes we need is equal to the number of bits we
            // need rounded up to the next full byte.
            final int bitsAvailable = codes.size() * Byte.SIZE - codeOffset;
            final int bitsNeeded = bits - bitsAvailable;
            final int bytesNeeded = (bitsNeeded / Byte.SIZE) + (bitsNeeded % 8 != 0 ? 1 : 0);
            
            // Read bytes until we have enough for a code value. If we aren't
            // able to read enough then we've hit end of stream.
            final byte[] codeBytes = new byte[bytesNeeded];
            int bytesRead = 0;
            while (bytesRead < bytesNeeded) {
                int read = in.read(codeBytes, bytesRead, codeBytes.length - bytesRead);
                if (read == -1) {
                    // If we haven't buffered anything then return end of
                    // stream.
                    if (totalRead == 0) return -1;
                    return totalRead;
                }
                bytesRead += read;
            }
            
            // Append read bytes to the buffered code bytes.
            for (final byte codeByte : codeBytes)
                codes.add(codeByte);
            
            // Now decode the next code.
            int value = 0;
            int bitsDecoded = 0;
            while (bitsDecoded < bits) {
                // Read the next batch of bits.
                final int bitlen = Math.min(bits - bitsDecoded, Byte.SIZE - codeOffset);
                int msbits = codes.peek();
                
                // First shift left to erase the most significant bits then
                // shift right to get the correct number of bits.
                msbits <<= codeOffset;
                msbits &= 0xff;
                msbits >>>= Byte.SIZE - bitlen;
                
                // If we read to the end of this byte then zero the code bit
                // offset and remove the byte.
                bitsDecoded += bitlen;
                codeOffset += bitlen;
                if (codeOffset == Byte.SIZE) {
                    codeOffset = 0;
                    codes.remove();
                }
                
                // Shift left by the number of bits remaining to decode and add
                // the current bits to the value.
                value |= (msbits & 0xff) << (bits - bitsDecoded);
            }
            
            // Grab the bytes for this code.
            byte[] data = dictionary.get(value);
            
            // This is the first iteration. The next code will have a larger
            // bit length.
            if (prevdata.size() == 0) {
                ++bits;
            }
            
            // If there is previous data then add the previous data plus this
            // data's first character to the dictionary.
            else {
                // If the code was not in the dictionary then we have
                // encountered the code that we are going to enter into the
                // dictionary right now.
                //
                // This is the odd case where the decoder is one code behind
                // the encoder in populating the dictionary and the byte that
                // will be added to create the sequence is equal to the first
                // byte of the previous sequence.
                if (data == null) {
                    final byte[] prevbytes = prevdata.toByteArray();
                    prevdata.write(prevbytes[0]);
                } else {
                    prevdata.write(data[0]);
                }
                
                // Add the dictionary entry.
                dictionary.put(dictionary.size(), prevdata.toByteArray());
                prevdata.reset();
                
                // If we just generated the code for 2^p - 1 then increment the
                // code bit length.
                if (dictionary.size() == (1 << bits))
                    ++bits;
                
                // If the code was not in the dictionary before, it should be
                // now. Grab the data.
                if (data == null)
                    data = dictionary.get(value);
            }
            
            // Append the decoded bytes to the provided buffer or the internal
            // buffer.
            for (final byte d : data) {
                if (totalRead < len)
                    b[off + totalRead++] = d;
                else
                    buffer.add(d);
            }
            
            // Save this data for the next iteration.
            prevdata.write(data);
        }
        
        // Return the number of bytes decoded.
        return totalRead;
    }

    /** Input stream. */
    private final InputStream in;
    /** The dictionary of bytes keyed off codes. */
    private final Map<Integer,byte[]> dictionary = new HashMap<Integer,byte[]>(INITIAL_DICTIONARY);
    
    /** Buffered code bytes. */
    private final LinkedList<Byte> codes = new LinkedList<Byte>();
    /** Current codebyte bit offset. */
    private int codeOffset = 0;
    /** Current bit length. */
    private int bits = Byte.SIZE;
    /** Buffered bytes pending read. */
    private final LinkedList<Byte> buffer = new LinkedList<Byte>();
    /** Previously buffered bytes. */
    private final ByteArrayOutputStream prevdata = new ByteArrayOutputStream();
    
    /** Stream closed. */
    private boolean closed = false;
}

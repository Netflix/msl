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
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * <p>This class implements a stream filter for writing compressed data in the
 * LZW format.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class LZWOutputStream extends OutputStream {
    /** Maximum number of codes to buffer before flushing. */
    private static final int MAX_BUFFER_SIZE = 100;
    
    /** A byte array for use as map keys. */
    private static class Key {
        /**
         * Create a new key with the following byte array value. This does not
         * make a copy of the byte array.
         * 
         * @param bytes the byte array to serve as the key value.
         */
        public Key(final byte[] bytes) {
            this.bytes = bytes;
            this.hashCode = Arrays.hashCode(bytes);
        }
        
        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals(final Object o) {
            if (o == this) return true;
            if (!(o instanceof Key)) return false;
            return Arrays.equals(bytes, ((Key)o).bytes);
        }

        /* (non-Javadoc)
         * @see java.lang.Object#hashCode()
         */
        @Override
        public int hashCode() {
            return hashCode;
        }

        /* (non-Javadoc)
         * @see java.lang.Object#toString()
         */
        @Override
        public String toString() {
            return Arrays.toString(bytes);
        }

        /** The byte array value. */
        private final byte[] bytes;
        /** The hash code value. */
        private final int hashCode;
    }
    
    /** A code is a numeric value represented by a specific number of bits. */
    private static class Code {
        /**
         * Create a new code with the specified value and bit length.
         * 
         * @param value the value.
         * @param bits the number of bits used to encode the value.
         */
        public Code(int value, int bits) {
            this.value = value;
            this.bits = bits;
        }
        
        /* (non-Javadoc)
         * @see java.lang.Object#toString()
         */
        @Override
        public String toString() {
            return Integer.toHexString(value) + " (" + bits + "b)";
        }

        /** Numeric value. */
        public final int value;
        /** Bit length. */
        public final int bits;
    }
    
    /** Maximum number of values represented by a byte. */
    private static final int BYTE_RANGE = 256;
    /** The initial dictionary. */
    private static final Map<Key,Integer> INITIAL_DICTIONARY = new HashMap<Key,Integer>(BYTE_RANGE);
    static {
        for (int i = 0; i < BYTE_RANGE; ++i) {
            final byte[] keybytes = { (byte)i };
            final Key key = new Key(keybytes);
            INITIAL_DICTIONARY.put(key, i);
        }
    }
    
    /**
     * Creates a new output stream.
     * 
     * @param out the output stream.
     */
    public LZWOutputStream(final OutputStream out) {
        this.out = out;
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
     * @see java.io.OutputStream#close()
     */
    @Override
    public void close() throws IOException {
        if (!closed) {
            finish();
            out.close();
            closed = true;
        }
    }
    
    /**
     * Finishes writing compressed data to the output stream without closing
     * the underlying stream. Use this method when applying multiple filters in
     * succession to the same output stream.
     * 
     * @throws IOException if an I/O error has occurred.
     */
    public void finish() throws IOException {
        if (!finish) {
            finish = true;
            
            // If there are any symbols left we have to emit those codes now.
            if (symbols.size() > 0) {
                final byte[] keybytes = symbols.toByteArray();
                final Key key = new Key(keybytes);
                final Integer value = dictionary.get(key);
                buffer.add(new Code(value, bits));
                flush();
            }
        }
    }

    /* (non-Javadoc)
     * @see java.io.OutputStream#write(int)
     */
    @Override
    public void write(int b) throws IOException {
        final byte[] buf = new byte[1];
        buf[0] = (byte)(b & 0xff);
        write(buf, 0, 1);
    }

    /* (non-Javadoc)
     * @see java.io.OutputStream#write(byte[], int, int)
     */
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (closed)
            throw new IOException("Output stream is closed.");
        
        if (off < 0)
            throw new IndexOutOfBoundsException("Offset cannot be negative.");
        if (len < 0)
            throw new IndexOutOfBoundsException("Length cannot be negative.");
        if (off + len > b.length)
            throw new IndexOutOfBoundsException("Offset plus length cannot be greater than the array length.");
        
        for (int i = off; i < off + len; ++i) {
            // Add a byte to the input.
            final byte c = b[i];
            symbols.write(c);
            
            // Check if the input is in the dictionary.
            final byte[] keybytes = symbols.toByteArray();
            final Key key = new Key(keybytes);
            final Integer value = dictionary.get(key);
            
            // If the input is not in the dictionary, then...
            if (value == null) {
                // emit the previous input's code...
                final byte[] prevkeybytes = Arrays.copyOf(keybytes, keybytes.length - 1);
                final Key prevkey = new Key(prevkeybytes);
                final Integer prevvalue = dictionary.get(prevkey);
                buffer.add(new Code(prevvalue, bits));
                
                // and add the new input to the dictionary.
                //
                // The bit width increases from p to p + 1 when the new code is
                // the first code requiring p + 1 bits.
                final int newvalue = dictionary.size();
                if (newvalue >> bits != 0)
                    ++bits;
                dictionary.put(key, newvalue);
                
                // Remove the emitted symbol from the current input.
                symbols.reset();
                symbols.write(c);
                
                // If the buffer is too big, flush to avoid blowing the heap.
                if (buffer.size() > MAX_BUFFER_SIZE)
                    flush();
            }
        }
    }

    /* (non-Javadoc)
     * @see java.io.OutputStream#flush()
     */
    public void flush() throws IOException {
        // Do nothing if the code buffer is empty.
        if (buffer.isEmpty()) return;
        
        // Use MSB-First packing order.
        //
        // Collect codes until aligned on a byte boundary.
        int codebits = 0;
        final LinkedList<Code> codes = new LinkedList<Code>();
        while (buffer.size() > 0) {
            final Code c = buffer.remove();
            codes.add(c);
            codebits += c.bits;
            
            // If aligned on a byte boundary output the collected codes and
            // remove them from the codes buffer.
            if (codebits % 8 == 0) {
                out.write(codesToBytes(codes));
                codes.clear();
                codebits = 0;
            }
        }
        
        // If the stream is closed then output the remaining codes.
        if (finish)
            out.write(codesToBytes(codes));
        
        // Otherwise stick them back onto the code buffer for next time.
        else
            buffer.addAll(codes);
    }
    
    /**
     * Convert an ordered list of codes (which may or may not be byte-aligned)
     * into their MSB-first byte representation.
     * 
     * @param codes an ordered list of codes.
     * @return the MSB-first byte representation of the codes.
     */
    private static byte[] codesToBytes(final LinkedList<Code> codes) {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte b = 0;
        int available = Byte.SIZE;
        while (codes.size() > 0) {
            // Write the current code bits MSB-first.
            final Code code = codes.remove();
            int bits = code.bits;
            while (bits > 0) {
                // If the code has more bits than available, shift right to get
                // the most significant bits. This finishes off the current
                // byte.
                if (bits > available) {
                    int msbits = code.value;
                    msbits >>>= bits - available;
                    b |= (msbits & 0xff);
                    
                    // The current byte is finished so write it out.
                    bytes.write(b);

                    // We've written 'available' bits of the current code. The
                    // next byte is completely available so reset the values.
                    bits -= available;
                    available = Byte.SIZE;
                    b = 0;
                }
                
                // If the code has less then or equal bits available, shift
                // left to pack against the previous bits.
                else if (bits <= available) {
                    // First shift left to erase the most significant bits then
                    // shift right to start at the correct offset.
                    int msbits = code.value;
                    msbits <<= available - bits;
                    msbits &= 0xff;
                    msbits >>>= Byte.SIZE - available;
                    b |= (msbits & 0xff);

                    // We've written 'bits' bits into the current byte. There
                    // are no more bits to write for the current code.
                    available -= bits;
                    bits = 0;
                    
                    // If this finished the current byte then write it and
                    // reset the values.
                    if (available == 0) {
                        bytes.write(b);
                        available = Byte.SIZE;
                        b = 0;
                    }
                }
            }
        }
        
        // If the number of bits available in the current byte is less than the
        // size of a byte then the current byte still needs to be written.
        if (available < Byte.SIZE)
            bytes.write(b);
        return bytes.toByteArray();
    }
    
    /** Output stream. */
    private final OutputStream out;
    /** The dictionary of codes keyed off bytes. */
    private final Map<Key,Integer> dictionary = new HashMap<Key,Integer>(INITIAL_DICTIONARY);

    /** Working symbols. */
    private final ByteArrayOutputStream symbols = new ByteArrayOutputStream();
    /** Current bit length. */
    private int bits = Byte.SIZE;
    /** Buffered codes pending write. */
    private final LinkedList<Code> buffer = new LinkedList<Code>();
    
    /** Finish called. */
    private boolean finish = false;
    /** Stream closed. */
    private boolean closed = false;
}

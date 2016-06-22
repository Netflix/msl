/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.util;

import com.netflix.msl.util.Base64.Base64Impl;

/**
 * <p>Base64 encoder/decoder implementation that strictly enforces the validity
 * of the encoding and does not exit early if an error is encountered.
 * Whitespace (space, tab, newline, carriage return) are skipped.</p>
 * 
 * <p>Based upon {@link javax.xml.bind.DatatypeConverter}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Base64Secure implements Base64Impl {
    /** The encode map. */
    private static final char[] ENCODE_MAP = initEncodeMap();
    /** The decode map. */
    private static final byte[] DECODE_MAP = initDecodeMap();
    /** Tab character value. */
    private static final byte TAB = 9;
    /** Newline character value. */
    private static final byte NEWLINE = 10;
    /** Carriage return character value. */
    private static final byte CARRIAGE_RETURN = 13;
    /** Space character value. */
    private static final byte SPACE = 32;
    /** Padding character sentinel value. */
    private static final byte PADDING = 127;
    
    /**
     * @return the 64-character Base64 encode map.
     */
    private static char[] initEncodeMap() {
        final char[] map = new char[64];
        for (int i = 0; i < 26; i++)
            map[i] = (char)('A' + i);
        for (int i = 26; i < 52; i++)
            map[i] = (char)('a' + (i - 26));
        for (int i = 52; i < 62; i++)
            map[i] = (char)('0' + (i - 52));
        map[62] = '+';
        map[63] = '/';

        return map;
    }
    
    /**
     * @return the 128-byte Base64 decode map.
     */
    private static byte[] initDecodeMap() {
        final byte[] map = new byte[128];
        for (int i = 0; i < 128; i++)
            map[i] = -1;

        for (int i = 'A'; i <= 'Z'; i++)
            map[i] = (byte)(i - 'A');
        for (int i = 'a'; i <= 'z'; i++)
            map[i] = (byte)(i - 'a' + 26);
        for (int i = '0'; i <= '9'; i++)
            map[i] = (byte)(i - '0' + 52);
        map['+'] = 62;
        map['/'] = 63;
        map['='] = PADDING;

        return map;
    }
    
    /**
     * @param i the value to encode.
     * @return the character the value maps onto.
     */
    private static char encode(final int i) {
        return ENCODE_MAP[i & 0x3F];
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.Base64.Base64Impl#encode(byte[])
     */
    @Override
    public String encode(final byte[] b) {
        // Allocate the character buffer.
        final char[] buf = new char[((b.length + 2) / 3) * 4];
        int ptr = 0;
        
        // Encode elements until there are only 1 or 2 left.
        int remaining = b.length;
        int i;
        for (i = 0; remaining >= 3; remaining -= 3, i += 3) {
            buf[ptr++] = encode(b[i] >> 2);
            buf[ptr++] = encode(((b[i] & 0x3) << 4) | ((b[i+1] >> 4) & 0xF));
            buf[ptr++] = encode(((b[i + 1] & 0xF) << 2) | ((b[i + 2] >> 6) & 0x3));
            buf[ptr++] = encode(b[i + 2] & 0x3F);
        }
        // If there is one final element...
        if (remaining == 1) {
            buf[ptr++] = encode(b[i] >> 2);
            buf[ptr++] = encode(((b[i]) & 0x3) << 4);
            buf[ptr++] = '=';
            buf[ptr++] = '=';
        }
        // If there are two final elements...
        else if (remaining == 2) {
            buf[ptr++] = encode(b[i] >> 2);
            buf[ptr++] = encode(((b[i] & 0x3) << 4) | ((b[i + 1] >> 4) & 0xF));
            buf[ptr++] = encode((b[i + 1] & 0xF) << 2);
            buf[ptr++] = '=';
        }
        
        // Return the encoded string.
        return new String(buf);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.Base64.Base64Impl#decode(java.lang.String)
     */
    @Override
    public byte[] decode(final String s) {
        // Flag to remember if we've encountered an invalid character or have
        // reached the end of the string prematurely.
        boolean invalid = false;
        
        // Allocate the destination buffer, which may be too large due to
        // whitespace.
        final int strlen = s.length();
        final int outlen = strlen * 3 / 4;
        final byte[] out = new byte[outlen];
        int o = 0;
        
        // Convert each quadruplet to three bytes.
        final byte[] quadruplet = new byte[4];
        int q = 0;
        for (int i = 0; i < strlen; ++i) {
            final char c = s.charAt(i);
            final byte b = DECODE_MAP[c];
            
            // Skip invalid characters.
            if (b == -1) {
                // Flag invalid for non-whitespace.
                if (c != SPACE && c != TAB && c != NEWLINE && c != CARRIAGE_RETURN)
                    invalid = true;
                continue;
            }
            
            // Append value to quadruplet.
            quadruplet[q++] = b;
            
            // If the quadruplet is full, append it to the destination buffer.
            if (q == 4) {
                // If the quadruplet starts with padding, flag invalid.
                if (quadruplet[0] == PADDING || quadruplet[1] == PADDING)
                    invalid = true;
                
                // Decode into the destination buffer.
                out[o++] = (byte)((quadruplet[0] << 2) | (quadruplet[1] >> 4));
                if (quadruplet[2] != PADDING)
                    out[o++] = (byte)((quadruplet[1] << 4) | (quadruplet[2] >> 2));
                if (quadruplet[3] != PADDING)
                    out[o++] = (byte)((quadruplet[2] << 6) | (quadruplet[3]));
                
                // Reset the quadruplet index.
                q = 0;
            }
        }
        
        // If the quadruplet is not empty, flag invalid.
        if (q != 0)
            invalid = true;
        
        // If invalid throw an exception.
        if (invalid)
            throw new IllegalArgumentException("Invalid Base64 encoded string: " + s);
        
        // Always the destination buffer into the return buffer to maintain
        // consistent runtime.
        final byte[] ret = new byte[o];
        System.arraycopy(out, 0, ret, 0, o);
        return ret;
    }
}

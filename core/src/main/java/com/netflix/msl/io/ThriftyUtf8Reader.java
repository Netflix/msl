/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
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

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;

/**
 * <p>A specialized UTF-8 reader that only reads exactly the number of bytes
 * necessary to decode the character, and does not close the underlying input
 * stream. This ensures any unneeded bytes remain on the input stream, which
 * can then be reused.</p>
 *
 * <p>Based on Andy Clark's
 * {@code com.sun.org.apache.xerces.internal.impl.io.UTF8Reader}.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ThriftyUtf8Reader extends Reader {
    /** Default byte buffer size (8192). */
    public static final int DEFAULT_BUFFER_SIZE = 16384;
    /** Malformed replacement character. */
    public static final char MALFORMED_CHAR = 0xFFFD;

    /** Input stream. */
    private final InputStream fInputStream;
    /** Byte buffer. */
    private final byte[] fBuffer = new byte[DEFAULT_BUFFER_SIZE];
    /** Current buffer read position. */
    private int fIndex = 0;
    /** Number of valid bytes in the buffer. */
    private int fOffset = 0;
    /** Pending character. */
    private int fPending = -1;
    /** Surrogate character. */
    private int fSurrogate = -1;

    /**
     * Create a new thrifty UTF-8 reader that will read data off the provided
     * input stream.
     *
     * @param inputStream the underlying input stream.
     */
    public ThriftyUtf8Reader(final InputStream inputStream) {
        fInputStream = inputStream;
    }

    @Override
    public int read() throws IOException {
        // Return any surrogate.
        if (fSurrogate != -1) {
            final int c = fSurrogate;
            fSurrogate = -1;
            return c;
        }

        // Read the first byte or use the pending character.
        final int b0;
        if (fPending != -1) {
            b0 = fPending;
            fPending = -1;
        } else {
            b0 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b0 == -1)
                return -1;
        }

        // UTF-8:   [0xxx xxxx]
        // Unicode: [0000 0000] [0xxx xxxx]
        if (b0 < 0x80)
            return (char)b0;

        // UTF-8:   [110y yyyy] [10xx xxxx]
        // Unicode: [0000 0yyy] [yyxx xxxx]
        if ((b0 & 0xE0) == 0xC0) {
            final int b1 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b1 == -1)
                return MALFORMED_CHAR;
            if ((b1 & 0xC0) != 0x80) {
                fPending = b1;
                return MALFORMED_CHAR;
            }
            // Make sure the decoded value is not below the first code point of
            // a 2-byte sequence.
            if ((b0 & 0x1E) == 0)
                return MALFORMED_CHAR;
            return ((b0 << 6) & 0x07C0) | (b1 & 0x003F);
        }

        // UTF-8:   [1110 zzzz] [10yy yyyy] [10xx xxxx]
        // Unicode: [zzzz yyyy] [yyxx xxxx]
        if ((b0 & 0xF0) == 0xE0) {
            final int b1 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b1 == -1)
                return MALFORMED_CHAR;
            if ((b1 & 0xC0) != 0x80) {
                fPending = b1;
                return MALFORMED_CHAR;
            }
            final int b2 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b2 == -1)
                return MALFORMED_CHAR;
            if ((b2 & 0xC0) != 0x80) {
                fPending = b2;
                return MALFORMED_CHAR;
            }
            // Make sure the decoded value is not:
            //
            // 1. A surrogate character (0xD800 - 0xDFFF).
            // 2. Below the first code point of a 3-byte sequence.
            // 3. Equal to 0xFFFE or 0xFFFF.
            if ((b0 == 0xED && b1 >= 0xA0)
                || ((b0 & 0x0F) == 0 && (b1 & 0x20) == 0)
                || (b0 == 0xEF && (b1 & 0x3F) == 0x3F && (b2 & 0x3E) == 0x3E))
            {
                return MALFORMED_CHAR;
            }
            return ((b0 << 12) & 0xF000) | ((b1 << 6) & 0x0FC0) | (b2 & 0x003F);
        }

        // UTF-8:   [1111 0uuu] [10uu zzzz] [10yy yyyy] [10xx xxxx]*
        // Unicode: [1101 10ww] [wwzz zzyy] (high surrogate)
        //          [1101 11yy] [yyxx xxxx] (low surrogate)
        //          * uuuuu = wwww + 1
        if ((b0 & 0xF8) == 0xF0) {
            final int b1 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b1 == -1)
                return MALFORMED_CHAR;
            if ((b1 & 0xC0) != 0x80) {
                fPending = b1;
                return MALFORMED_CHAR;
            }
            final int b2 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b2 == -1)
                return MALFORMED_CHAR;
            if ((b2 & 0xC0) != 0x80) {
                fPending = b2;
                return MALFORMED_CHAR;
            }
            final int b3 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b3 == -1)
                return MALFORMED_CHAR;
            if ((b3 & 0xC0) != 0x80) {
                fPending = b3;
                return MALFORMED_CHAR;
            }
            // Make sure the decoded value is not below the first code point of
            // a 4-byte sequence.
            if ((b0 & 0x07) == 0 && (b1 & 0x30) == 0)
                return MALFORMED_CHAR;
            final int uuuuu = ((b0 << 2) & 0x001C) | ((b1 >> 4) & 0x0003);
            // Make sure the decoded value is not above the Unicode plane 0x10.
            if (uuuuu > 0x10)
                return MALFORMED_CHAR;
            final int wwww = uuuuu - 1;
            final int hs = 0xD800 |
                ((wwww << 6) & 0x03C0) | ((b1 << 2) & 0x003C) |
                ((b2 >> 4) & 0x0003);
            final int ls = 0xDC00 | ((b2 << 6) & 0x03C0) | (b3 & 0x003F);
            fSurrogate = ls;
            return hs;
        }

        // UTF-8:   [1111 10uu] [10uu zzzz] [10yy yyyy] [10xx xxxx] [10ww wwww]
        // Unicode: invalid
        if ((b0 & 0xFC) == 0xF8) {
            final int b1 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b1 == -1)
                return MALFORMED_CHAR;
            if ((b1 & 0xC0) != 0x80) {
                fPending = b1;
                return MALFORMED_CHAR;
            }
            final int b2 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b2 == -1)
                return MALFORMED_CHAR;
            if ((b2 & 0xC0) != 0x80) {
                fPending = b2;
                return MALFORMED_CHAR;
            }
            final int b3 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b3 == -1)
                return MALFORMED_CHAR;
            if ((b3 & 0xC0) != 0x80) {
                fPending = b3;
                return MALFORMED_CHAR;
            }
            final int b4 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b4 == -1)
                return MALFORMED_CHAR;
            if ((b4 & 0xC0) != 0x80) {
                fPending = b4;
                return MALFORMED_CHAR;
            }
            return MALFORMED_CHAR;
        }

        // UTF-8:   [1111 110u] [10uu zzzz] [10yy yyyy] [10xx xxxx] [10ww wwww] [10vv vvvv]
        // Unicode: invalid
        if ((b0 & 0xFE) == 0xFC) {
            final int b1 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b1 == -1)
                return MALFORMED_CHAR;
            if ((b1 & 0xC0) != 0x80) {
                fPending = b1;
                return MALFORMED_CHAR;
            }
            final int b2 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b2 == -1)
                return MALFORMED_CHAR;
            if ((b2 & 0xC0) != 0x80) {
                fPending = b2;
                return MALFORMED_CHAR;
            }
            final int b3 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b3 == -1)
                return MALFORMED_CHAR;
            if ((b3 & 0xC0) != 0x80) {
                fPending = b3;
                return MALFORMED_CHAR;
            }
            final int b4 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b4 == -1)
                return MALFORMED_CHAR;
            if ((b4 & 0xC0) != 0x80) {
                fPending = b4;
                return MALFORMED_CHAR;
            }
            final int b5 = (fIndex == fOffset) ? fInputStream.read() : fBuffer[fIndex++] & 0x00FF;
            if (b5 == -1)
                return MALFORMED_CHAR;
            if ((b5 & 0xC0) != 0x80) {
                fPending = b5;
                return MALFORMED_CHAR;
            }
            return MALFORMED_CHAR;
        }

        // Error.
        return MALFORMED_CHAR;
    }

    @Override
    public int read(final char ch[], int offset, int length) throws IOException {
        int numRead = 0;

        // Start with any surrogate.
        if (fSurrogate != -1) {
            ch[offset++] = (char)fSurrogate;
            fSurrogate = -1;
            --length;
            ++numRead;
        }

        // If there are no available bytes in the buffer...
        if (fIndex >= fOffset) {
            // Read at most buffer size bytes.
            if (length > fBuffer.length)
                length = fBuffer.length;
            final int count = fInputStream.read(fBuffer, 0, length);

            // If we could not read anymore, return the number of characters
            // read so far or end-of-stream.
            if (count == -1)
                return (numRead > 0) ? numRead : -1;

            // Start reading from the beginning of the buffer, up to the number
            // of valid bytes.
            fIndex = 0;
            fOffset = count;
        }

        // Read bytes (out of the buffer) until the buffer is empty or we have
        // all of the characters requested.
        while (fIndex < fOffset && numRead < length) {
            final int c = read();

            // If we could not read anymore, return the number of characters
            // read so far or end-of-stream.
            if (c == -1)
                return (numRead > 0) ? numRead : -1;

            // Populate the character array.
            ch[offset++] = (char)c;
            ++numRead;
        }

        // To avoid recursing forever or from blocking too long, return with
        // what we have so far.
        return numRead;
    }

    @Override
    public long skip(final long n) throws IOException {
        // Don't pass skip down to the backing input stream since we're being
        // asked to skip characters and not bytes.
        long remaining = n;
        final char[] ch = new char[fBuffer.length];
        do {
            final int length = ch.length < remaining ? ch.length : (int)remaining;
            final int count = read(ch, 0, length);
            if (count > 0)
                remaining -= count;
            else
                break;
        } while (remaining > 0);

        final long skipped = n - remaining;
        return skipped;
    }

    /**
     * Tell whether this stream supports the mark() operation.
     */
    @Override
    public boolean markSupported() {
        return fInputStream.markSupported();
    }

    @Override
    public void mark(final int readLimit) throws IOException {
        // This is complicated because the read limit is in characters but the
        // backing input stream is in bytes. If we really want to be safe then
        // we need to multiply by the maximum number of bytes per character.
        // Account for overflow.
        final long byteLimit = 6 * readLimit;
        final int safeLimit = (byteLimit < 0 || byteLimit > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int)byteLimit;
        fInputStream.mark(safeLimit);
    }

    @Override
    public void reset() throws IOException {
        fOffset = 0;
        fSurrogate = -1;
        fInputStream.reset();
    }

    @Override
    public void close() {
        // Explicitly do not close the backing input stream for our use case.
        // This is because we are using ThriftyUtf8Reader inside a stream
        // parser.
    }
}

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
    public static final int DEFAULT_BUFFER_SIZE = 8192;

    /** Input stream. */
    private final InputStream fInputStream;
    /** Byte buffer. */
    private final byte[] fBuffer = new byte[DEFAULT_BUFFER_SIZE];
    /** Offset into buffer. */
    private int fOffset = 0;
    /** Surrogate character. */
    private int fSurrogate = -1;

    public ThriftyUtf8Reader(final InputStream inputStream) {
        fInputStream = inputStream;
    }

    @Override
    public int read() throws IOException {
        // decode character
        int c = fSurrogate;
        if (fSurrogate == -1) {
            // NOTE: We use the index into the buffer if there are remaining
            //       bytes from the last block read. -Ac
            int index = 0;

            // get first byte
            final int b0 = index == fOffset
                   ? fInputStream.read() : fBuffer[index++] & 0x00FF;
            if (b0 == -1) {
                return -1;
            }

            // UTF-8:   [0xxx xxxx]
            // Unicode: [0000 0000] [0xxx xxxx]
            if (b0 < 0x80) {
                c = (char)b0;
            }

            // UTF-8:   [110y yyyy] [10xx xxxx]
            // Unicode: [0000 0yyy] [yyxx xxxx]
            else if ((b0 & 0xE0) == 0xC0 && (b0 & 0x1E) != 0) {
                final int b1 = index == fOffset
                       ? fInputStream.read() : fBuffer[index++] & 0x00FF;
                if (b1 == -1) {
                    expectedByte(2, 2);
                }
                if ((b1 & 0xC0) != 0x80) {
                    invalidByte(2, 2, b1);
                }
                c = ((b0 << 6) & 0x07C0) | (b1 & 0x003F);
            }

            // UTF-8:   [1110 zzzz] [10yy yyyy] [10xx xxxx]
            // Unicode: [zzzz yyyy] [yyxx xxxx]
            else if ((b0 & 0xF0) == 0xE0) {
                final int b1 = index == fOffset
                       ? fInputStream.read() : fBuffer[index++] & 0x00FF;
                if (b1 == -1) {
                    expectedByte(2, 3);
                }
                if ((b1 & 0xC0) != 0x80
                    || (b0 == 0xED && b1 >= 0xA0)
                    || ((b0 & 0x0F) == 0 && (b1 & 0x20) == 0)) {
                    invalidByte(2, 3, b1);
                }
                final int b2 = index == fOffset
                       ? fInputStream.read() : fBuffer[index++] & 0x00FF;
                if (b2 == -1) {
                    expectedByte(3, 3);
                }
                if ((b2 & 0xC0) != 0x80) {
                    invalidByte(3, 3, b2);
                }
                c = ((b0 << 12) & 0xF000) | ((b1 << 6) & 0x0FC0) |
                    (b2 & 0x003F);
            }

            // UTF-8:   [1111 0uuu] [10uu zzzz] [10yy yyyy] [10xx xxxx]*
            // Unicode: [1101 10ww] [wwzz zzyy] (high surrogate)
            //          [1101 11yy] [yyxx xxxx] (low surrogate)
            //          * uuuuu = wwww + 1
            else if ((b0 & 0xF8) == 0xF0) {
                final int b1 = index == fOffset
                       ? fInputStream.read() : fBuffer[index++] & 0x00FF;
                if (b1 == -1) {
                    expectedByte(2, 4);
                }
                if ((b1 & 0xC0) != 0x80
                    || ((b1 & 0x30) == 0 && (b0 & 0x07) == 0)) {
                    invalidByte(2, 3, b1);
                }
                final int b2 = index == fOffset
                       ? fInputStream.read() : fBuffer[index++] & 0x00FF;
                if (b2 == -1) {
                    expectedByte(3, 4);
                }
                if ((b2 & 0xC0) != 0x80) {
                    invalidByte(3, 3, b2);
                }
                final int b3 = index == fOffset
                       ? fInputStream.read() : fBuffer[index++] & 0x00FF;
                if (b3 == -1) {
                    expectedByte(4, 4);
                }
                if ((b3 & 0xC0) != 0x80) {
                    invalidByte(4, 4, b3);
                }
                final int uuuuu = ((b0 << 2) & 0x001C) | ((b1 >> 4) & 0x0003);
                if (uuuuu > 0x10) {
                    invalidSurrogate(uuuuu);
                }
                final int wwww = uuuuu - 1;
                final int hs = 0xD800 |
                         ((wwww << 6) & 0x03C0) | ((b1 << 2) & 0x003C) |
                         ((b2 >> 4) & 0x0003);
                final int ls = 0xDC00 | ((b2 << 6) & 0x03C0) | (b3 & 0x003F);
                c = hs;
                fSurrogate = ls;
            }

            // error
            else {
                invalidByte(1, 1, b0);
            }
        }

        // use surrogate
        else {
            fSurrogate = -1;
        }

        // return character
        return c;
    }

    @Override
    public int read(final char ch[], final int offset, int length) throws IOException {
        // handle surrogate
        int out = offset;
        if (fSurrogate != -1) {
            ch[offset + 1] = (char)fSurrogate;
            fSurrogate = -1;
            length--;
            out++;
        }

        // read bytes
        int count = 0;
        if (fOffset == 0) {
            // adjust length to read
            if (length > fBuffer.length) {
                length = fBuffer.length;
            }

            // perform read operation
            count = fInputStream.read(fBuffer, 0, length);
            if (count == -1) {
                return -1;
            }
            count += out - offset;
        }

        // skip read; last character was in error
        // NOTE: Having an offset value other than zero means that there was
        //       an error in the last character read. In this case, we have
        //       skipped the read so we don't consume any bytes past the
        //       error. By signalling the error on the next block read we
        //       allow the method to return the most valid characters that
        //       it can on the previous block read. -Ac
        else {
            count = fOffset;
            fOffset = 0;
        }

        // convert bytes to characters
        final int total = count;
        int in;
        byte byte1;
        final byte byte0 = 0;
        for (in = 0; in < total; in++) {
            byte1 = fBuffer[in];
            if (byte1 >= byte0) {
                ch[out++] = (char)byte1;
            }
            else   {
                break;
            }
        }
        for ( ; in < total; in++) {
            byte1 = fBuffer[in];

            // UTF-8:   [0xxx xxxx]
            // Unicode: [0000 0000] [0xxx xxxx]
            if (byte1 >= byte0) {
                ch[out++] = (char)byte1;
                continue;
            }

            // UTF-8:   [110y yyyy] [10xx xxxx]
            // Unicode: [0000 0yyy] [yyxx xxxx]
            final int b0 = byte1 & 0x0FF;
            if ((b0 & 0xE0) == 0xC0 && (b0 & 0x1E) != 0) {
                int b1 = -1;
                if (++in < total) {
                    b1 = fBuffer[in] & 0x00FF;
                }
                else {
                    b1 = fInputStream.read();
                    if (b1 == -1) {
                        if (out > offset) {
                            fBuffer[0] = (byte)b0;
                            fOffset = 1;
                            return out - offset;
                        }
                        expectedByte(2, 2);
                    }
                    count++;
                }
                if ((b1 & 0xC0) != 0x80) {
                    if (out > offset) {
                        fBuffer[0] = (byte)b0;
                        fBuffer[1] = (byte)b1;
                        fOffset = 2;
                        return out - offset;
                    }
                    invalidByte(2, 2, b1);
                }
                final int c = ((b0 << 6) & 0x07C0) | (b1 & 0x003F);
                ch[out++] = (char)c;
                count -= 1;
                continue;
            }

            // UTF-8:   [1110 zzzz] [10yy yyyy] [10xx xxxx]
            // Unicode: [zzzz yyyy] [yyxx xxxx]
            if ((b0 & 0xF0) == 0xE0) {
                int b1 = -1;
                if (++in < total) {
                    b1 = fBuffer[in] & 0x00FF;
                }
                else {
                    b1 = fInputStream.read();
                    if (b1 == -1) {
                        if (out > offset) {
                            fBuffer[0] = (byte)b0;
                            fOffset = 1;
                            return out - offset;
                        }
                        expectedByte(2, 3);
                    }
                    count++;
                }
                if ((b1 & 0xC0) != 0x80
                    || (b0 == 0xED && b1 >= 0xA0)
                    || ((b0 & 0x0F) == 0 && (b1 & 0x20) == 0)) {
                    if (out > offset) {
                        fBuffer[0] = (byte)b0;
                        fBuffer[1] = (byte)b1;
                        fOffset = 2;
                        return out - offset;
                    }
                    invalidByte(2, 3, b1);
                }
                int b2 = -1;
                if (++in < total) {
                    b2 = fBuffer[in] & 0x00FF;
                }
                else {
                    b2 = fInputStream.read();
                    if (b2 == -1) {
                        if (out > offset) {
                            fBuffer[0] = (byte)b0;
                            fBuffer[1] = (byte)b1;
                            fOffset = 2;
                            return out - offset;
                        }
                        expectedByte(3, 3);
                    }
                    count++;
                }
                if ((b2 & 0xC0) != 0x80) {
                    if (out > offset) {
                        fBuffer[0] = (byte)b0;
                        fBuffer[1] = (byte)b1;
                        fBuffer[2] = (byte)b2;
                        fOffset = 3;
                        return out - offset;
                    }
                    invalidByte(3, 3, b2);
                }
                final int c = ((b0 << 12) & 0xF000) | ((b1 << 6) & 0x0FC0) |
                        (b2 & 0x003F);
                ch[out++] = (char)c;
                count -= 2;
                continue;
            }

            // UTF-8:   [1111 0uuu] [10uu zzzz] [10yy yyyy] [10xx xxxx]*
            // Unicode: [1101 10ww] [wwzz zzyy] (high surrogate)
            //          [1101 11yy] [yyxx xxxx] (low surrogate)
            //          * uuuuu = wwww + 1
            if ((b0 & 0xF8) == 0xF0) {
                int b1 = -1;
                if (++in < total) {
                    b1 = fBuffer[in] & 0x00FF;
                }
                else {
                    b1 = fInputStream.read();
                    if (b1 == -1) {
                        if (out > offset) {
                            fBuffer[0] = (byte)b0;
                            fOffset = 1;
                            return out - offset;
                        }
                        expectedByte(2, 4);
                    }
                    count++;
                }
                if ((b1 & 0xC0) != 0x80
                    || ((b1 & 0x30) == 0 && (b0 & 0x07) == 0)) {
                    if (out > offset) {
                        fBuffer[0] = (byte)b0;
                        fBuffer[1] = (byte)b1;
                        fOffset = 2;
                        return out - offset;
                    }
                    invalidByte(2, 4, b1);
                }
                int b2 = -1;
                if (++in < total) {
                    b2 = fBuffer[in] & 0x00FF;
                }
                else {
                    b2 = fInputStream.read();
                    if (b2 == -1) {
                        if (out > offset) {
                            fBuffer[0] = (byte)b0;
                            fBuffer[1] = (byte)b1;
                            fOffset = 2;
                            return out - offset;
                        }
                        expectedByte(3, 4);
                    }
                    count++;
                }
                if ((b2 & 0xC0) != 0x80) {
                    if (out > offset) {
                        fBuffer[0] = (byte)b0;
                        fBuffer[1] = (byte)b1;
                        fBuffer[2] = (byte)b2;
                        fOffset = 3;
                        return out - offset;
                    }
                    invalidByte(3, 4, b2);
                }
                int b3 = -1;
                if (++in < total) {
                    b3 = fBuffer[in] & 0x00FF;
                }
                else {
                    b3 = fInputStream.read();
                    if (b3 == -1) {
                        if (out > offset) {
                            fBuffer[0] = (byte)b0;
                            fBuffer[1] = (byte)b1;
                            fBuffer[2] = (byte)b2;
                            fOffset = 3;
                            return out - offset;
                        }
                        expectedByte(4, 4);
                    }
                    count++;
                }
                if ((b3 & 0xC0) != 0x80) {
                    if (out > offset) {
                        fBuffer[0] = (byte)b0;
                        fBuffer[1] = (byte)b1;
                        fBuffer[2] = (byte)b2;
                        fBuffer[3] = (byte)b3;
                        fOffset = 4;
                        return out - offset;
                    }
                    invalidByte(4, 4, b2);
                }

                // check if output buffer is large enough to hold 2 surrogate chars
                if (out + 1 >= ch.length) {
                    fBuffer[0] = (byte)b0;
                    fBuffer[1] = (byte)b1;
                    fBuffer[2] = (byte)b2;
                    fBuffer[3] = (byte)b3;
                    fOffset = 4;
                    return out - offset;
                }

                // decode bytes into surrogate characters
                final int uuuuu = ((b0 << 2) & 0x001C) | ((b1 >> 4) & 0x0003);
                if (uuuuu > 0x10) {
                    invalidSurrogate(uuuuu);
                }
                final int wwww = uuuuu - 1;
                final int zzzz = b1 & 0x000F;
                final int yyyyyy = b2 & 0x003F;
                final int xxxxxx = b3 & 0x003F;
                final int hs = 0xD800 | ((wwww << 6) & 0x03C0) | (zzzz << 2) | (yyyyyy >> 4);
                final int ls = 0xDC00 | ((yyyyyy << 6) & 0x03C0) | xxxxxx;

                // set characters
                ch[out++] = (char)hs;
                ch[out++] = (char)ls;
                count -= 2;
                continue;
            }

            // error
            if (out > offset) {
                fBuffer[0] = (byte)b0;
                fOffset = 1;
                return out - offset;
            }
            invalidByte(1, 1, b0);
        }

        // return number of characters converted
        return count;
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
        // we need to multiply by 4 bytes. Account for overflow.
        final int safeLimit = Math.max(Integer.MAX_VALUE, 4 * readLimit);
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

    /** Throws an exception for expected byte. */
    private void expectedByte(final int position, final int count) throws IOException {
        throw new IOException("Expected byte " + position + " for " + count + " byte sequence.");
    }

    /** Throws an exception for invalid byte. */
    private void invalidByte(final int position, final int count, final int c) throws IOException {
        throw new IOException("Invalid byte " + c + " at position " + position + " of " + count + " byte sequence.");
    }

    /** Throws an exception for invalid surrogate bits. */
    private void invalidSurrogate(final int uuuuu) throws IOException {
        throw new IOException("Invalid high surrogate " + uuuuu + ".");
    }
}

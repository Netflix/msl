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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * <p>A {@code UnsynchronizedBufferedInputStream} adds support for the
 * {@code mark()} and {@code reset()} functions.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UnsynchronizedBufferedInputStream extends FilterInputStream {
    /**
     * Buffer of data read since the last call to mark(). Null if
     * mark() has not been called or if the read limit has been
     * exceeded.
     */
    protected byte buf[] = null;
    /** Number of valid bytes in the buffer. */
    protected int bufcount;
    /** Current buffer read position. */
    protected int bufpos;

    /**
     * Creates a new <code>UnsynchronizedBufferedInputStream</code> without any
     * mark position set.
     *
     * @param in the backing input stream.
     */
    public UnsynchronizedBufferedInputStream(final InputStream in) {
        super(in);
    }

    @Override
    public int read() throws IOException {
        if (in == null)
            throw new IOException("Stream is closed");

        // If we have any data in the buffer, read it first.
        if (bufpos < bufcount)
            return buf[bufpos++];

        // Otherwise read from the backing stream...
        final int c = in.read();
        if (c == -1) return -1;

        // If we are buffering data...
        if (buf != null) {
            // Store the data if there is space.
            if (bufcount < buf.length) {
                buf[bufcount++] = (byte)c;
                bufpos++;
            }

            // Otherwise we have exceeded the read limit. Stop buffering and
            // invalidate the mark.
            else {
                buf = null;
                bufcount = 0;
                bufpos = 0;
            }
        }

        // Return the read data.
        return c;
    }

    @Override
    public int read(final byte b[], final int off, final int len) throws IOException {
        if (in == null)
            throw new IOException("Stream is closed");

        // Copy in any buffered data.
        final int copied;
        if (bufcount > bufpos) {
            copied = Math.min(bufcount - bufpos, len);
            System.arraycopy(buf, bufpos, b, off, copied);
            bufpos += copied;
        } else {
            copied = 0;
        }

        // Read any remaining data requested.
        final int remaining = len - copied;
        final int numread = in.read(b, off + copied, remaining);

        // If we were unable to read, return the number of bytes copied or -1
        // to indicate end-of-stream if we also didn't copy any bytes.
        if (numread == -1)
            return (copied > 0) ? copied : -1;

        // If we are buffering data...
        if (buf != null) {
            // Store the data if there is space.
            if (bufcount + numread <= buf.length) {
                System.arraycopy(b, copied, buf, bufpos, numread);
                bufcount += numread;
                bufpos += numread;
            }

            // Otherwise we have exceeded the read limit. Stop buffering and
            // invalidate the mark.
            else {
                buf = null;
                bufcount = 0;
                bufpos = 0;
            }
        }

        // Return number of bytes read.
        return copied + numread;
    }

    @Override
    public long skip(final long n) throws IOException {
        if (in == null)
            throw new IOException("Stream is closed");

        // If we have enough buffered characters, skip over them.
        final long buffered = bufcount - bufpos;
        if (buffered >= n) {
            bufpos += n;
            return n;
        }

        // Otherwise skip over the buffered characters and read the rest.
        bufpos += buffered;
        long remaining = n - buffered;
        while (remaining > 0) {
            final byte[] buf = new byte[(int)remaining];
            final int read = read(buf, 0, buf.length);
            if (read == -1) break;
            remaining -= read;
        }

        // Return the number of characters skipped.
        return n - remaining;
    }

    @Override
    public int available() throws IOException {
        if (in == null)
            throw new IOException("Stream is closed");
        final int available = in.available();
        return (bufcount + available < 0) ? Integer.MAX_VALUE : bufcount + available;
    }

    @Override
    public void mark(final int readlimit) {
        // Create the new buffer of the requested size.
        final byte[] newbuf = new byte[readlimit];

        // Copy any unread data that is currently buffered into the new buffer.
        final int tocopy = (buf != null) ? bufcount - bufpos : 0;
        if (tocopy > 0)
            System.arraycopy(buf, bufpos, newbuf, 0, tocopy);

        // Set the buffer.
        buf = newbuf;
        bufpos = 0;
        bufcount = tocopy;
    }

    @Override
    public void reset() throws IOException {
        if (in == null)
            throw new IOException("Stream is closed");
        bufpos = 0;
    }

    @Override
    public boolean markSupported() {
        return true;
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
            in = null;
        }
    }
}
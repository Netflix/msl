/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.client.configuration.msg;

import com.netflix.msl.msg.FilterStreamFactory;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * User: skommidi
 * Date: 8/27/14
 */
public class TestConsoleFilterStreamFactory implements FilterStreamFactory {

    /**
     * A filter input stream that outputs read data to stdout. A new line is
     * output when the stream is closed.
     */
    private static class ConsoleInputStream extends FilterInputStream {
        /**
         * Create a new console input stream backed by the provided input
         * stream.
         *
         * @param in the backing input stream.
         */
        protected ConsoleInputStream(final InputStream in) {
            super(in);
        }
        /* (non-Javadoc)
         * @see java.io.FilterInputStream#close()
         */
        @Override
        public void close() throws IOException {
            System.out.println();
            System.out.flush();
            super.close();
        }

        /* (non-Javadoc)
         * @see java.io.FilterInputStream#read()
         */
        @Override
        public int read() throws IOException {
            int c = super.read();
            System.out.write(c);
            System.out.flush();
            return c;
        }

        /* (non-Javadoc)
         * @see java.io.FilterInputStream#read(byte[], int, int)
         */
        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            System.out.println("==================== Client Read ====================");
            int r = super.read(b, off, len);
            System.out.write(b, off,len);
            System.out.flush();
            return r;
        }
    }

    /**
     * A filter output stream that outputs written data to stdout. A newline is
     * output when the stream is closed.
     */
    private static class ConsoleOutputStream extends FilterOutputStream {
        /**
         * Create a new console output stream backed by the provided output
         * stream.
         *
         * @param out the backing output stream.
         */
        public ConsoleOutputStream(final OutputStream out) {
            super(out);
        }

        /* (non-Javadoc)
         * @see java.io.FilterOutputStream#close()
         */
        @Override
        public void close() throws IOException {
            System.out.println();
            System.out.flush();
            super.close();
        }

        /* (non-Javadoc)
         * @see java.io.FilterOutputStream#write(byte[], int, int)
         */
        @Override
        public void write(final byte[] b, final int off, final int len) throws IOException {
            System.out.println("==================== Client Write ====================");
            System.out.write(b, off, len);
            System.out.flush();
            super.write(b, off, len);
        }

        /* (non-Javadoc)
         * @see java.io.FilterOutputStream#write(int)
         */
        @Override
        public void write(final int b) throws IOException {
            System.out.write(b);
            System.out.flush();
            super.write(b);
        }
    }

    @Override
    public InputStream getInputStream(InputStream in) {
        return new ConsoleInputStream(in);
    }

    @Override
    public OutputStream getOutputStream(OutputStream out) {
        return new ConsoleOutputStream(out);
    }
}

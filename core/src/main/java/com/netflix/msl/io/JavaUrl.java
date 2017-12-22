/**
 * Copyright (c) 2012-2016 Netflix, Inc.  All rights reserved.
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
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 * An implementation of the {@link Url} interface based on the built-in Java
 * {@link URL} class.
 */
public class JavaUrl implements Url {
    /**
     * A delayed input stream does not open the real input stream until one of its
     * its methods is called. This class may be useful in situations where the
     * connection will not permit use of its output stream after the input stream
     * is requested.
     */
    public class DelayedInputStream extends FilterInputStream {
        /**
         * Create a new delayed input stream that will not attempt to
         * construct the input stream from the URL connection until it is
         * actually needed (i.e. read from).
         * 
         * @param conn backing URL connection.
         */
        public DelayedInputStream(final URLConnection conn) {
            super(null);
            this.conn = conn;
        }
        
        @Override
        public int available() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.available();
        }

        @Override
        public void close() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            super.close();
        }

        @Override
        public synchronized void mark(final int readlimit) {
        }

        @Override
        public boolean markSupported() {
            return false;
        }

        @Override
        public int read() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return in.read();
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.read(b, off, len);
        }

        @Override
        public int read(final byte[] b) throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.read(b);
        }

        @Override
        public synchronized void reset() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            super.reset();
        }

        @Override
        public long skip(final long n) throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.skip(n);
        }
        
        /** Connection providing the input stream. */
        private final URLConnection conn;
    }
    
    /**
     * An implementation of the {@link Connection} interface backed by the
     * built-in Java {@link URLConnection} class.
     */
    private class JavaConnection implements Connection {
        /**
         * Create a new Java connection with the backing URL connection.
         * 
         * @param conn the backing URL connection.
         */
        public JavaConnection(final URLConnection conn) {
            this.conn = conn;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.io.Url.Connection#getInputStream()
         */
        @Override
        public InputStream getInputStream() throws IOException {
            // Asking for the URL connection's input stream prevents further
            // writing to the output stream, so return a delayed input stream.
            return new DelayedInputStream(conn);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.io.Url.Connection#getOutputStream()
         */
        @Override
        public OutputStream getOutputStream() throws IOException {
            return conn.getOutputStream();
        }
        
        /** URL connection. */
        private final URLConnection conn;
    }
    
    /**
     * @param url the target location.
     */
    public JavaUrl(final URL url) {
        this.url = url;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.Url#setTimeout(int)
     */
    @Override
    public void setTimeout(final int timeout) {
        this.timeout = timeout;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.Url#openConnection()
     */
    @Override
    public Connection openConnection() throws IOException {
        final URLConnection connection = url.openConnection();
        connection.setConnectTimeout(timeout);
        connection.setReadTimeout(timeout);
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.connect();
        return new JavaConnection(connection);
    }
    
    /** URL. */
    private final URL url;
    /** Connection timeout. */
    private int timeout = 0;
}

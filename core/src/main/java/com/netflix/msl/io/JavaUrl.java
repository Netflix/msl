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
     * An implementation of the {@link Connection} interface backed by the
     * built-in Java {@link URLConnection} class.
     */
    public class JavaConnection implements Connection {
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
            return conn.getInputStream();
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

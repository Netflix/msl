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

/**
 * The URL interface provides access to an input stream and output stream tied
 * to a specific URL.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface Url {
    /**
     * The Connection interface represents a communication link between the
     * application and a URL.
     */
    public static interface Connection {
        /**
         * Returns an input stream that reads from this connection.
         * 
         * @return an input stream that reads from this connection.
         * @throws IOException if an I/O error occurs while creating the input
         *         stream.
         */
        public InputStream getInputStream() throws IOException;
        
        /**
         * Returns an output stream that writes to this connection.
         * 
         * @return an output stream that writes to this connection.
         * @throws IOException if an I/O error occurs while creating the output
         *         stream.
         */
        public OutputStream getOutputStream() throws IOException;
    }
    
    /**
     * Set the timeout.
     *
     * @param timeout connect/read/write timeout in milliseconds.
     */
    public void setTimeout(final int timeout);
    
    /**
     * Open a new connection to the target location.
     *
     * @return a {@link #Connection} linking to the URL.
     * @throws IOException if an I/O exception occurs.
     */
    public Connection openConnection() throws IOException;
}

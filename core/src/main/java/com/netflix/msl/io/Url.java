/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
         * <p>Returns an input stream that reads from this connection.</p>
         * 
         * <p>Asking for the input stream must not prevent use of the output
         * stream, but reading from the input stream may prevent further
         * writing to the output stream.</p>
         * 
         * <p>The returned input stream must support
         * {@link InputStream#mark(int)}, {@link InputStream#reset()}, and
         * {@link InputStream#skip(long)} if you wish to use it for more than
         * one MSL message.</p> 
         * 
         * @return an input stream that reads from this connection.
         * @throws IOException if an I/O error occurs while creating the input
         *         stream.
         */
        public InputStream getInputStream() throws IOException;
        
        /**
         * <p>Returns an output stream that writes to this connection.</p>
         * 
         * <p>Asking for the output stream must not prevent use of the input
         * stream, but writing to the output stream may prevent further reading
         * from the input stream.</p>
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
     * @return a {@link Connection} linking to the URL.
     * @throws IOException if an I/O exception occurs.
     */
    public Connection openConnection() throws IOException;
}

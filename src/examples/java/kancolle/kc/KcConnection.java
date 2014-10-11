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
package kancolle.kc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <p>A local URL connection backed by piped input and output streams. The
 * registered protocol is "kc".</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KcConnection extends URLConnection {
    /** Known servers. */
    private static final Map<String,KanColleServer> servers = new ConcurrentHashMap<String,KanColleServer>();
    
    /**
     * <p>Register a KanColle server. It can then be connected by using a URL
     * {@code kc://identity} where {@code identity} is the server identity.</p>
     * 
     * @param server KanColle server.
     */
    public static void addServer(final KanColleServer server) {
        final String identity = server.getIdentity();
        servers.put(identity, server);
    }
    
    /**
     * <p>Construct a URL connection to the specified URL.</p>
     * 
     * @param u the specified URL.
     */
    public KcConnection(final URL u) {
        super(u);
    }
    
    /* (non-Javadoc)
     * @see java.net.URLConnection#connect()
     */
    @Override
    public void connect() throws IOException {
        // Lookup the port identified in the URL.
        final String identity = url.getHost();
        final KanColleServer server = servers.get(identity);
        if (server == null)
            throw new IOException("No server registered with the identity " + identity + ".");
        
        // Create the piped input and output streams.
        final PipedOutputStream portOutput = new PipedOutputStream();
        in = new PipedInputStream(portOutput);
        final PipedInputStream portInput = new PipedInputStream();
        out = new PipedOutputStream(portInput);
        
        // Connect to the port.
        server.connect(portInput, portOutput);
    }

    /* (non-Javadoc)
     * @see java.net.URLConnection#getInputStream()
     */
    @Override
    public InputStream getInputStream() {
        return in;
    }

    /* (non-Javadoc)
     * @see java.net.URLConnection#getOutputStream()
     */
    @Override
    public OutputStream getOutputStream() throws IOException {
        return out;
    }

    /** Input stream to read from the URL. */
    private InputStream in;
    /** Output stream to write to the URL. */
    private OutputStream out;
}

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

/**
 * <p>A KanColle server accepts connections and is identified by its MSL entity
 * identity.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface KanColleServer {
    /**
     * <p>Return the server identity.</p>
     * 
     * @return the server identity.
     */
    public String getIdentity();
    
    /**
     * <p>Establish a connection between the remote entity and this server. The
     * input stream is used by the server to read data from the remote entity.
     * The output stream is used by the server to send data to the remote
     * entity.</p>
     * 
     * @param in input stream from remote entity.
     * @param out output stream to remote entity.
     * @throws IOException if the connection cannot be established.
     */
    public void connect(final InputStream in, final OutputStream out) throws IOException;
}

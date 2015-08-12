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
package kancolle.msg;

import java.io.IOException;
import java.util.List;

import kancolle.keyx.DiffieHellmanManager;

import com.netflix.msl.msg.MessageOutputStream;

/**
 * <p>Report the accumulated ship's log to a port.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ReportMessageContext extends KanColleMessageContext {
    /**
     * Create a new report message sent by the specified officer.
     * 
     * @param name reporting officer name.
     * @param fingerprint reporting officer fingerprint. May be null if the
     *        officer is already authenticated (a user ID token exists).
     * @param records report records.
     * @param keyxManager key exchange manager.
     */
    public ReportMessageContext(final String name, final byte[] fingerprint, final List<String> records, final DiffieHellmanManager keyxManager) {
        super(name, fingerprint, keyxManager);
        if (name == null)
            throw new NullPointerException("Reports must specify an officer name.");
        this.records = records;
    }

    @Override
    public void write(final MessageOutputStream output) throws IOException {
        MessageProcessor.report(output, records);
    }
    
    /** Report records. */
    private final List<String> records;
}

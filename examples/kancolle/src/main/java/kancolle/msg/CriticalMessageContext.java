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
 * <p>Send a critical report to a specific port.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class CriticalMessageContext extends ReportMessageContext {
    /**
     * Create a new critical report message sent by the specified officer.
     * 
     * @param name reporting officer name.
     * @param fingerprint reporting officer fingerprint. May be null if the
     *        officer is already authenticated (a user ID token exists).
     * @param callsign the intended naval port recipient.
     * @param records report records.
     * @param keyxManager key exchange manager.
     */
    public CriticalMessageContext(final String name, final byte[] fingerprint, final String callsign, final List<String> records, final DiffieHellmanManager keyxManager) {
        super(name, fingerprint, records, keyxManager);
        if (callsign == null)
            throw new NullPointerException("Critical reports must specify a naval port recipient.");
        this.callsign = callsign;
        this.records = records;
    }

    @Override
    public String getRemoteEntityIdentity() {
        return callsign;
    }
    
    @Override
    public boolean isNonReplayable() {
        return true;
    }

    @Override
    public void write(final MessageOutputStream output) throws IOException {
        MessageProcessor.critical(output, records);
    }
    
    /** Recipient naval port callsign. */
    private final String callsign;
    /** Report records. */
    private final List<String> records;
}

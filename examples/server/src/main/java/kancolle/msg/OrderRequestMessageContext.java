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

import kancolle.keyx.DiffieHellmanManager;

import com.netflix.msl.msg.MessageOutputStream;

/**
 * <p>Request orders.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class OrderRequestMessageContext extends KanColleMessageContext {
    /**
     * Create a new order request message sent by the specified officer.
     * 
     * @param name reporting officer name.
     * @param fingerprint reporting officer fingerprint. May be null if the
     *        officer is already authenticated (a user ID token exists).
     * @param keyxManager key exchange manager.
     */
    public OrderRequestMessageContext(final String name, final byte[] fingerprint, final DiffieHellmanManager keyxManager) {
        super(name, fingerprint, keyxManager);
        if (name == null)
            throw new NullPointerException("Reports must specify an officer name.");
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }

    @Override
    public void write(final MessageOutputStream output) throws IOException {
        // TODO Auto-generated method stub

    }
}

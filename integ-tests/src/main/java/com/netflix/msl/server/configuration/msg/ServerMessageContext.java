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
package com.netflix.msl.server.configuration.msg;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MockMessageContext;
import com.netflix.msl.server.configuration.util.ServerMslContext;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * User: skommidi
 * Date: 7/21/14
 */
public class ServerMessageContext extends MockMessageContext {

    private byte[] buffer;

    /**
     * Create a new test message context.
     * 
     * @param mslCtx MSL context.
     * @param payloadBytes application data to write.
     * @param messageEncrypted true if the message must be encrypted.
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     * @throws MslKeyExchangeException if there is an error accessing Diffie-
     *         Hellman parameters.
     */
    public ServerMessageContext(final ServerMslContext mslCtx, final byte[] payloadBytes, final boolean messageEncrypted) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslKeyExchangeException {
        super(mslCtx, null, UserAuthenticationScheme.EMAIL_PASSWORD);
        super.setUserAuthData(null);
        super.setKeyRequestData(new HashSet<KeyRequestData>());
        super.setEncrypted(messageEncrypted);
        this.buffer = payloadBytes;
    }

    public void setBuffer(final byte[] buffer) {
        this.buffer = buffer;
    }

    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.write(buffer);
        output.flush();
        output.close();
    }
}

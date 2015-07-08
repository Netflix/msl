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
package mslcli.client.msg;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

import mslcli.client.util.KeyRequestDataHandle;
import mslcli.client.util.UserAuthenticationDataHandle;

/**
 * Client Request message context
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ClientRequestMessageContext implements MessageContext {
    private final boolean                    isEncrypted;
    private final boolean                    isIntegrityProtected;
    private final boolean                    isNonReplayable;
    private final UserAuthenticationDataHandle userAuthenticationDataHandle;
    private final String                     userId; 
    private final KeyRequestDataHandle       keyRequestDataHandle; 
    private final byte[]                     payload;
    private final Map<String,ICryptoContext> cryptoContexts;

    /**
     * <p>Create a new request context.
     * <p/>
     *
     * @param isEncrypted true if message is to be encrypted, false otherwise
     * @param isIntegrityProtected true if message is to be integrity protected, false otherwise
     * @param isNonReplayable true if message is to be marked as non-replayable, false otherwise
     * @param userId user ID, should be null if a message is not user-bound
     * @param userAuthDataHandle user authentication data getter
     * @param keyRequestDataHandle key request data getter
     * @param payload message payload
     */
    public ClientRequestMessageContext(final MessageConfig                msgCfg,
                                       final UserAuthenticationDataHandle userAuthenticationDataHandle,
                                       final KeyRequestDataHandle         keyRequestDataHandle,
                                       final byte[]                       payload
                                      )
    {
        if (msgCfg == null) {
            throw new IllegalArgumentException("NULL message config data");
        }
        if (userAuthenticationDataHandle == null) {
            throw new IllegalArgumentException("NULL user authentication data handle");
        }
        if (keyRequestDataHandle == null) {
            throw new IllegalArgumentException("NULL key request data handle");
        }
        this.isEncrypted          = msgCfg.isEncrypted;
        this.isIntegrityProtected = msgCfg.isIntegrityProtected;
        this.isNonReplayable      = msgCfg.isNonReplayable;
        this.userId               = msgCfg.userId;
        this.userAuthenticationDataHandle = userAuthenticationDataHandle;
        this.keyRequestDataHandle = keyRequestDataHandle;
        this.payload              = payload;
        this.cryptoContexts       = Collections.<String,ICryptoContext>emptyMap();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getCryptoContext()
     */
    @Override 
    public Map<String,ICryptoContext> getCryptoContexts() {
        return cryptoContexts;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getRecipient()
     */
    @Override
    public String getRecipient() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isEncrypted()
     */
    @Override
    public boolean isEncrypted() {
        return isEncrypted;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isIntegrityProtected()
     */
    @Override
    public boolean isIntegrityProtected() {
        return isIntegrityProtected;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isNonReplayable()
     */
    @Override
    public boolean isNonReplayable() {
        return isNonReplayable;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isRequestingTokens()
     */
    @Override
    public boolean isRequestingTokens() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserId()
     */
    @Override
    public String getUserId() {
        return userId;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserAuthData()
     */
    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        if ((reauthCode == null) && required) {
            return userAuthenticationDataHandle.getUserAuthenticationData();
        } else {
            return null;
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUser()
     */
    @Override
    public MslUser getUser() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getKeyRequestData()
     */
    @Override
    public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
        return keyRequestDataHandle.getKeyRequestData();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#updateServiceTokens()
     */
    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake)
        throws MslMessageException, MslCryptoException, MslEncodingException, MslException {
        // do nothing on client side
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        if (payload != null) {
            output.write(payload);
            output.flush();
            output.close();
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getDebugContext()
     */
    @Override
    public MessageDebugContext getDebugContext() {
        return null;
    }
}

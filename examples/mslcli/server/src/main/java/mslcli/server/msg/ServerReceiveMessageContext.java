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

package mslcli.server.msg;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

import mslcli.common.util.SharedUtil;

/**
 * <p>Example server message context for receiving messages.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ServerReceiveMessageContext implements MessageContext {
    /**
     * <p>Create a new receive message context.</p>
     * 
     * @param cryptoContexts service token crypto contexts.
     */
    public ServerReceiveMessageContext(final Map<String,ICryptoContext> cryptoContexts) {
        this.cryptoContexts = Collections.unmodifiableMap(cryptoContexts);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getCryptoContexts()
     */
    @Override
    public Map<String, ICryptoContext> getCryptoContexts() {
        return cryptoContexts;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getRemoteEntityIdentity()
     */
    @Override
    public String getRemoteEntityIdentity() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isEncrypted()
     */
    @Override
    public boolean isEncrypted() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isIntegrityProtected()
     */
    @Override
    public boolean isIntegrityProtected() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isNonReplayable()
     */
    @Override
    public boolean isNonReplayable() {
        return false;
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
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserAuthData(com.netflix.msl.msg.MessageContext.ReauthCode, boolean, boolean)
     */
    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        return null;
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
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#updateServiceTokens(com.netflix.msl.msg.MessageServiceTokenBuilder, boolean)
     */
    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) {
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getDebugContext()
     */
    @Override
    public MessageDebugContext getDebugContext() {
        return null;
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this);
    }

    /** Service token crypto contexts. */
    private final Map<String,ICryptoContext> cryptoContexts;
}

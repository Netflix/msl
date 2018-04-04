/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>A trusted services network message context used to receive client
 * messages suitable for use with
 * {@link MslControl#receive(com.netflix.msl.util.MslContext, MessageContext, java.io.InputStream, java.io.OutputStream, int)}.
 * Since this message context is only used for receiving messages, it cannot be
 * used to send application data back to the client and does not require
 * encryption or integrity protection.</p>
 * 
 * <p>The application may wish to override
 * {@link #updateServiceTokens(MessageServiceTokenBuilder, boolean)} to
 * modify any service tokens sent in handshake responses.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ServerReceiveMessageContext extends PublicMessageContext {
    /**
     * <p>Create a new receive message context.</p>
     * 
     * @param cryptoContexts service token crypto contexts. May be
     *        {@code null}.
     * @param dbgCtx optional message debug context. May be {@code null}.
     */
    public ServerReceiveMessageContext(final Map<String,ICryptoContext> cryptoContexts, final MessageDebugContext dbgCtx) {
        this.cryptoContexts = (cryptoContexts != null) ? new HashMap<String,ICryptoContext>(cryptoContexts) : new HashMap<String,ICryptoContext>();
        this.dbgCtx = dbgCtx;
    }

    @Override
    public Map<String, ICryptoContext> getCryptoContexts() {
        return Collections.unmodifiableMap(cryptoContexts);
    }

    @Override
    public String getRemoteEntityIdentity() {
        return null;
    }

    @Override
    public boolean isRequestingTokens() {
        return false;
    }

    @Override
    public String getUserId() {
        return null;
    }

    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        return null;
    }

    @Override
    public MslUser getUser() {
        return null;
    }

    @Override
    public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
        return Collections.emptySet();
    }
    
    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) {
    }

    @Override
    public void write(final MessageOutputStream output) throws IOException {
    }

    @Override
    public MessageDebugContext getDebugContext() {
        return dbgCtx;
    }
    
    /** Service token crypto contexts. */
    protected final Map<String,ICryptoContext> cryptoContexts;
    /** Message debug context. */
    protected final MessageDebugContext dbgCtx;
}

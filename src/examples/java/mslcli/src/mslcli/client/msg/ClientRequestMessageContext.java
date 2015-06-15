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
import com.netflix.msl.util.MslContext;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ClientRequestMessageContext implements MessageContext {
    private final MslContext                 mslCtx;
    private final boolean                    isEncrypted;
    private final boolean                    isIntegrityProtected;
    private final boolean                    isNonReplayable;
    private final UserAuthenticationData     userAuthData;
    private final String                     userId; 
    private final Set<KeyRequestData>        keyRequestDataSet; 
    private final byte[]                     payload;
    private final Map<String,ICryptoContext> cryptoContexts;

    /**
     * <p>Create a new request context.
     * <p/>
     * The message will be encrypted and non-replayable.
     *
     *
     *
     * @param ctx    MSL context.
     * @param userId user ID.
     * @param scheme user authentication scheme.
     * @param isMessageEncrypted
     * @param isIntegrityProtected
     * @throws java.security.NoSuchAlgorithmException
     *                         if a key generation algorithm is not
     *                         found.
     * @throws java.security.InvalidAlgorithmParameterException
     *                         if key generation parameters
     *                         are invalid.
     * @throws com.netflix.msl.MslCryptoException
     *                         if the service token crypto context keys are
     *                         the wrong length.
     * @throws com.netflix.msl.MslKeyExchangeException
     *                         if there is an error accessing Diffie-
     *                         Hellman parameters.
     */
    public ClientRequestMessageContext(final MslContext               mslCtx,
                                       final boolean                  isEncrypted,
                                       final boolean                  isIntegrityProtected,
                                       final boolean                  isNonReplayable,
                                       final String                   userId,
                                       final UserAuthenticationData   userAuthData,
                                       final Set<KeyRequestData>      keyRequestDataSet,
                                       final byte[]                   payload
                                      )
    {
        this.mslCtx               = mslCtx;
        this.isEncrypted          = isEncrypted;
        this.isIntegrityProtected = isIntegrityProtected;
        this.isNonReplayable      = isNonReplayable;
        this.userId               = userId;
        this.userAuthData         = userAuthData;
        this.keyRequestDataSet    = Collections.unmodifiableSet(keyRequestDataSet);
        this.payload              = payload;
        this.cryptoContexts       = Collections.<String,ICryptoContext>emptyMap();
    }

    @Override 
    public Map<String,ICryptoContext> getCryptoContexts() {
        return cryptoContexts;
    }

    @Override
    public String getRecipient() {
        return null;
    }

    @Override
    public boolean isEncrypted() {
        return isEncrypted;
    }

    @Override
    public boolean isIntegrityProtected() {
        return isIntegrityProtected;
    }

    @Override
    public boolean isNonReplayable() {
        return isNonReplayable;
    }

    /* Per Wes, even if returning false, MSL stack will still acquire
     * master and user tokens if they are not available, or use them
     * if they are available.
     */
    @Override
    public boolean isRequestingTokens() {
        return false;
    }

    @Override
    public String getUserId() {
        return userId;
    }

    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        if ((reauthCode == null) && required) {
            return userAuthData;
        } else {
            return null;
        }
    }

    @Override
    public MslUser getUser() {
        return null;
    }

    @Override
    public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
        return keyRequestDataSet;
    }

    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake)
        throws MslMessageException, MslCryptoException, MslEncodingException, MslException {
        // do nothing on client side
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MockMessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.write(payload);
        output.flush();
        output.close();
    }

    @Override
    public MessageDebugContext getDebugContext() {
        return null;
    }
}

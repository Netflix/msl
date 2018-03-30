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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import kancolle.keyx.DiffieHellmanManager;
import kancolle.userauth.OfficerAuthenticationData;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>Base message context with default security properties.</p>
 * 
 * <p>By default messages are encrypted and integrity-protected, but replayable
 * and not requesting tokens. No recipient is specified.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class KanColleMessageContext implements MessageContext {
    /**
     * <p>Create a new KanColle message context.</p>
     * 
     * <p>If the officer name is null then the message will not be associated
     * with a user.</p>
     * 
     * <p>If the key exchange manager is null then key request data will not be
     * included.</p>
     * 
     * @param name reporting officer name. May be null.
     * @param fingerprint reporting officer fingerprint. May be null if the
     *        officer is already authenticated (a user ID token exists).
     * @param keyxManager key exchange manager. May be null.
     */
    public KanColleMessageContext(final String name, final byte[] fingerprint, final DiffieHellmanManager keyxManager) {
        this.name = name;
        this.fingerprint = fingerprint;
        this.keyxManager = keyxManager;
    }
    
    /**
     * <p>No service token crypto contexts are provided.</p>
     * 
     * @return the empty map.
     * @see com.netflix.msl.msg.MessageContext#getCryptoContexts()
     */
    @Override
    public Map<String, ICryptoContext> getCryptoContexts() {
        return Collections.emptyMap();
    }

    /**
     * <p>No recipient is specified.</p>
     * 
     * @return {@code null}.
     * @see com.netflix.msl.msg.MessageContext#getRemoteEntityIdentity()
     */
    @Override
    public String getRemoteEntityIdentity() {
        return null;
    }

    /**
     * <p>Messages are encrypted.</p>
     * 
     * @return {@code true}.
     * @see com.netflix.msl.msg.MessageContext#isEncrypted()
     */
    @Override
    public boolean isEncrypted() {
        return true;
    }

    /**
     * <p>Messages are integrity-protected.</p>
     * 
     * @return {@code true}.
     * @see com.netflix.msl.msg.MessageContext#isIntegrityProtected()
     */
    @Override
    public boolean isIntegrityProtected() {
        return true;
    }

    /**
     * <p>Messages are replayable.</p>
     * 
     * @return {@code false}.
     * @see com.netflix.msl.msg.MessageContext#isNonReplayable()
     */
    @Override
    public boolean isNonReplayable() {
        return false;
    }

    /**
     * <p>Messages are not requesting tokens.</p>
     * 
     * @return {@code false}.
     * @see com.netflix.msl.msg.MessageContext#isRequestingTokens()
     */
    @Override
    public boolean isRequestingTokens() {
        return false;
    }

    /**
     * <p>Messages may be associated with a user depending on what was passed
     * in at construction.</p>
     * 
     * @return the officer name or {@code null} if the message is not
     *         associated with a user.
     * @see com.netflix.msl.msg.MessageContext#getUserId()
     */
    @Override
    public String getUserId() {
        return name;
    }

    /**
     * <p>If an officer was specified at construction, returns user
     * authentication data if required is {@code true} and a fingerprint was
     * also provided at construction. Otherwise {@code null} is returned.</p>
     * 
     * @return the user authentication data or {@code null}.
     * @see com.netflix.msl.msg.MessageContext#getUserAuthData(com.netflix.msl.msg.MessageContext.ReauthCode, boolean, boolean)
     */
    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        // If no officer is specified then return null.
        if (name == null)
            return null;
        
        // If a reauth code is provided then return null indicating failure;
        // we don't have a different officer.
        if (reauthCode != null)
            return null;
        
        // If required and we have the fingerprint then return the user
        // authentication data.
        if (required && fingerprint != null)
            return new OfficerAuthenticationData(name, fingerprint);
        
        // Otherwise don't return the user authentication data. Maybe a user ID
        // token exists.
        return null;
    }

    /**
     * <p>Messages do not have a user assigned.</p>
     * 
     * @return {@code null}.
     * @see com.netflix.msl.msg.MessageContext#getUser()
     */
    @Override
    public MslUser getUser() {
        return null;
    }

    /**
     * <p>Messages may include key request data if a key exchange manager was
     * provided at construction.</p>
     * 
     * @return the key request data, which may be the empty set.
     * @see com.netflix.msl.msg.MessageContext#getKeyRequestData()
     */
    @Override
    public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
        // If a key exchange manager was provided then return key request data.
        if (keyxManager != null)
            return new HashSet<KeyRequestData>(Arrays.asList(keyxManager.getRequestData()));
        return Collections.emptySet();
    }

    /**
     * <p>Service tokens are not modified.</p>
     * 
     * @see com.netflix.msl.msg.MessageContext#updateServiceTokens(com.netflix.msl.msg.MessageServiceTokenBuilder, boolean)
     */
    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) {
    }

    /**
     * <p>No message debug context is provided.</p>
     * 
     * @return {@code null}.
     * @see com.netflix.msl.msg.MessageContext#getDebugContext()
     */
    @Override
    public MessageDebugContext getDebugContext() {
        return null;
    }

    /** Reporting officer name. */
    private final String name;
    /** Reporting officer fingerprint. */
    private final byte[] fingerprint;
    /** Key exchange manager. */
    private final DiffieHellmanManager keyxManager;
}

/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.msg;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.ProxyMslError;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>A trusted services network message context used to generate server
 * messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class RespondMessageContext implements MessageContext {
    /**
     * <p>Create a new receive message context.</p>
     * 
     * @param appdata the application data to include in the response.
     * @param entityServiceTokens entity-associated service token name/value
     *        pairs.
     * @param userServiceTokens user-associated service token name/value pairs.
     * @param cryptoContext default service token crypto context.
     * @param user optional user to attach to the response. May be {@code null}.
     * @param dbgCtx optional message debug context. May be {@code null}.
     */
    public RespondMessageContext(final byte[] appdata, final Map<String,byte[]> entityServiceTokens, final Map<String,byte[]> userServiceTokens, final ICryptoContext cryptoContext, final MslUser user, final MessageDebugContext dbgCtx) {
        this.appdata = appdata;
        this.entityServiceTokens = entityServiceTokens;
        this.userServiceTokens = userServiceTokens;
        final Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
        cryptoContexts.put("", cryptoContext);
        this.cryptoContexts = Collections.unmodifiableMap(cryptoContexts);
        this.user = user;
        this.dbgCtx = dbgCtx;
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
        return true;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isIntegrityProtected()
     */
    @Override
    public boolean isIntegrityProtected() {
        return true;
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
        return user;
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
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) throws MslEncodingException, MslCryptoException, MslException {
        // Attach tokens. Throw an exception if a desired token cannot be
        // attached.
        for (final Map.Entry<String,byte[]> entry : entityServiceTokens.entrySet()) {
            final String name = entry.getKey();
            final byte[] value = entry.getValue();
            final boolean added = builder.addMasterBoundPrimaryServiceToken(name, value, true, null);
            if (!added)
                throw new MslMessageException(ProxyMslError.SERVICETOKEN_REQUIRES_MASTERTOKEN, name);
        }
        for (final Map.Entry<String,byte[]> entry : userServiceTokens.entrySet()) {
            final String name = entry.getKey();
            final byte[] value = entry.getValue();
            final boolean added = builder.addUserBoundPrimaryServiceToken(name, value, true, null);
            if (!added)
                throw new MslMessageException(ProxyMslError.SERVICETOKEN_REQUIRES_USERIDTOKEN, name);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.write(appdata);
        output.close();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getDebugContext()
     */
    @Override
    public MessageDebugContext getDebugContext() {
        return dbgCtx;
    }

    /** Application data. */
    private final byte[] appdata;
    /** Entity service tokens. */
    private final Map<String,byte[]> entityServiceTokens;
    /** User service tokens. */
    private final Map<String,byte[]> userServiceTokens;
    /** Service token crypto context. */
    private final Map<String,ICryptoContext> cryptoContexts;
    /** MSL user. */
    private final MslUser user;
    /** Message debug context. */
    private final MessageDebugContext dbgCtx;
}

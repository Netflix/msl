/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.tokens;

import javax.crypto.SecretKey;

import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.ProxyMslError;
import com.netflix.msl.util.MslContext;

/**
 * <p>This token factory accepts all tokens and renews tokens by echoing them
 * back.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class FailoverTokenFactory implements TokenFactory {
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRevoked(final MslContext ctx, final MasterToken masterToken) {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#acceptNonReplayableId(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, long)
     */
    @Override
    public MslError acceptNonReplayableId(final MslContext ctx, final MasterToken masterToken, final long nonReplayableId) throws MslException {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createMasterToken(com.netflix.msl.util.MslContext, java.lang.String, javax.crypto.SecretKey, javax.crypto.SecretKey)
     */
    @Override
    public MasterToken createMasterToken(final MslContext ctx, final String identity, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslException {
        // This method should not get called. If it does then throw an
        // exception to trigger processing by the proxied MSL service.
        throw new MslException(ProxyMslError.MASTERTOKEN_CREATION_REQUIRED);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRenewable(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRenewable(final MslContext ctx, final MasterToken masterToken) {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, javax.crypto.SecretKey, javax.crypto.SecretKey)
     */
    @Override
    public MasterToken renewMasterToken(final MslContext ctx, final MasterToken masterToken, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslException {
        return masterToken;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isUserIdTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslError isUserIdTokenRevoked(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken) {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createUserIdToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MslUser, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public UserIdToken createUserIdToken(final MslContext ctx, final MslUser user, final MasterToken masterToken) throws MslException {
        throw new MslException(ProxyMslError.USERIDTOKEN_CREATION_REQUIRED);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewUserIdToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.UserIdToken, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public UserIdToken renewUserIdToken(final MslContext ctx, final UserIdToken userIdToken, final MasterToken masterToken) throws MslException {
        return userIdToken;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createUser(com.netflix.msl.util.MslContext, java.lang.String)
     */
    @Override
    public MslUser createUser(final MslContext ctx, final String userdata) {
        return new NetflixMslUser(userdata);
    }
}

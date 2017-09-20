/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.tokens;

import javax.crypto.SecretKey;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.ProxyMslError;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.userauth.ProxyMslUser;
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
     * @see com.netflix.msl.tokens.TokenFactory#createMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData, javax.crypto.SecretKey, javax.crypto.SecretKey, com.netflix.msl.io.MslObject)
     */
    @Override
    public MasterToken createMasterToken(final MslContext ctx, final EntityAuthenticationData entityAuthData, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslEncodingException, MslCryptoException, MslException {
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
     * @see com.netflix.msl.tokens.TokenFactory#renewMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, javax.crypto.SecretKey, javax.crypto.SecretKey, com.netflix.msl.io.MslObject)
     */
    @Override
    public MasterToken renewMasterToken(final MslContext ctx, final MasterToken masterToken, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslException {
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
        return new ProxyMslUser(userdata);
    }
}

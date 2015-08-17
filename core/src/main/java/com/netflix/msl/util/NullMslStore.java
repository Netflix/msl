/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.util;

import java.util.Collections;
import java.util.Set;

import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;

/**
 * <p>A MSL store where all operations are no-ops.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NullMslStore implements MslStore {
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#setCryptoContext(com.netflix.msl.tokens.MasterToken, com.netflix.msl.crypto.ICryptoContext)
     */
    @Override
    public void setCryptoContext(final MasterToken masterToken, final ICryptoContext cryptoContext) {
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getMasterToken()
     */
    @Override
    public MasterToken getMasterToken() {
        return null;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getNonReplayableId(com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public long getNonReplayableId(final MasterToken masterToken) {
        return 1;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getCryptoContext(com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public ICryptoContext getCryptoContext(final MasterToken masterToken) {
        return null;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#removeCryptoContext(com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public void removeCryptoContext(final MasterToken masterToken) {
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#clearCryptoContexts()
     */
    @Override
    public void clearCryptoContexts() {
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#addUserIdToken(java.lang.String, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public void addUserIdToken(final String userId, final UserIdToken userIdToken) {
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getUserIdToken(java.lang.String)
     */
    @Override
    public UserIdToken getUserIdToken(final String userId) {
        return null;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#removeUserIdToken(com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public void removeUserIdToken(final UserIdToken userIdToken) {
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#clearUserIdTokens()
     */
    @Override
    public void clearUserIdTokens() {
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#addServiceTokens(java.util.Set)
     */
    @Override
    public void addServiceTokens(final Set<ServiceToken> tokens) {
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getServiceTokens(com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public Set<ServiceToken> getServiceTokens(final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        // Validate arguments.
        if (userIdToken != null) {
            if (masterToken == null)
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NULL);
            if (!userIdToken.isBoundTo(masterToken))
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.getMasterTokenSerialNumber() + "; mt " + masterToken.getSerialNumber());
        }
        
        return Collections.emptySet();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#removeServiceTokens(java.lang.String, com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public void removeServiceTokens(final String name, final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        // Validate arguments.
        if (userIdToken != null && masterToken != null &&
            !userIdToken.isBoundTo(masterToken))
        {
            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.getMasterTokenSerialNumber() + "; mt " + masterToken.getSerialNumber());
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#clearServiceTokens()
     */
    @Override
    public void clearServiceTokens() {
    }
}

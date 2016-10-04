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

package mslcli.common.util;

import java.util.Set;

import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslStore;

/**
 * <p>
 * Wrapper class for MslStore to enable selective call interception by deriving from this class.
 * Extending this class allows overwriting selected method in order to change their behavior,
 * for reporting, testing, etc.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class MslStoreWrapper implements MslStore {
    /** target MslStore instance to which all calls are delegated */
    private final MslStore mslStore;

    /**
     * Ctor.
     *
     * @param mslStore target MslStore instance to which all calls are delegated
     */
    public MslStoreWrapper(final MslStore mslStore) {
        if (mslStore == null) {
            throw new IllegalArgumentException("NULL MSL Store");
        }
        if (mslStore instanceof MslStoreWrapper) {
            throw new IllegalArgumentException("MSL Store is MslStoreWrapper instance");
        }
        this.mslStore = mslStore;
    }

    /**
     * @return underlying instance of MslStore
     */
    public final MslStore getMslStore() {
        return mslStore;
    }

    /**
     * @see com.netflix.msl.util.MslStore#setCryptoContext(MasterToken,ICryptoContext)
     */
    @Override
    public void setCryptoContext(final MasterToken masterToken, final ICryptoContext cryptoContext) {
        mslStore.setCryptoContext(masterToken, cryptoContext);
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#getMasterToken()
     */
    @Override
    public MasterToken getMasterToken() {
        return mslStore.getMasterToken();
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#getNonReplayableId(MasterToken)
     */
    @Override
    public long getNonReplayableId(final MasterToken masterToken) {
        return mslStore.getNonReplayableId(masterToken);
    }

    /**
     * @see com.netflix.msl.util.MslStore#getCryptoContext(MasterToken)
     */
    @Override
    public ICryptoContext getCryptoContext(final MasterToken masterToken) {
        return mslStore.getCryptoContext(masterToken);
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#removeCryptoContext(MasterToken)
     */
    @Override
    public void removeCryptoContext(final MasterToken masterToken) {
        mslStore.removeCryptoContext(masterToken);
    }

    /**
     * @see com.netflix.msl.util.MslStore#clearCryptoContexts()
     */
    @Override
    public void clearCryptoContexts() {
        mslStore.clearCryptoContexts();
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#addUserIdToken(String,UserIdToken)
     */
    @Override
    public void addUserIdToken(final String userId, final UserIdToken userIdToken) throws MslException {
        mslStore.addUserIdToken(userId, userIdToken);
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#getUserIdToken(String)
     */
    @Override
    public UserIdToken getUserIdToken(final String userId) {
        return mslStore.getUserIdToken(userId);
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#removeUserIdToken(UserIdToken)
     */
    @Override
    public void removeUserIdToken(final UserIdToken userIdToken) {
        mslStore.removeUserIdToken(userIdToken);
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#clearUserIdTokens()
     */
    @Override
    public void clearUserIdTokens() {
        mslStore.clearUserIdTokens();
    }
    
    /**
     * @see com.netflix.msl.util.MslStore#addServiceTokens(Set)
     */
    @Override
    public void addServiceTokens(final Set<ServiceToken> tokens) throws MslException {
        mslStore.addServiceTokens(tokens);
    }

    /**
     * @see com.netflix.msl.util.MslStore#getServiceTokens(MasterToken,UserIdToken)
     */
    @Override
    public Set<ServiceToken> getServiceTokens(final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        return mslStore.getServiceTokens(masterToken, userIdToken);
    }

    /**
     * @see com.netflix.msl.util.MslStore#removeServiceTokens(String,MasterToken,UserIdToken)
     */
    @Override
    public void removeServiceTokens(final String name, final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        mslStore.removeServiceTokens(name, masterToken, userIdToken);
    }

    /**
     * @see com.netflix.msl.util.MslStore#clearServiceTokens()
     */
    @Override
    public void clearServiceTokens() {
        mslStore.clearServiceTokens();
    }

    @Override
    public String toString() {
        return SharedUtil.toString(mslStore);
    }
}

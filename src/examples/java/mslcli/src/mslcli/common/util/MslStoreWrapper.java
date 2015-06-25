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
 * Wrapper class for MslStore to enable selective call interception by deriving from this class
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class MslStoreWrapper implements MslStore {
    private MslStore mslStore;

    /**
     * package-private so only AppContext can call it
     */
    final void setMslStore(final MslStore mslStore) {
        if (mslStore == null) {
            throw new IllegalArgumentException("NULL MSL Store");
        }
        if (mslStore instanceof MslStoreWrapper) {
            throw new IllegalArgumentException("MSL Store is MslStoreWrapper instance");
        }
        this.mslStore = mslStore;
    }

    @Override
    public void setCryptoContext(final MasterToken masterToken, final ICryptoContext cryptoContext) {
        mslStore.setCryptoContext(masterToken, cryptoContext);
    }
    
    @Override
    public MasterToken getMasterToken() {
        return mslStore.getMasterToken();
    }
    
    @Override
    public long getNonReplayableId(final MasterToken masterToken) {
        return mslStore.getNonReplayableId(masterToken);
    }

    @Override
    public ICryptoContext getCryptoContext(final MasterToken masterToken) {
        return mslStore.getCryptoContext(masterToken);
    }
    
    @Override
    public void removeCryptoContext(final MasterToken masterToken) {
        mslStore.removeCryptoContext(masterToken);
    }

    @Override
    public void clearCryptoContexts() {
        mslStore.clearCryptoContexts();
    }
    
    @Override
    public void addUserIdToken(final String userId, final UserIdToken userIdToken) throws MslException {
        mslStore.addUserIdToken(userId, userIdToken);
    }
    
    @Override
    public UserIdToken getUserIdToken(final String userId) {
        return mslStore.getUserIdToken(userId);
    }
    
    @Override
    public void removeUserIdToken(final UserIdToken userIdToken) {
        mslStore.removeUserIdToken(userIdToken);
    }
    
    @Override
    public void clearUserIdTokens() {
        mslStore.clearUserIdTokens();
    }
    
    @Override
    public void addServiceTokens(final Set<ServiceToken> tokens) throws MslException {
        mslStore.addServiceTokens(tokens);
    }

    @Override
    public Set<ServiceToken> getServiceTokens(final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        return mslStore.getServiceTokens(masterToken, userIdToken);
    }

    @Override
    public void removeServiceTokens(final String name, final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        mslStore.removeServiceTokens(name, masterToken, userIdToken);
    }

    @Override
    public void clearServiceTokens() {
        mslStore.clearServiceTokens();
    }
}

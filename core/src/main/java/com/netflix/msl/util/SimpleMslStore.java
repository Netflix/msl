/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;

/**
 * <p>A simple MSL store that maintains state.</p>
 * 
 * <p>This class is thread-safe.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleMslStore implements MslStore {
    /**
     * Increments the provided non-replayable ID by 1, wrapping around to zero
     * if the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
     * 
     * @param id the non-replayable ID to increment.
     * @return the non-replayable ID + 1.
     * @throws MslInternalException if the provided non-replayable ID is out of
     *         range.
     */
    private static long incrementNonReplayableId(final long id) {
        if (id < 0 || id > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Non-replayable ID " + id + " is outside the valid range.");
        return (id == MslConstants.MAX_LONG_VALUE) ? 0 : id + 1;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#setCryptoContext(com.netflix.msl.tokens.MasterToken, com.netflix.msl.crypto.ICryptoContext)
     */
    @Override
    public void setCryptoContext(final MasterToken masterToken, final ICryptoContext cryptoContext) {
        if (cryptoContext == null)
            removeCryptoContext(masterToken);
        else
            cryptoContexts.put(masterToken, cryptoContext);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getMasterToken()
     */
    @Override
    public MasterToken getMasterToken() {
        MasterToken masterToken = null;
        for (final MasterToken storedMasterToken : cryptoContexts.keySet()) {
            if (masterToken == null || storedMasterToken.isNewerThan(masterToken))
                masterToken = storedMasterToken;
        }
        return masterToken;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getNonReplayableId(com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public synchronized long getNonReplayableId(final MasterToken masterToken) {
        // Return the next largest non-replayable ID, or 1 if there is none.
        final long serialNumber = masterToken.getSerialNumber();
        final long currentId = (nonReplayableIds.containsKey(serialNumber))
            ? nonReplayableIds.get(serialNumber)
            : 0;
        final long nextId = incrementNonReplayableId(currentId);
        nonReplayableIds.put(serialNumber, nextId);
        return nextId;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getCryptoContext(com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public ICryptoContext getCryptoContext(final MasterToken masterToken) {
        return cryptoContexts.get(masterToken);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#removeCryptoContext(com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public synchronized void removeCryptoContext(final MasterToken masterToken) {
        // We must perform the removal operations in reverse-dependency order.
        // This ensures the store is in the correct state, allowing all logical
        // and safety checks to pass.
        //
        // First any bound user ID tokens are removed (which first removes any
        // service tokens bound to those user ID tokens), then bound service
        // tokens, and finally the non-replayable ID and crypto context and
        // master token pair.
        if (cryptoContexts.containsKey(masterToken)) {
            // Look for a second master token with the same serial number. If
            // there is one, then just remove this master token and its crypto
            // context but do not remove any bound user ID tokens, service
            // tokens, or the non-replayable ID as those are still associated
            // with the master token that remains.
            final long serialNumber = masterToken.getSerialNumber();
            for (final MasterToken token : cryptoContexts.keySet()) {
                if (!token.equals(masterToken) && token.getSerialNumber() == serialNumber) {
                    cryptoContexts.remove(masterToken);
                    return;
                }
            }
            
            // Remove bound user ID tokens and service tokens.
            for (final UserIdToken userIdToken : userIdTokens.values()) {
                if (userIdToken.isBoundTo(masterToken))
                    removeUserIdToken(userIdToken);
            }
            try {
                removeServiceTokens(null, masterToken, null);
            } catch (final MslException e) {
                // This should not happen since we are only providing a master
                // token.
                throw new MslInternalException("Unexpected exception while removing master token bound service tokens.", e);
            }
            
            // Remove the non-replayable ID.
            nonReplayableIds.remove(serialNumber);
            
            // Finally remove the crypto context.
            cryptoContexts.remove(masterToken);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#clearCryptoContexts()
     */
    @Override
    public synchronized void clearCryptoContexts() {
        cryptoContexts.clear();
        nonReplayableIds.clear();
        userIdTokens.clear();
        uitServiceTokens.clear();
        mtServiceTokens.clear();
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#addUserIdToken(java.lang.String, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public void addUserIdToken(final String userId, final UserIdToken userIdToken) throws MslException {
        boolean foundMasterToken = false;
        for (final MasterToken masterToken : cryptoContexts.keySet()) {
            if (userIdToken.isBoundTo(masterToken)) {
                foundMasterToken = true;
                break;
            }
        }
        if (!foundMasterToken)
            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NOT_FOUND, "uit mtserialnumber " + userIdToken.getMasterTokenSerialNumber());
        userIdTokens.put(userId, userIdToken);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getUserIdToken(java.lang.String)
     */
    @Override
    public UserIdToken getUserIdToken(final String userId) {
        return userIdTokens.get(userId);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#removeUserIdToken(com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public void removeUserIdToken(final UserIdToken userIdToken) {
        // Find the master token this user ID token is bound to.
        MasterToken masterToken = null;
        for (final MasterToken token : cryptoContexts.keySet()) {
            if (userIdToken.isBoundTo(token)) {
                masterToken = token;
                break;
            }
        }
        
        // If we didn't find a master token we shouldn't be able to find a user
        // ID token, but it doesn't hurt to try anyway and clean things up.
        for (final Entry<String,UserIdToken> entry : userIdTokens.entrySet()) {
            if (entry.getValue().equals(userIdToken)) {
                try {
                    removeServiceTokens(null, masterToken, userIdToken);
                } catch (final MslException e) {
                    // This should not happen since we have already confirmed
                    // that the user ID token is bound to the master token.
                    throw new MslInternalException("Unexpected exception while removing user ID token bound service tokens.", e);
                }
                final String userId = entry.getKey();
                userIdTokens.remove(userId);
                break;
            }
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#clearUserIdTokens()
     */
    @Override
    public void clearUserIdTokens() {
        final List<UserIdToken> tokens = new ArrayList<UserIdToken>(userIdTokens.values());
        for (final UserIdToken token : tokens)
            removeUserIdToken(token);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#addServiceTokens(java.util.Set)
     */
    @Override
    public synchronized void addServiceTokens(final Set<ServiceToken> tokens) throws MslException {
        // Verify we recognize the bound service tokens.
        for (final ServiceToken token : tokens) {
            // Verify master token bound.
            if (token.isMasterTokenBound()) {
                boolean foundMasterToken = false;
                for (final MasterToken masterToken : cryptoContexts.keySet()) {
                    if (token.isBoundTo(masterToken)) {
                        foundMasterToken = true;
                        break;
                    }
                }
                if (!foundMasterToken)
                    throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_NOT_FOUND, "st mtserialnumber " + token.getMasterTokenSerialNumber());
            }
            
            // Verify user token bound.
            if (token.isUserIdTokenBound()) {
                boolean foundUserIdToken = false;
                for (final UserIdToken userIdToken : userIdTokens.values()) {
                    if (token.isBoundTo(userIdToken)) {
                        foundUserIdToken = true;
                        break;
                    }
                }
                if (!foundUserIdToken)
                    throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_NOT_FOUND, "st uitserialnumber " + token.getUserIdTokenSerialNumber());
            }
        }
        
        // Add service tokens.
        for (final ServiceToken token : tokens) {
            // Unbound?
            if (token.isUnbound()) {
                unboundServiceTokens.add(token);
                continue;
            }
            
            // Master token bound?
            if (token.isMasterTokenBound()) {
                Set<ServiceToken> tokenSet = mtServiceTokens.get(token.getMasterTokenSerialNumber());
                if (tokenSet == null) {
                    tokenSet = new HashSet<ServiceToken>();
                    mtServiceTokens.put(token.getMasterTokenSerialNumber(), tokenSet);
                }
                tokenSet.add(token);
            }
            
            // User ID token bound?
            if (token.isUserIdTokenBound()) {
                Set<ServiceToken> tokenSet = uitServiceTokens.get(token.getUserIdTokenSerialNumber());
                if (tokenSet == null) {
                    tokenSet = new HashSet<ServiceToken>();
                    uitServiceTokens.put(token.getUserIdTokenSerialNumber(), tokenSet);
                }
                tokenSet.add(token);
            }
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#getServiceTokens(com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public synchronized Set<ServiceToken> getServiceTokens(final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        // Validate arguments.
        if (userIdToken != null) {
            if (masterToken == null)
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NULL);
            if (!userIdToken.isBoundTo(masterToken))
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.getMasterTokenSerialNumber() + "; mt " + masterToken.getSerialNumber());
        }
        
        // Grab service tokens. We start with the set of unbound service
        // tokens.
        final Set<ServiceToken> serviceTokens = new HashSet<ServiceToken>();
        serviceTokens.addAll(unboundServiceTokens);
        // If we have a master token add the set of master token bound service
        // tokens that are not bound to any user ID tokens.
        if (masterToken != null) {
            final Set<ServiceToken> mtTokens = mtServiceTokens.get(masterToken.getSerialNumber());
            if (mtTokens != null) {
                for (final ServiceToken mtToken : mtTokens) {
                    if (!mtToken.isUserIdTokenBound())
                        serviceTokens.add(mtToken);
                }
            }
        }
        // If we have a user ID token (and because of the check above a master
        // token) add the set of user ID token bound service tokens that are
        // also bound to the same master token.
        if (userIdToken != null) {
            final Set<ServiceToken> uitTokens = uitServiceTokens.get(userIdToken.getSerialNumber());
            if (uitTokens != null) {
                for (final ServiceToken uitToken : uitTokens) {
                    if (uitToken.isBoundTo(masterToken))
                        serviceTokens.add(uitToken);
                }
            }
        }

        return serviceTokens;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#removeServiceTokens(java.lang.String, com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public synchronized void removeServiceTokens(final String name, final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        // Validate arguments.
        if (userIdToken != null && masterToken != null &&
            !userIdToken.isBoundTo(masterToken))
        {
            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.getMasterTokenSerialNumber() + "; mt " + masterToken.getSerialNumber());
        }
        
        // If only a name was provided remove all unbound tokens with that
        // name.
        if (name != null && masterToken == null && userIdToken == null) {
            // Remove all unbound tokens with the specified name.
            final Iterator<ServiceToken> unboundTokens = unboundServiceTokens.iterator();
            while (unboundTokens.hasNext()) {
                if (unboundTokens.next().getName().equals(name))
                    unboundTokens.remove();
            }
        }
        
        // If a master token was provided but no user ID token was provided,
        // remove all tokens bound to the master token. If a name was also
        // provided then limit removal to tokens with the specified name.
        if (masterToken != null && userIdToken == null) {
            final Set<ServiceToken> tokenSet = mtServiceTokens.get(masterToken.getSerialNumber());
            if (tokenSet != null) {
                final Iterator<ServiceToken> tokens = tokenSet.iterator();
                while (tokens.hasNext()) {
                    final ServiceToken token = tokens.next();
                    
                    // Skip if the name was provided and it does not match.
                    if (name != null && !token.getName().equals(name))
                        continue;
                    
                    // Remove the token.
                    tokens.remove();
                }
            }
        }
        
        // If a user ID token was provided remove all tokens bound to the user
        // ID token. If a name was also provided then limit removal to tokens
        // with the specified name.
        if (userIdToken != null) {
            final Set<ServiceToken> tokenSet = uitServiceTokens.get(userIdToken.getSerialNumber());
            if (tokenSet != null) {
                final Iterator<ServiceToken> tokens = tokenSet.iterator();
                while (tokens.hasNext()) {
                    final ServiceToken token = tokens.next();
                    
                    // Skip if the name was provided and it does not match.
                    if (name != null && !token.getName().equals(name))
                        continue;
                    
                    // Remove the token.
                    tokens.remove();
                }
            }
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslStore#clearServiceTokens()
     */
    @Override
    public synchronized void clearServiceTokens() {
        unboundServiceTokens.clear();
        mtServiceTokens.clear();
        uitServiceTokens.clear();
    }
    
    /** Map of master tokens onto crypto contexts. */
    private final Map<MasterToken,ICryptoContext> cryptoContexts = new ConcurrentHashMap<MasterToken,ICryptoContext>();
    /** Map of local user IDs onto User ID tokens. */
    private final Map<String,UserIdToken> userIdTokens = new ConcurrentHashMap<String,UserIdToken>();
    
    /** Map of master token serial numbers onto non-replayable IDs. */
    private final Map<Long,Long> nonReplayableIds = new HashMap<Long,Long>();
    
    /** Set of unbound service tokens. */
    private final Set<ServiceToken> unboundServiceTokens = new HashSet<ServiceToken>();
    /** Map of master token serial numbers onto service tokens. */
    private final Map<Long,Set<ServiceToken>> mtServiceTokens = new HashMap<Long,Set<ServiceToken>>();
    /** Map of user ID token serial numbers onto service tokens. */
    private final Map<Long,Set<ServiceToken>> uitServiceTokens = new HashMap<Long,Set<ServiceToken>>();
}

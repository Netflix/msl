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
package com.netflix.msl.msg;

import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>A message service token builder provides methods for intelligently
 * manipulating the primary and peer service tokens that will be included in a
 * message.</p>
 * 
 * <p>There are two categories of service tokens: primary and peer.
 * <ul>
 * <li>Primary service tokens are associated with the primary master token and
 * peer user ID token, and are the only category of service token to appear in
 * trusted network mode. Primary service tokens are also used in peer-to-peer
 * mode.</li>
 * <li>Peer service tokens are associated with the peer master token and peer
 * user ID token and only used in peer-to-peer mode.</li>
 * </ul></p>
 * 
 * <p>There are three levels of service token binding.
 * <ul>
 * <li>Unbound service tokens may be freely moved between entities and
 * users.</li>
 * <li>Master token bound service tokens must be accompanied by a master token
 * that they are bound to and will be rejected if sent with a different master
 * token or without a master token. This binds a service token to a specific
 * entity.</li>
 * <li>User ID token bound service tokens must be accompanied by a user ID
 * token that they are bound to and will be rejected if sent with a different
 * user or used without a user ID token. This binds a service token to a
 * specific user and by extension a specific entity.</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageServiceTokenBuilder {
    /**
     * <p>Select the appropriate crypto context for the named service token.</p>
     * 
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be returned. Otherwise the
     * default crypto context mapped from the empty string key will be returned.
     * If no explicit or default crypto context exists null will be
     * returned.</p>
     * 
     * @param name service token name.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return the correct crypto context for the service token or null.
     */
    private static ICryptoContext selectCryptoContext(final String name, final Map<String,ICryptoContext> cryptoContexts) {
        if (cryptoContexts.containsKey(name))
            return cryptoContexts.get(name);
        return cryptoContexts.get("");
    }
    
    /**
     * Create a new message service token builder with the provided MSL and
     * message contexts and message builder.
     * 
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param builder message builder for message being built.
     */
    public MessageServiceTokenBuilder(final MslContext ctx, final MessageContext msgCtx, final MessageBuilder builder) {
        this.ctx = ctx;
        this.cryptoContexts = msgCtx.getCryptoContexts();
        this.builder = builder;
    }
    
    /**
     * Returns the master token that primary service tokens should be bound
     * against.
     * 
     * @return the primary service token master token or {@code null} if there
     *         is none.
     */
    private MasterToken getPrimaryMasterToken() {
        // If key exchange data is provided and we are not in peer-to-peer mode
        // then its master token will be used for creating service tokens.
        final KeyExchangeData keyExchangeData = builder.getKeyExchangeData();
        if (keyExchangeData != null && !ctx.isPeerToPeer()) {
            return keyExchangeData.keyResponseData.getMasterToken();
        } else {
            return builder.getMasterToken();
        }
    }
    
    /**
     * Returns true if the message has a primary master token available for
     * adding master-bound primary service tokens.
     * 
     * @return true if the message has a primary master token.
     */
    public boolean isPrimaryMasterTokenAvailable() {
        return getPrimaryMasterToken() != null;
    }
    
    /**
     * @return true if the message has a primary user ID token.
     */
    public boolean isPrimaryUserIdTokenAvailable() {
        return builder.getUserIdToken() != null;
    }
    
    /**
     * @return true if the message has a peer master token.
     */
    public boolean isPeerMasterTokenAvailable() {
        return builder.getPeerMasterToken() != null;
    }
    
    /**
     * @return true if the message has a peer user ID token.
     */
    public boolean isPeerUserIdTokenAvailable() {
        return builder.getPeerUserIdToken() != null;
    }

    /**
     * @return the unmodifiable set of primary service tokens that will be
     *         included in the built message.
     */
    public Set<ServiceToken> getPrimaryServiceTokens() {
        return builder.getServiceTokens();
    }
    
    /**
     * @return the unmodifiable set of peer service tokens that will be
     *         included in the built message.
     */
    public Set<ServiceToken> getPeerServiceTokens() {
        return builder.getPeerServiceTokens();
    }
    
    /**
     * Adds a primary service token to the message, replacing any existing
     * primary service token with the same name.
     * 
     * @param serviceToken primary service token.
     * @return true if the service token was added, false if the service token
     *         is bound to a master token or user ID token and the message does
     *         not have the same token.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the primary master token or primary user ID token of the
     *         message being built.
     */
    public boolean addPrimaryServiceToken(final ServiceToken serviceToken) throws MslMessageException {
        try {
            builder.addServiceToken(serviceToken);
            return true;
        } catch (final MslMessageException e) {
            return false;
        }
    }
    
    /**
     * Adds a peer service token to the message, replacing any existing peer
     * service token with the same name.
     * 
     * @param serviceToken peer service token.
     * @return true if the service token was added, false if the service token
     *         is bound to a master token or user ID token and the message does
     *         not have the same token.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the peer master token or peer user ID token of the message
     *         being built.
     */
    public boolean addPeerServiceToken(final ServiceToken serviceToken) throws MslMessageException {
        try {
            builder.addPeerServiceToken(serviceToken);
            return true;
        } catch (final MslMessageException e) {
            return false;
        }
    }
    
    /**
     * Adds a new unbound primary service token to the message, replacing any
     * existing primary service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    public boolean addUnboundPrimaryServiceToken(final String name, final byte[] data, final boolean encrypt, final CompressionAlgorithm compressionAlgo) throws MslEncodingException, MslCryptoException, MslException {
        // Fail if there is no crypto context.
        final ICryptoContext cryptoContext = selectCryptoContext(name, cryptoContexts);
        if (cryptoContext == null)
            return false;
        
        // Add the service token.
        final ServiceToken serviceToken = new ServiceToken(ctx, name, data, null, null, encrypt, compressionAlgo, cryptoContext);
        try {
            builder.addServiceToken(serviceToken);
        } catch (final MslMessageException e) {
            throw new MslInternalException("Service token bound to incorrect authentication tokens despite being unbound.", e);
        }
        return true;
    }
    
    /**
     * Adds a new unbound peer service token to the message, replacing any
     * existing peer service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    public boolean addUnboundPeerServiceToken(final String name, final byte[] data, final boolean encrypt, final CompressionAlgorithm compressionAlgo) throws MslEncodingException, MslCryptoException, MslException {
        // Fail if there is no crypto context.
        final ICryptoContext cryptoContext = selectCryptoContext(name, cryptoContexts);
        if (cryptoContext == null)
            return false;
        
        // Add the service token.
        final ServiceToken serviceToken = new ServiceToken(ctx, name, data, null, null, encrypt, compressionAlgo, cryptoContext);
        try {
            builder.addPeerServiceToken(serviceToken);
        } catch (final MslMessageException e) {
            throw new MslInternalException("Service token bound to incorrect authentication tokens despite being unbound.", e);
        }
        return true;
    }
    
    /**
     * Adds a new master token bound primary service token to the message,
     * replacing any existing primary service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a primary master token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    public boolean addMasterBoundPrimaryServiceToken(final String name, final byte[] data, final boolean encrypt, final CompressionAlgorithm compressionAlgo) throws MslEncodingException, MslCryptoException, MslException {
        // Fail if there is no master token.
        final MasterToken masterToken = getPrimaryMasterToken();
        if (masterToken == null)
            return false;
        
        // Fail if there is no crypto context.
        final ICryptoContext cryptoContext = selectCryptoContext(name, cryptoContexts);
        if (cryptoContext == null)
            return false;
        
        // Add the service token.
        final ServiceToken serviceToken = new ServiceToken(ctx, name, data, masterToken, null, encrypt, compressionAlgo, cryptoContext);
        try {
            builder.addServiceToken(serviceToken);
        } catch (final MslMessageException e) {
            throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token.", e);
        }
        return true;
    }
    
    /**
     * Adds a new master token bound peer service token to the message,
     * replacing any existing peer service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a peer master token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    public boolean addMasterBoundPeerServiceToken(final String name, final byte[] data, final boolean encrypt, final CompressionAlgorithm compressionAlgo) throws MslEncodingException, MslCryptoException, MslException {
        // Fail if there is no master token.
        final MasterToken masterToken = builder.getPeerMasterToken();
        if (masterToken == null)
            return false;
        
        // Fail if there is no crypto context.
        final ICryptoContext cryptoContext = selectCryptoContext(name, cryptoContexts);
        if (cryptoContext == null)
            return false;
        
        // Add the service token.
        final ServiceToken serviceToken = new ServiceToken(ctx, name, data, masterToken, null, encrypt, compressionAlgo, cryptoContext);
        try {
            builder.addPeerServiceToken(serviceToken);
        } catch (final MslMessageException e) {
            throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token.", e);
        }
        return true;
    }

    /**
     * Adds a new user ID token bound primary service token to the message,
     * replacing any existing primary service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a primary user ID token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    public boolean addUserBoundPrimaryServiceToken(final String name, final byte[] data, final boolean encrypt, final CompressionAlgorithm compressionAlgo) throws MslEncodingException, MslCryptoException, MslException {
        // Fail if there is no master token.
        final MasterToken masterToken = getPrimaryMasterToken();
        if (masterToken == null)
            return false;
        
        // Fail if there is no user ID token.
        final UserIdToken userIdToken = builder.getUserIdToken();
        if (userIdToken == null)
            return false;
        
        // Fail if there is no crypto context.
        final ICryptoContext cryptoContext = selectCryptoContext(name, cryptoContexts);
        if (cryptoContext == null)
            return false;
        
        // Add the service token.
        final ServiceToken serviceToken = new ServiceToken(ctx, name, data, masterToken, userIdToken, encrypt, compressionAlgo, cryptoContext);
        try {
            builder.addServiceToken(serviceToken);
        } catch (final MslMessageException e) {
            throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token and user ID token.", e);
        }
        return true;
    }

    /**
     * Adds a new user ID token bound peer service token to the message,
     * replacing any peer existing service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a peer user ID token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    public boolean addUserBoundPeerServiceToken(final String name, final byte[] data, final boolean encrypt, final CompressionAlgorithm compressionAlgo) throws MslEncodingException, MslCryptoException, MslException {
        // Fail if there is no master token.
        final MasterToken masterToken = builder.getPeerMasterToken();
        if (masterToken == null)
            return false;
        
        // Fail if there is no user ID token.
        final UserIdToken userIdToken = builder.getPeerUserIdToken();
        if (userIdToken == null)
            return false;
        
        // Fail if there is no crypto context.
        final ICryptoContext cryptoContext = selectCryptoContext(name, cryptoContexts);
        if (cryptoContext == null)
            return false;
        
        // Add the service token.
        final ServiceToken serviceToken = new ServiceToken(ctx, name, data, masterToken, userIdToken, encrypt, compressionAlgo, cryptoContext);
        try {
            builder.addPeerServiceToken(serviceToken);
        } catch (final MslMessageException e) {
            throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token and user ID token.", e);
        }
        return true;
    }
    
    /**
     * <p>Exclude a primary service token from the message. This matches the
     * token name and whether or not it is bound to a master token or to a user
     * ID token. It does not require the token to be bound to the exact same
     * master token or user ID token that will be used in the message.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * <p>This function is equivalent to calling
     * {@link #excludePrimaryServiceToken(String, boolean, boolean)}.</p>
     * 
     * @param serviceToken the service token.
     * @return true if the service token was found and therefore removed.
     */
    public boolean excludePrimaryServiceToken(final ServiceToken serviceToken) {
        return excludePrimaryServiceToken(serviceToken.getName(), serviceToken.isMasterTokenBound(), serviceToken.isUserIdTokenBound());
    }
    
    /**
     * <p>Exclude a primary service token from the message matching all
     * specified parameters. A false value for the master token bound or user
     * ID token bound parameters restricts exclusion to tokens that are not
     * bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the service token was found and therefore removed.
     */
    public boolean excludePrimaryServiceToken(final String name, final boolean masterTokenBound, final boolean userIdTokenBound) {
        // Exclude the service token if found.
        for (final ServiceToken serviceToken : builder.getServiceTokens()) {
            if (serviceToken.getName().equals(name) &&
                serviceToken.isMasterTokenBound() == masterTokenBound &&
                serviceToken.isUserIdTokenBound() == userIdTokenBound)
            {
                builder.excludeServiceToken(name, masterTokenBound, userIdTokenBound);
                return true;
            }
        }
        
        // Not found.
        return false;
    }
    
    /**
     * <p>Exclude a peer service token from the message. This matches the
     * token name and whether or not it is bound to a master token or to a user
     * ID token. It does not require the token to be bound to the exact same
     * master token or user ID token that will be used in the message.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * <p>This function is equivalent to calling
     * {@link #excludePeerServiceToken(String, boolean, boolean)}.</p>
     * 
     * @param serviceToken the service token.
     * @return true if the service token was found and therefore removed.
     */
    public boolean excludePeerServiceToken(final ServiceToken serviceToken) {
        return excludePeerServiceToken(serviceToken.getName(), serviceToken.isMasterTokenBound(), serviceToken.isUserIdTokenBound());
    }
    
    /**
     * <p>Exclude a peer service token from the message matching all specified
     * parameters. A false value for the master token bound or user ID token
     * bound parameters restricts exclusion to tokens that are not bound to a
     * master token or not bound to a user ID token respectively.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the peer service token was found and therefore removed.
     */
    public boolean excludePeerServiceToken(final String name, final boolean masterTokenBound, final boolean userIdTokenBound) {
        // Exclude the service token if found.
        for (final ServiceToken serviceToken : builder.getPeerServiceTokens()) {
            if (serviceToken.getName().equals(name) &&
                serviceToken.isMasterTokenBound() == masterTokenBound &&
                serviceToken.isUserIdTokenBound() == userIdTokenBound)
            {
                builder.excludePeerServiceToken(name, masterTokenBound, userIdTokenBound);
                return true;
            }
        }
        
        // Not found.
        return false;
    }
    
    /**
     * <p>Mark a primary service token for deletion, if it exists. This matches
     * the token name and whether or not it is bound to a master token or to a
     * user ID token. It does not require the token to be bound to the exact
     * same master token or user ID token that will be used in the message.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * <p>This function is equivalent to calling
     * {@link #deletePrimaryServiceToken(String, boolean, boolean)}.</p>
     * 
     * @param serviceToken the service token.
     * @return true if the service token exists and was marked for deletion.
     */
    public boolean deletePrimaryServiceToken(final ServiceToken serviceToken) {
        return deletePrimaryServiceToken(serviceToken.getName(), serviceToken.isMasterTokenBound(), serviceToken.isUserIdTokenBound());
    }
    
    /**
     * <p>Mark a primary service token for deletion, if it exists, matching all
     * specified parameters. A false value for the master token bound or user
     * ID token bound parameters restricts deletion to tokens that are not
     * bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the service token exists and was marked for deletion.
     */
    public boolean deletePrimaryServiceToken(final String name, final boolean masterTokenBound, final boolean userIdTokenBound) {
        // Mark the service token for deletion if found.
        for (final ServiceToken serviceToken : builder.getServiceTokens()) {
            if (serviceToken.getName().equals(name) &&
                serviceToken.isMasterTokenBound() == masterTokenBound &&
                serviceToken.isUserIdTokenBound() == userIdTokenBound)
            {
                builder.deleteServiceToken(name, masterTokenBound, userIdTokenBound);
                return true;
            }
        }
        
        // Not found.
        return false;
    }
    
    /**
     * <p>Mark a peer service token for deletion, if it exists. This matches
     * the token name and whether or not it is bound to a master token or to a
     * user ID token. It does not require the token to be bound to the exact
     * same master token or user ID token that will be used in the message.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * <p>This function is equivalent to calling
     * {@link #deletePeerServiceToken(String, boolean, boolean)}.</p>
     * 
     * @param serviceToken the service token.
     * @return true if the service token exists and was marked for deletion.
     */
    public boolean deletePeerServiceToken(final ServiceToken serviceToken) {
        return deletePeerServiceToken(serviceToken.getName(), serviceToken.isMasterTokenBound(), serviceToken.isUserIdTokenBound());
    }
    
    /**
     * <p>Mark a peer service token for deletion, if it exists, matching all
     * specified parameters. A false value for the master token bound or user
     * ID token bound parameters restricts deletion to tokens that are not
     * bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the peer service token exists and was marked for
     *         deletion.
     */
    public boolean deletePeerServiceToken(final String name, final boolean masterTokenBound, final boolean userIdTokenBound) {
        // Mark the service token for deletion if found.
        for (final ServiceToken serviceToken : builder.getPeerServiceTokens()) {
            if (serviceToken.getName().equals(name) &&
                serviceToken.isMasterTokenBound() == masterTokenBound &&
                serviceToken.isUserIdTokenBound() == userIdTokenBound)
            {
                builder.deletePeerServiceToken(name, masterTokenBound, userIdTokenBound);
                return true;
            }
        }
        
        // Not found.
        return false;
    }
    
    /** MSL context. */
    private final MslContext ctx;
    /** Service token crypto contexts. */
    private final Map<String,ICryptoContext> cryptoContexts;
    /** Message builder for message being built. */
    private final MessageBuilder builder;
}

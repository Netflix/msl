/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.keyx;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;

/**
 * A key exchange factory creates key request and response data instances for
 * a specific key exchange scheme.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class KeyExchangeFactory {
    /**
     * The key exchange data struct contains key response data and a crypto
     * context for the exchanged keys.
     */
    public static class KeyExchangeData {
        /**
         * Create a new key key exhange data struct with the provided key
         * response data, master token, and crypto context.
         * 
         * @param keyResponseData the key response data.
         * @param cryptoContext the crypto context.
         */
        public KeyExchangeData(final KeyResponseData keyResponseData, final ICryptoContext cryptoContext) {
            this.keyResponseData = keyResponseData;
            this.cryptoContext = cryptoContext;
        }
        
        /** Key response data. */
        public final KeyResponseData keyResponseData;
        /** Crypto context for the exchanged keys. */
        public final ICryptoContext cryptoContext;
    }
    
    /**
     * Create a new key exchange factory for the specified scheme.
     * 
     * @param scheme the key exchange scheme.
     */
    protected KeyExchangeFactory(final KeyExchangeScheme scheme) {
        this.scheme = scheme;
    }
    
    /**
     * @return the key exchange scheme this factory is for.
     */
    public KeyExchangeScheme getScheme() {
        return scheme;
    }
    
    /**
     * Construct a new key request data instance from the provided MSL object.
     * 
     * @param ctx MSL context.
     * @param keyRequestMo the MSL object.
     * @return the key request data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if there is an error creating the key
     *         request data.
     * @throws MslCryptoException if the keying material cannot be created.
     */
    protected abstract KeyRequestData createRequestData(final MslContext ctx, final MslObject keyRequestMo) throws MslEncodingException, MslKeyExchangeException, MslCryptoException;
    
    /**
     * Construct a new key response data instance from the provided MSL object.
     * 
     * @param ctx MSL context.
     * @param masterToken the master token for the new key response data.
     * @param keyDataMo the MSL object.
     * @return the key response data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if there is an error creating the key
     *         response data.
     */
    protected abstract KeyResponseData createResponseData(final MslContext ctx, final MasterToken masterToken, final MslObject keyDataMo) throws MslEncodingException, MslKeyExchangeException;
    
    /**
     * <p>Generate a new key response data instance and crypto context in
     * response to the provided key request data. The key request data will be
     * from the the remote entity.</p>
     * 
     * <p>The provided master token should be renewed by incrementing its
     * sequence number but maintaining its serial number by using the MSL
     * context's token factory.</p>
     * 
     * @param ctx MSL context.
     * @param format MSL encoder format.
     * @param keyRequestData the key request data.
     * @param masterToken the master token to renew.
     * @return the key response data and crypto context or {@code null} if the
     *         factory chooses not to perform key exchange. 
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing or encoding
     *         the data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity.
     * @throws MslException if there is an error renewing the master token.
     */
    public abstract KeyExchangeData generateResponse(final MslContext ctx, final MslEncoderFormat format, final KeyRequestData keyRequestData, final MasterToken masterToken) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException;
    
    /**
     * <p>Generate a new key response data instance and crypto context in
     * response to the provided key request data and entity authentication
     * data. The key request data will be from the the remote entity.</p>
     * 
     * @param ctx MSL context.
     * @param format MSL encoder format.
     * @param keyRequestData the key request data.
     * @param entityAuthData the entity authentication data.
     * @return the key response data and crypto context or {@code null} if the
     *         factory chooses not to perform key exchange.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing or encoding
     *         the data.
     * @throws MslEntityAuthException if there is a problem with the entity
     *         identity.
     * @throws MslException if there is an error creating the master token.
     */
    public abstract KeyExchangeData generateResponse(final MslContext ctx, final MslEncoderFormat format, final KeyRequestData keyRequestData, final EntityAuthenticationData entityAuthData) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException;
    
    /**
     * Create a crypto context from the provided key request data and key
     * response data. The key request data will be from the local entity and
     * the key response data from the remote entity.
     * 
     * @param ctx MSL context.
     * @param keyRequestData the key request data.
     * @param keyResponseData the key response data.
     * @param masterToken the current master token (not the one inside the key
     *        response data). May be null.
     * @return the crypto context.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity.
     */
    public abstract ICryptoContext getCryptoContext(final MslContext ctx, final KeyRequestData keyRequestData, final KeyResponseData keyResponseData, final MasterToken masterToken) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException;
    
    /** The factory's key exchange scheme. */
    private final KeyExchangeScheme scheme;
}
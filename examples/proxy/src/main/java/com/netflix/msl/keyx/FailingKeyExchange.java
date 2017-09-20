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
package com.netflix.msl.keyx;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>Failing user authentication factory.</p>
 * 
 * <p>When used, this factory either refuses to perform key exchange or throws
 * a {@link MslKeyExchangeException} containing the MSL error specified when
 * attempting to generate a key response.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class FailingKeyExchange extends KeyExchangeFactory {
    /**
     * <p>A simple key request object that holds the raw key request data.</p>
     */
    private static class KeyRequest extends KeyRequestData {
        /**
         * <p>Create a new key request data that contains the provided
         * key request data.</p>
         * 
         * @param keydata the unprocessed key request data.
         */
        public KeyRequest(final MslObject keydata) {
            super(ProxyKeyExchangeScheme.PROXY);
            this.keydata = keydata;
        }

        @Override
        protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) {
            return keydata;
        }
        
        /** The original key data. */
        private final MslObject keydata;
    }

    /**
     * Create a new failing key exchange factory for the specified scheme.
     * 
     * @param scheme the key exchange scheme.
     * @param error the error to throw or {@code null} if key exchange should
     *        simply no be performed.
     */
    public FailingKeyExchange(final KeyExchangeScheme scheme, final MslError error) {
        super(scheme);
        this.error = error;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createRequestData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    protected KeyRequestData createRequestData(final MslContext ctx, final MslObject keyRequestMo) {
        // This method will be called if key request data exists. We do not
        // want to trigger external processing if we are not going to do
        // key exchange, so simply return a dummy key request data object.
        return new KeyRequest(keyRequestMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createResponseData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    @Override
    protected KeyResponseData createResponseData(final MslContext ctx, final MasterToken masterToken, final MslObject keyDataMo) {
        // This method should never be called; we should never receive key
        // response data.
        throw new MslInternalException("Unexpected call to create key response data.");
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslEncoderFormat, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final MslEncoderFormat format, final KeyRequestData keyRequestData, final MasterToken masterToken) throws MslKeyExchangeException {
        // This method is called if key exchange needs to be performed.
        // Throw an exception if an error was specified.
        if (error != null)
            throw new MslKeyExchangeException(error);
        
        // Otherwise refuse to perform the key exchange.
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslEncoderFormat, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final MslEncoderFormat format, final KeyRequestData keyRequestData, final EntityAuthenticationData entityAuthData) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
        // This method is called if key exchange needs to be performed.
        // Throw an exception if an error was specified.
        if (error != null)
            throw new MslKeyExchangeException(error);
        
        // Otherwise refuse to perform the key exchange.
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.keyx.KeyResponseData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final KeyRequestData keyRequestData, final KeyResponseData keyResponseData, final MasterToken masterToken) throws MslKeyExchangeException {
        // This method should never be called; we should never be the
        // entity requesting a key exchange.
        throw new MslInternalException("Unexpected call to generate a crypto context from key response data.");
    }

    /** MSL error. May be {@code null}. */
    private final MslError error;
}

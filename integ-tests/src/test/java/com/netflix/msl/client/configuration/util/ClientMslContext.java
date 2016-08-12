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
package com.netflix.msl.client.configuration.util;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.MockEccAuthenticationFactory;
import com.netflix.msl.entityauth.MockX509AuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.EccAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.entityauth.X509AuthenticationData;
import com.netflix.msl.util.MockMslContext;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class ClientMslContext extends MockMslContext {
    /** MSL encryption key. */
    private static final byte[] CLIENT_MSL_ENCRYPTION_KEY = {
            (byte)0x2d, (byte)0x58, (byte)0xf3, (byte)0xb8, (byte)0xf7, (byte)0x47, (byte)0xd1, (byte)0x6a,
            (byte)0xb1, (byte)0x93, (byte)0xc4, (byte)0xc0, (byte)0xa6, (byte)0x24, (byte)0xea, (byte)0xcf,
    };
    /** MSL HMAC key. */
    private static final byte[] CLIENT_MSL_HMAC_KEY = {
            (byte)0xe7, (byte)0xae, (byte)0xbf, (byte)0xd5, (byte)0x87, (byte)0x9b, (byte)0xb0, (byte)0xe0,
            (byte)0xad, (byte)0x01, (byte)0x6a, (byte)0x4c, (byte)0xf3, (byte)0xcb, (byte)0x39, (byte)0x82,
            (byte)0xf5, (byte)0xba, (byte)0x26, (byte)0x0d, (byte)0xa5, (byte)0x20, (byte)0x24, (byte)0x5b,
            (byte)0xb4, (byte)0x22, (byte)0x75, (byte)0xbd, (byte)0x79, (byte)0x47, (byte)0x37, (byte)0x0c,
    };
    /** MSL wrapping key. */
    private static final byte[] CLIENT_MSL_WRAPPING_KEY = {
            (byte)0x93, (byte)0xb6, (byte)0x9a, (byte)0x15, (byte)0x80, (byte)0xd3, (byte)0x23, (byte)0xa2,
            (byte)0xe7, (byte)0x9d, (byte)0xd9, (byte)0xb2, (byte)0x26, (byte)0x26, (byte)0xb3, (byte)0xf6,
    };
    private final EntityAuthenticationScheme schemeUsed;
    private int currentRetryCount;
    private int maxRetryCount;

    /**
     * Create a new test MSL context.
     *
     *
     * @param scheme                entity authentication scheme.
     * @param peerToPeer            true if the context should operate in peer-to-peer mode.
     * @param nullCryptoContext     true if the crypto context is supposed to be set to NullCryptoContext
     * @throws MslCryptoException
     *          if there is an error signing or creating the
     *          entity authentication data.
     * @throws MslEncodingException
     *          if there is an error creating the entity
     *          authentication data.
     */
    public ClientMslContext(EntityAuthenticationScheme scheme, boolean peerToPeer, boolean nullCryptoContext) throws MslEncodingException, MslCryptoException {
        super(scheme, peerToPeer);
        final SecretKey mslEncryptionKey = new SecretKeySpec(CLIENT_MSL_ENCRYPTION_KEY, JcaAlgorithm.AES);
        final SecretKey mslHmacKey = new SecretKeySpec(CLIENT_MSL_HMAC_KEY, JcaAlgorithm.HMAC_SHA256);
        final SecretKey mslWrappingKey = new SecretKeySpec(CLIENT_MSL_WRAPPING_KEY, JcaAlgorithm.AESKW);
        if(nullCryptoContext) {
            mslCryptoContext = new NullCryptoContext();
        } else {
            mslCryptoContext = new SymmetricCryptoContext(this, "TestMslKeys", mslEncryptionKey, mslHmacKey, mslWrappingKey);
        }
        setClientCryptoContext();

        pskAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        x509AuthData = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        rsaAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        eccAuthData = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        noneAuthData = new UnauthenticatedAuthenticationData("MOCKUNAUTH-ESN-TEST");

        // Server is with NONE entity authentication, to be different from server.
        if(EntityAuthenticationScheme.NONE.equals(scheme)) {
            super.setEntityAuthenticationData(noneAuthData);
        }

        schemeUsed = scheme;
        maxRetryCount = 0;
        currentRetryCount = 0;
    }

    public void setClientCryptoContext() {
        super.setMslCryptoContext(mslCryptoContext);
    }

    @Override
    public EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {

        if(reauthCode == ReauthCode.ENTITYDATA_REAUTH) {
            if(currentRetryCount++ == maxRetryCount) {
                final EntityAuthenticationData entityAuthData;
                if (EntityAuthenticationScheme.PSK.equals(schemeUsed))
                    entityAuthData = pskAuthData;
                else if (EntityAuthenticationScheme.X509.equals(schemeUsed))
                    entityAuthData = x509AuthData;
                else if (EntityAuthenticationScheme.RSA.equals(schemeUsed))
                    entityAuthData = rsaAuthData;
                else if (EntityAuthenticationScheme.ECC.equals(schemeUsed))
                    entityAuthData = eccAuthData;
                else if (EntityAuthenticationScheme.NONE.equals(schemeUsed))
                    entityAuthData = noneAuthData;
                else
                    throw new IllegalArgumentException("Unsupported authentication type: " + schemeUsed.name());

                super.setEntityAuthenticationData(entityAuthData);
            }
        }
        return super.getEntityAuthenticationData(reauthCode);
    }

    /** MSL crypto context. */
    private ICryptoContext mslCryptoContext;
    /** Entity Authentication Data */
    private EntityAuthenticationData pskAuthData, x509AuthData, rsaAuthData, noneAuthData, eccAuthData;

    public void setMaxRetryCount(int retryCount) {
        maxRetryCount = retryCount;
    }

    public void resetCurrentRetryCount() {
        currentRetryCount = 0;
    }
}

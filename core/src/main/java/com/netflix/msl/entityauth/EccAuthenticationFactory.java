/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.entityauth;

import java.security.PrivateKey;
import java.security.PublicKey;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.EccCryptoContext;
import com.netflix.msl.crypto.EccCryptoContext.Mode;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>ECC asymmetric keys entity authentication factory.</p>
 */
public class EccAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * <p>Construct a new ECC asymmetric keys authentication factory
     * instance.</p>
     *
     * @param store ECC key store.
     * @param authutils authentication utilities.
     */
    public EccAuthenticationFactory(final EccStore store, final AuthenticationUtils authutils) {
        this(null, store, authutils);
    }

    /**
     * <p>Construct a new ECC asymmetric keys authentication factory instance
     * with the specified key pair ID for the local entity. The ECC key store
     * must contain a private key for the local entity (a public key is
     * optional).</p>
     *
     * @param keyPairId local entity key pair ID.
     * @param store ECC key store.
     * @param authutils authentication utilities.
     */
    public EccAuthenticationFactory(final String keyPairId, final EccStore store, final AuthenticationUtils authutils) {
        super(EntityAuthenticationScheme.ECC);
        this.keyPairId = keyPairId;
        this.store = store;
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslCryptoException {
        return new EccAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof EccAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final EccAuthenticationData ead = (EccAuthenticationData)authdata;

        // Check for revocation.
        final String identity = ead.getIdentity();
        if (authutils.isEntityRevoked(identity))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "ecc" + identity).setEntityAuthenticationData(ead);

        // Verify the scheme is permitted.
        if (!authutils.isSchemePermitted(identity, getScheme()))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + getScheme()).setEntityAuthenticationData(ead);

        // Extract ECC authentication data.
        final String pubkeyid = ead.getPublicKeyId();
        final PublicKey publicKey = store.getPublicKey(pubkeyid);
        final PrivateKey privateKey = store.getPrivateKey(pubkeyid);

        // The local entity must have a private key.
        if (pubkeyid.equals(keyPairId) && privateKey == null)
            throw new MslEntityAuthException(MslError.ECC_PRIVATEKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(ead);

        // Remote entities must have a public key.
        else if (!pubkeyid.equals(keyPairId) && publicKey == null)
            throw new MslEntityAuthException(MslError.ECC_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(ead);

        // Return the crypto context.
        return new EccCryptoContext(identity, privateKey, publicKey, Mode.SIGN_VERIFY);
    }

    /** Local entity key pair ID. */
    private final String keyPairId;
    /** ECC key store. */
    private final EccStore store;
    /** Authentication utilities. */
    private final AuthenticationUtils authutils;
}

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
package com.netflix.msl.entityauth;

import java.security.PrivateKey;
import java.security.PublicKey;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext.Mode;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>RSA asymmetric keys entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class RsaAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * <p>Construct a new RSA asymmetric keys authentication factory
     * instance.</p>
     * 
     * @param store RSA key store.
     * @param authutils authentication utilities.
     */
    public RsaAuthenticationFactory(final RsaStore store, final AuthenticationUtils authutils) {
        this(null, store, authutils);
    }
    
    /**
     * <p>Construct a new RSA asymmetric keys authentication factory instance
     * with the specified key pair ID for the local entity. The RSA key store
     * must contain a private key for the local entity (a public key is
     * optional).</p>
     * 
     * @param keyPairId local entity key pair ID.
     * @param store RSA key store.
     * @param authutils authentication utilities.
     */
    public RsaAuthenticationFactory(final String keyPairId, final RsaStore store, final AuthenticationUtils authutils) {
        super(EntityAuthenticationScheme.RSA);
        this.keyPairId = keyPairId;
        this.store = store;
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslCryptoException {
        return new RsaAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof RsaAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final RsaAuthenticationData rad = (RsaAuthenticationData)authdata;
        
        // Check for revocation.
        final String identity = rad.getIdentity();
        if (authutils.isEntityRevoked(identity))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "rsa " + identity).setEntityAuthenticationData(rad);
        
        // Verify the scheme is permitted.
        if (!authutils.isSchemePermitted(identity, getScheme()))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + getScheme()).setEntityAuthenticationData(rad);
        
        // Extract RSA authentication data.
        final String pubkeyid = rad.getPublicKeyId();
        final PublicKey publicKey = store.getPublicKey(pubkeyid);
        final PrivateKey privateKey = store.getPrivateKey(pubkeyid);
        
        // The local entity must have a private key.
        if (pubkeyid.equals(keyPairId) && privateKey == null)
            throw new MslEntityAuthException(MslError.RSA_PRIVATEKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);
        
        // Remote entities must have a public key.
        else if (!pubkeyid.equals(keyPairId) && publicKey == null)
            throw new MslEntityAuthException(MslError.RSA_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);
        
        // Return the crypto context.
        return new RsaCryptoContext(ctx, identity, privateKey, publicKey, Mode.SIGN_VERIFY);
    }
    
    /** Local entity key pair ID. */
    private final String keyPairId;
    /** RSA key store. */
    private final RsaStore store;
    /** Authentication utilities. */
    final AuthenticationUtils authutils;
}

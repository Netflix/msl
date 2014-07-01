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
package com.netflix.msl.entityauth;

import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.json.JSONObject;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext.Mode;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>X.509 asymmetric keys entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class X509AuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * Construct a new X.509 asymmetric keys authentication factory instance.
     * 
     * @param store X.509 certificate authority store.
     * @param authutils entity authentication utilities.
     */
    public X509AuthenticationFactory(final X509Store store, final AuthenticationUtils authutils) {
        super(EntityAuthenticationScheme.X509);
        this.caStore = store;
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, org.json.JSONObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final JSONObject entityAuthJO) throws MslCryptoException, MslEncodingException {
        return new X509AuthenticationData(entityAuthJO);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslCryptoException, MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof X509AuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final X509AuthenticationData x509ad = (X509AuthenticationData)authdata;
        
        // Extract X.509 authentication data.
        final X509Certificate cert = x509ad.getX509Cert();
        final String identity = cert.getSubjectX500Principal().getName();
        final PublicKey publicKey = cert.getPublicKey();
        
        // Check for revocation.
        if (authutils.isEntityRevoked(identity))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, cert.toString()).setEntity(x509ad);
        
        // Verify the scheme is permitted.
        if (!authutils.isSchemePermitted(identity, getScheme()))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + getScheme()).setEntity(x509ad);
        
        // Verify entity certificate.
        try {
            if (!caStore.isAccepted(cert))
                throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, cert.toString()).setEntity(x509ad);
        } catch (final CertificateExpiredException e) {
            throw new MslEntityAuthException(MslError.X509CERT_EXPIRED, cert.toString(), e).setEntity(x509ad);
        } catch (final CertificateNotYetValidException e) {
            throw new MslEntityAuthException(MslError.X509CERT_NOT_YET_VALID, cert.toString(), e).setEntity(x509ad);
        }
        
        // Return the crypto context.
        return new RsaCryptoContext(ctx, identity, null, publicKey, Mode.SIGN_VERIFY);
    }

    /** X.509 CA store. */
    private final X509Store caStore;
    /** Entity authentication utilities. */
    private final AuthenticationUtils authutils;
}

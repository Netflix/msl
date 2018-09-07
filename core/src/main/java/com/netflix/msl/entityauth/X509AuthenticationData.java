/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;

/**
 * <p>X.509 asymmetric keys entity authentication data.</p>
 * 
 * <p>The X.509 certificate should be used to enumerate any entity
 * properties. The certificate subject canonical name is considered the device
 * identity. X.509 authentication data is considered equal based on the device
 * identity.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "x509certificate" ],
 *   "x509certificate" : "string"
 * }} where:
 * <ul>
 * <li>{@code x509certificate} is the Base64-encoded X.509 certificate</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class X509AuthenticationData extends EntityAuthenticationData {
    /** Key entity X.509 certificate. */
    private static final String KEY_X509_CERT = "x509certificate";
    
    /**
     * Construct a new X.509 asymmetric keys authentication data instance from
     * the provided X.509 certificate.
     * 
     * @param x509cert entity X.509 certificate.
     * @throws MslCryptoException if the X.509 certificate data cannot be
     *         parsed.
     */
    public X509AuthenticationData(final X509Certificate x509cert) throws MslCryptoException {
        super(EntityAuthenticationScheme.X509);
        this.x509cert = x509cert;
        this.identity = x509cert.getSubjectX500Principal().getName();
    }
    
    /**
     * Construct a new X.509 asymmetric keys authentication data instance from
     * the provided MSL object.
     * 
     * @param x509AuthMo the authentication data MSL object.
     * @throws MslCryptoException if the X.509 certificate data cannot be
     *         parsed.
     * @throws MslEncodingException if the X.509 certificate cannot be found.
     */
    public X509AuthenticationData(final MslObject x509AuthMo) throws MslCryptoException, MslEncodingException {
        super(EntityAuthenticationScheme.X509);
        
        // Extract X.509 certificate representation.
        final String x509;
        try {
            x509 = x509AuthMo.getString(KEY_X509_CERT);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "X.509 authdata " + x509AuthMo, e);
        }
        
        // Get the X.509 certificate factory.
        final CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (final CertificateException e) {
            throw new MslInternalException("No certificate X.509 certificate factory.", e);
        }
        
        // Create X.509 cert.
        final byte[] x509bytes;
        try {
            x509bytes = Base64.decode(x509);
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.X509CERT_INVALID, x509, e);
        }
        try {
            final ByteArrayInputStream bais = new ByteArrayInputStream(x509bytes);
            x509cert = (X509Certificate)factory.generateCertificate(bais);
            identity = x509cert.getSubjectX500Principal().getName();
        } catch (final CertificateException e) {
            throw new MslCryptoException(MslError.X509CERT_PARSE_ERROR, Base64.encode(x509bytes), e);
        }
    }
    
    /**
     * @return the X.509 certificate.
     */
    public X509Certificate getX509Cert() {
        return x509cert;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getIdentity()
     */
    @Override
    public String getIdentity() {
        return identity;
    }
    
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        final MslObject mo = encoder.createObject();
        try {
            mo.put(KEY_X509_CERT, Base64.encode(x509cert.getEncoded()));
        } catch (final CertificateEncodingException | IllegalArgumentException e) {
            throw new MslEncoderException("Error encoding X.509 authdata", e);
        }
        return mo;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof X509AuthenticationData)) return false;
        final X509AuthenticationData that = (X509AuthenticationData)obj;
        return super.equals(obj) && this.identity.equals(that.identity);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^ identity.hashCode();
    }

    /** Entity X.509 certificate. */
    private final X509Certificate x509cert;
    /** Entity identity. */
    private final String identity;
}

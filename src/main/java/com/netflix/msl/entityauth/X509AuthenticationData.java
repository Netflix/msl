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

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;

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
 *   "x509certificate" : "base64 DER-encoded certificate"
 * }} where:
 * <ul>
 * <li>{@code x509certificate} is Base64-encoded X.509 certificate</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class X509AuthenticationData extends EntityAuthenticationData {
    /** JSON key entity X.509 certificate. */
    private static final String KEY_X509_CERT = "x509certificate";
    private static final String KEY_X509_CHAIN = "x509chain";  // FIXME: remove
    
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
        this.certs = Collections.singleton(x509cert);
        this.identity = x509cert.getSubjectX500Principal().getName();
    }
    
    /**
     * Construct a new X.509 asymmetric keys authentication data instance from
     * the provided JSON object.
     * 
     * @param x509AuthJO the authentication data JSON object.
     * @throws MslCryptoException if the X.509 certificate data cannot be
     *         parsed.
     * @throws MslEncodingException if the X.509 certificate cannot be found.
     */
    @SuppressWarnings("unchecked")  // FIXME: remove
    X509AuthenticationData(final JSONObject x509AuthJO) throws MslCryptoException, MslEncodingException {
        super(EntityAuthenticationScheme.X509);
        // Extract X.509 certificate representation.
        String inString;
        byte[] inBytes;
        try {
        	if (x509AuthJO.has(KEY_X509_CERT)) {
        		inString = x509AuthJO.getString(KEY_X509_CERT);
                try {
                    inBytes = DatatypeConverter.parseBase64Binary(inString);
                } catch (final IllegalArgumentException e) {
                    throw new MslCryptoException(MslError.X509CERT_INVALID, inString, e);
                }
        	} else if (x509AuthJO.has(KEY_X509_CHAIN)) {
        		// FIXME TODO
        		throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "X.509 authdata " + x509AuthJO.toString(), null);
        	} else {
        		throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "X.509 authdata " + x509AuthJO.toString(), null);
        	}
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "X.509 authdata " + x509AuthJO.toString(), e);
        }
        
        // Get the X.509 certificate factory.
        final CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (final CertificateException e) {
            throw new MslInternalException("No certificate X.509 certificate factory.", e);
        }
        
        // Create X.509 cert.
        try {
            final ByteArrayInputStream bais = new ByteArrayInputStream(inBytes);
            certs = (Collection<X509Certificate>)factory.generateCertificates(bais);
            if (certs.isEmpty()) {
            	throw new MslCryptoException(MslError.X509CERT_PARSE_ERROR, inString, null);
            }
            identity = getX509Cert().getSubjectX500Principal().getName();
        } catch (final CertificateException e) {
            throw new MslCryptoException(MslError.X509CERT_PARSE_ERROR, inString, e);
        }
    }
    
    /**
     * @return the X.509 certificate.
     */
    public X509Certificate getX509Cert() {
    	return certs.iterator().next();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getIdentity()
     */
    @Override
    public String getIdentity() {
        return identity;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        final JSONObject jsonObj = new JSONObject();
        try {
            jsonObj.put(KEY_X509_CERT, DatatypeConverter.printBase64Binary(getX509Cert().getEncoded()));
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "X.509 authdata", e);
        } catch (final CertificateEncodingException e) {
            throw new MslEncodingException(MslError.X509CERT_ENCODE_ERROR, "X.509 authdata", e);
        }
        return jsonObj;
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
    private final Collection<X509Certificate> certs;
    /** Entity identity. */
    private final String identity;
}

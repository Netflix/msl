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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;

/**
 * X.509 asymmetric keys entity authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class X509AuthenticationFactoryTest {
    /** X.509 expired resource certificate. */
    private static final String X509_EXPIRED_CERT = "entityauth/expired.pem";
    /** X.509 untrusted resource certificate. */
    private static final String X509_UNTRUSTED_CERT = "entityauth/untrusted.pem";

    /** JSON key entity X.509 certificate. */
    private static final String KEY_X509_CERT = "x509certificate";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();

    /** Authentication utilities. */
    private static MockAuthenticationUtils authutils;
    
    @BeforeClass
    public static void setup() throws IOException, MslEncodingException, MslCryptoException, CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        
        final CertificateFactory x509Factory = CertificateFactory.getInstance("X.509");
        
        final URL expiredUrl = X509AuthenticationDataTest.class.getClassLoader().getResource(X509_EXPIRED_CERT);
        final InputStream expiredInputStream = expiredUrl.openStream();
        expiredCert = (X509Certificate)x509Factory.generateCertificate(expiredInputStream);

        final URL untrustedUrl = X509AuthenticationDataTest.class.getClassLoader().getResource(X509_UNTRUSTED_CERT);
        final InputStream untrustedInputStream = untrustedUrl.openStream();
        untrustedCert = (X509Certificate)x509Factory.generateCertificate(untrustedInputStream);
        
        final X509Store caStore = new X509Store();
        caStore.addTrusted(MockX509AuthenticationFactory.X509_CERT);
        caStore.addTrusted(MockX509AuthenticationFactory.X509_ROOT);
        authutils = new MockAuthenticationUtils();
        factory = new X509AuthenticationFactory(caStore, authutils);
        ctx.addEntityAuthenticationFactory(factory);
    }
    
    @AfterClass
    public static void teardown() {
        untrustedCert = null;
        expiredCert = null;
        factory = null;
        ctx = null;
    }
    
    @After
    public void reset() {
        authutils.reset();
    }
    
    @Test
    public void createData() throws MslEncodingException, MslCryptoException, MslEntityAuthException, JSONException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final JSONObject entityAuthJO = data.getAuthData();
        
        final EntityAuthenticationData authdata = factory.createData(ctx, entityAuthJO);
        assertNotNull(authdata);
        assertTrue(authdata instanceof X509AuthenticationData);
        
        final JSONObject dataJo = new JSONObject(data.toJSONString());
        final JSONObject authdataJo = new JSONObject(authdata.toJSONString());
        assertTrue(JsonUtils.equals(dataJo, authdataJo));
    }
    
    @Test
    public void encodeException() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final JSONObject entityAuthJO = data.getAuthData();
        entityAuthJO.remove(KEY_X509_CERT);
        factory.createData(ctx, entityAuthJO);
    }
    
    @Test
    public void cryptoContext() throws MslCryptoException, MslEntityAuthException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, data);
        assertNotNull(cryptoContext);
    }
    
    @Test
    public void untrustedCert() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.X509CERT_VERIFICATION_FAILED);

        final X509AuthenticationData data = new X509AuthenticationData(untrustedCert);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void expiredCert() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.X509CERT_EXPIRED);

        final X509AuthenticationData data = new X509AuthenticationData(expiredCert);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void revoked() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITY_REVOKED);

        authutils.revokeEntity(MockX509AuthenticationFactory.X509_ESN);
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void chain() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
    	final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CHAIN_JO);
    	factory.getCryptoContext(ctx, data);
        // FIXME TODO
    }

    /** MSL context. */
    private static MockMslContext ctx;
    /** Entity authentication factory. */
    private static EntityAuthenticationFactory factory;
    
    /** Expired X.509 certificate. */
    private static X509Certificate expiredCert;
    /** Untrusted X.509 certificate. */
    private static X509Certificate untrustedCert;
}

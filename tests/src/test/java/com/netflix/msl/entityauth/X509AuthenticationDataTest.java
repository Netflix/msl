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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * X.509 entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class X509AuthenticationDataTest {
    /** X.509 expired resource certificate. */
    private static final String X509_EXPIRED_CERT = "entityauth/expired.pem";
    
    /** JSON key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** JSON key entity X.509 certificate. */
    private static final String KEY_X509_CERT = "x509certificate";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws IOException, MslEncodingException, MslCryptoException, CertificateException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        
        final URL expiredUrl = X509AuthenticationDataTest.class.getClassLoader().getResource(X509_EXPIRED_CERT);
        final InputStream expiredInputStream = expiredUrl.openStream();
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        expiredCert = (X509Certificate)factory.generateCertificate(expiredInputStream);
    }
    
    @AfterClass
    public static void teardown() {
        expiredCert = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslCryptoException, MslEncodingException, JSONException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        assertEquals(MockX509AuthenticationFactory.X509_CERT, data.getX509Cert());
        assertEquals(EntityAuthenticationScheme.X509, data.getScheme());
        assertEquals(MockX509AuthenticationFactory.X509_CERT.getSubjectX500Principal().getName(), data.getIdentity());
        final JSONObject authdata = data.getAuthData();
        assertNotNull(authdata);
        final String jsonString = data.toJSONString();
        assertNotNull(jsonString);
        
        final X509AuthenticationData joData = new X509AuthenticationData(authdata);
        assertEquals(data.getX509Cert(), joData.getX509Cert());
        assertEquals(data.getScheme(), joData.getScheme());
        assertEquals(data.getIdentity(), joData.getIdentity());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(authdata, joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void jsonString() throws JSONException, UnsupportedEncodingException, MslCryptoException, CertificateEncodingException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final JSONObject jo = new JSONObject(data.toJSONString());
        assertEquals(EntityAuthenticationScheme.X509.name(), jo.getString(KEY_SCHEME));
        final JSONObject authdata = jo.getJSONObject(KEY_AUTHDATA);
        final String x509certificate = authdata.getString(KEY_X509_CERT);
        assertArrayEquals(MockX509AuthenticationFactory.X509_CERT.getEncoded(), Base64.decode(x509certificate));
    }
    
    @Test
    public void create() throws JSONException, MslEntityAuthException, MslEncodingException, MslCryptoException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final String jsonString = data.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, jo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof X509AuthenticationData);
        
        final X509AuthenticationData joData = (X509AuthenticationData)entitydata;
        assertEquals(data.getX509Cert(), joData.getX509Cert());
        assertEquals(data.getScheme(), joData.getScheme());
        assertEquals(data.getIdentity(), joData.getIdentity());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(data.getAuthData(), joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void missingX509Cert() throws MslEncodingException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_X509_CERT);
        new X509AuthenticationData(authdata);
    }
    
    @Test
    public void corruptX509Cert() throws JSONException, MslEncodingException, MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.X509CERT_PARSE_ERROR);

        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final JSONObject authdata = data.getAuthData();
        final String x509b64 = authdata.getString(KEY_X509_CERT);
        final byte[] x509raw = Base64.decode(x509b64);
        ++x509raw[0];
        authdata.put(KEY_X509_CERT, Base64.encode(x509raw));
        new X509AuthenticationData(authdata);
    }
    
    @Test
    public void equalsIdentity() throws MslEncodingException, JSONException, MslEntityAuthException, MslCryptoException {
        final X509AuthenticationData dataA = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final X509AuthenticationData dataB = new X509AuthenticationData(expiredCert);
        final EntityAuthenticationData dataA2 = EntityAuthenticationData.create(ctx, new JSONObject(dataA.toJSONString()));
        
        assertTrue(dataA.equals(dataA));
        assertEquals(dataA.hashCode(), dataA.hashCode());
        
        assertFalse(dataA.equals(dataB));
        assertFalse(dataB.equals(dataA));
        assertTrue(dataA.hashCode() != dataB.hashCode());
        
        assertTrue(dataA.equals(dataA2));
        assertTrue(dataA2.equals(dataA));
        assertEquals(dataA.hashCode(), dataA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslCryptoException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        assertFalse(data.equals(null));
        assertFalse(data.equals(KEY_X509_CERT));
        assertTrue(data.hashCode() != KEY_X509_CERT.hashCode());
    }
    
    /** MSL context. */
    private static MslContext ctx;

    /** Expired X.509 certificate. */
    private static X509Certificate expiredCert;
}

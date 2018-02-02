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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.IOUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * X.509 entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class X509AuthenticationDataTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** X.509 expired resource certificate. */
    private static final String X509_EXPIRED_CERT = "/entityauth/expired.pem";
    
    /** Key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** Key entity X.509 certificate. */
    private static final String KEY_X509_CERT = "x509certificate";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws IOException, MslEncodingException, MslCryptoException, CertificateException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        encoder = ctx.getMslEncoderFactory();
        expiredCert = IOUtils.readX509(X509_EXPIRED_CERT);
    }
    
    @AfterClass
    public static void teardown() {
        expiredCert = null;
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslCryptoException, MslEncodingException, MslEncoderException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        assertEquals(MockX509AuthenticationFactory.X509_CERT, data.getX509Cert());
        assertEquals(EntityAuthenticationScheme.X509, data.getScheme());
        assertEquals(MockX509AuthenticationFactory.X509_CERT.getSubjectX500Principal().getName(), data.getIdentity());
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(authdata);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final X509AuthenticationData moData = new X509AuthenticationData(authdata);
        assertEquals(data.getX509Cert(), moData.getX509Cert());
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getIdentity(), moData.getIdentity());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(authdata, moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void encode() throws MslEncoderException, UnsupportedEncodingException, MslCryptoException, CertificateEncodingException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        assertEquals(EntityAuthenticationScheme.X509.name(), mo.getString(KEY_SCHEME));
        final MslObject authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
        final String x509certificate = authdata.getString(KEY_X509_CERT);
        assertArrayEquals(MockX509AuthenticationFactory.X509_CERT.getEncoded(), Base64.decode(x509certificate));
    }
    
    @Test
    public void create() throws MslEncoderException, MslEntityAuthException, MslEncodingException, MslCryptoException {
        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, mo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof X509AuthenticationData);
        
        final X509AuthenticationData moData = (X509AuthenticationData)entitydata;
        assertEquals(data.getX509Cert(), moData.getX509Cert());
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getIdentity(), moData.getIdentity());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(data.getAuthData(encoder, ENCODER_FORMAT), moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void missingX509Cert() throws MslEncodingException, MslCryptoException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_X509_CERT);
        new X509AuthenticationData(authdata);
    }
    
    @Test
    public void corruptX509Cert() throws MslEncoderException, MslEncodingException, MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.X509CERT_PARSE_ERROR);

        final X509AuthenticationData data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        final byte[] x509raw = Base64.decode(authdata.getString(KEY_X509_CERT));
        ++x509raw[0];
        authdata.put(KEY_X509_CERT, Base64.encode(x509raw));
        new X509AuthenticationData(authdata);
    }
    
    @Test
    public void equalsIdentity() throws MslEncodingException, MslEncoderException, MslEntityAuthException, MslCryptoException {
        final X509AuthenticationData dataA = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        final X509AuthenticationData dataB = new X509AuthenticationData(expiredCert);
        final EntityAuthenticationData dataA2 = EntityAuthenticationData.create(ctx, MslTestUtils.toMslObject(encoder, dataA));
        
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
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;

    /** Expired X.509 certificate. */
    private static X509Certificate expiredCert;
}

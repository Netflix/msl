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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

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
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Preshared keys entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PresharedAuthenticationDataTest {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** Key entity identity. */
    private static final String KEY_IDENTITY = "identity";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws IOException, MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        encoder = ctx.getMslEncoderFactory();
    }
    
    @AfterClass
    public static void teardown() {
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslEncodingException, MslEncoderException {
        final PresharedAuthenticationData data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        assertEquals(MockPresharedAuthenticationFactory.PSK_ESN, data.getIdentity());
        assertEquals(EntityAuthenticationScheme.PSK, data.getScheme());
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(authdata);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final PresharedAuthenticationData moData = new PresharedAuthenticationData(authdata);
        assertEquals(data.getIdentity(), moData.getIdentity());
        assertEquals(data.getScheme(), moData.getScheme());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(authdata, moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void mslObject() throws MslEncoderException {
        final PresharedAuthenticationData data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        assertEquals(EntityAuthenticationScheme.PSK.toString(), mo.getString(KEY_SCHEME));
        final MslObject authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
        assertEquals(MockPresharedAuthenticationFactory.PSK_ESN, authdata.getString(KEY_IDENTITY));
    }
    
    @Test
    public void create() throws MslEncoderException, MslEntityAuthException, MslEncodingException, MslCryptoException {
        final PresharedAuthenticationData data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, mo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof PresharedAuthenticationData);
        
        final PresharedAuthenticationData moData = (PresharedAuthenticationData)entitydata;
        assertEquals(data.getIdentity(), moData.getIdentity());
        assertEquals(data.getScheme(), moData.getScheme());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(data.getAuthData(encoder, ENCODER_FORMAT), moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void missingIdentity() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PresharedAuthenticationData data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_IDENTITY);
        new PresharedAuthenticationData(authdata);
    }

    
    @Test
    public void equalsIdentity() throws MslEncodingException, MslEncoderException, MslEntityAuthException, MslCryptoException {
        final String identityA = MockPresharedAuthenticationFactory.PSK_ESN + "A";
        final String identityB = MockPresharedAuthenticationFactory.PSK_ESN + "B";
        final PresharedAuthenticationData dataA = new PresharedAuthenticationData(identityA);
        final PresharedAuthenticationData dataB = new PresharedAuthenticationData(identityB);
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
    public void equalsObject() {
        final PresharedAuthenticationData data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        assertFalse(data.equals(null));
        assertFalse(data.equals(KEY_IDENTITY));
        assertTrue(data.hashCode() != KEY_IDENTITY.hashCode());
    }

    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
}

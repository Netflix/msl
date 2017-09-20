/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * Preshared keys profile entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PresharedProfileAuthenticationDataTest {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** Key entity preshared keys identity. */
    private static final String KEY_PSKID = "pskid";
    /** Key entity profile. */
    private static final String KEY_PROFILE = "profile";
    
    /** Identity concatenation character. */
    private static final String CONCAT_CHAR = "-";
    
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
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        assertEquals(MockPresharedProfileAuthenticationFactory.PSK_ESN + CONCAT_CHAR + MockPresharedProfileAuthenticationFactory.PROFILE, data.getIdentity());
        assertEquals(MockPresharedProfileAuthenticationFactory.PSK_ESN, data.getPresharedKeysId());
        assertEquals(MockPresharedProfileAuthenticationFactory.PROFILE, data.getProfile());
        assertEquals(EntityAuthenticationScheme.PSK_PROFILE, data.getScheme());
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(authdata);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final PresharedProfileAuthenticationData moData = new PresharedProfileAuthenticationData(authdata);
        assertEquals(data.getIdentity(), moData.getIdentity());
        assertEquals(data.getPresharedKeysId(), moData.getPresharedKeysId());
        assertEquals(data.getProfile(), moData.getProfile());
        assertEquals(data.getScheme(), moData.getScheme());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(authdata, moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void encode() throws MslEncoderException {
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        assertEquals(EntityAuthenticationScheme.PSK_PROFILE.toString(), mo.getString(KEY_SCHEME));
        final MslObject authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
        assertEquals(MockPresharedProfileAuthenticationFactory.PSK_ESN, authdata.getString(KEY_PSKID));
        assertEquals(MockPresharedProfileAuthenticationFactory.PROFILE, authdata.getString(KEY_PROFILE));
    }
    
    @Test
    public void create() throws MslEncoderException, MslEntityAuthException, MslEncodingException, MslCryptoException {
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, mo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof PresharedProfileAuthenticationData);
        
        final PresharedProfileAuthenticationData moData = (PresharedProfileAuthenticationData)entitydata;
        assertEquals(data.getIdentity(), moData.getIdentity());
        assertEquals(data.getPresharedKeysId(), moData.getPresharedKeysId());
        assertEquals(data.getProfile(), moData.getProfile());
        assertEquals(data.getScheme(), moData.getScheme());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(data.getAuthData(encoder, ENCODER_FORMAT), moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void missingPskId() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_PSKID);
        new PresharedProfileAuthenticationData(authdata);
    }
    
    @Test
    public void missingProfile() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_PROFILE);
        new PresharedProfileAuthenticationData(authdata);
    }
    
    @Test
    public void equalsPskId() throws MslEncodingException, MslEncoderException, MslEntityAuthException, MslCryptoException {
        final String pskIdA = MockPresharedProfileAuthenticationFactory.PSK_ESN + "A";
        final String pskIdB = MockPresharedProfileAuthenticationFactory.PSK_ESN + "B";
        final PresharedProfileAuthenticationData dataA = new PresharedProfileAuthenticationData(pskIdA, MockPresharedProfileAuthenticationFactory.PROFILE);
        final PresharedProfileAuthenticationData dataB = new PresharedProfileAuthenticationData(pskIdB, MockPresharedProfileAuthenticationFactory.PROFILE);
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
    public void equalsProfile() throws MslEncodingException, MslEncoderException, MslEntityAuthException, MslCryptoException {
        final String profileA = MockPresharedProfileAuthenticationFactory.PROFILE + "A";
        final String profileB = MockPresharedProfileAuthenticationFactory.PROFILE + "B";
        final PresharedProfileAuthenticationData dataA = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, profileA);
        final PresharedProfileAuthenticationData dataB = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, profileB);
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
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        assertFalse(data.equals(null));
        assertFalse(data.equals(KEY_PSKID));
        assertTrue(data.hashCode() != KEY_PSKID.hashCode());
    }

    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
}

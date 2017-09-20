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
package com.netflix.msl.userauth;

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
import com.netflix.msl.MslError;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
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
 * Email/password user authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class EmailPasswordAuthenticationDataTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key user authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key user authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** Key email. */
    private static final String KEY_EMAIL = "email";
    /** Key password. */
    private static final String KEY_PASSWORD = "password";

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
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        assertEquals(UserAuthenticationScheme.EMAIL_PASSWORD, data.getScheme());
        assertEquals(MockEmailPasswordAuthenticationFactory.EMAIL, data.getEmail());
        assertEquals(MockEmailPasswordAuthenticationFactory.PASSWORD, data.getPassword());
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(authdata);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        
        final EmailPasswordAuthenticationData moData = new EmailPasswordAuthenticationData(authdata);
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getEmail(), moData.getEmail());
        assertEquals(data.getPassword(), moData.getPassword());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(authdata, moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void mslObject() throws MslEncoderException {
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        assertEquals(UserAuthenticationScheme.EMAIL_PASSWORD.toString(), mo.getString(KEY_SCHEME));
        final MslObject authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
        assertEquals(MockEmailPasswordAuthenticationFactory.EMAIL, authdata.getString(KEY_EMAIL));
        assertEquals(MockEmailPasswordAuthenticationFactory.PASSWORD, authdata.getString(KEY_PASSWORD));
    }
    
    @Test
    public void create() throws MslUserAuthException, MslEncodingException, MslEncoderException, MslCryptoException {
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        final UserAuthenticationData userdata = UserAuthenticationData.create(ctx, null, mo);
        assertNotNull(userdata);
        assertTrue(userdata instanceof EmailPasswordAuthenticationData);
        
        final EmailPasswordAuthenticationData moData = (EmailPasswordAuthenticationData)userdata;
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getEmail(), moData.getEmail());
        assertEquals(data.getPassword(), moData.getPassword());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(data.getAuthData(encoder, ENCODER_FORMAT), moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void missingEmail() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_EMAIL);
        new EmailPasswordAuthenticationData(authdata);
    }
    
    @Test
    public void missingPassword() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_PASSWORD);
        new EmailPasswordAuthenticationData(authdata);
    }
    
    @Test
    public void equalsEmail() throws MslEncodingException {
        final EmailPasswordAuthenticationData dataA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "A", MockEmailPasswordAuthenticationFactory.PASSWORD);
        final EmailPasswordAuthenticationData dataB = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "B", MockEmailPasswordAuthenticationFactory.PASSWORD);
        final EmailPasswordAuthenticationData dataA2 = new EmailPasswordAuthenticationData(dataA.getAuthData(encoder, ENCODER_FORMAT));
        
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
    public void equalsPassword() throws MslEncodingException {
        final EmailPasswordAuthenticationData dataA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "A");
        final EmailPasswordAuthenticationData dataB = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "B");
        final EmailPasswordAuthenticationData dataA2 = new EmailPasswordAuthenticationData(dataA.getAuthData(encoder, ENCODER_FORMAT));
        
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
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        assertFalse(data.equals(null));
        assertFalse(data.equals(KEY_EMAIL));
        assertTrue(data.hashCode() != KEY_EMAIL.hashCode());
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
}

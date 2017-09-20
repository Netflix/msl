/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Master token protected entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterTokenProtectedAuthenticationDataTest {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    
    /** Key master token. */
    protected static final String KEY_MASTER_TOKEN = "mastertoken";
    /** Key authentication data. */
    protected static final String KEY_AUTHENTICATION_DATA = "authdata";
    /** Key signature. */
    protected static final String KEY_SIGNATURE = "signature";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    private static final String IDENTITY = "identity";

    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Master token. */
    private static MasterToken masterToken;
    /** Encapsulated entity authentication data. */
    private static EntityAuthenticationData eAuthdata;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        encoder = ctx.getMslEncoderFactory();
        masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        eAuthdata = new UnauthenticatedAuthenticationData(IDENTITY);
    }
    
    @AfterClass
    public static void teardown() {
        eAuthdata = null;
        masterToken = null;
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslCryptoException, MslEntityAuthException, MslEncodingException, MslEncoderException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        assertEquals(eAuthdata.getIdentity(), data.getIdentity());
        assertEquals(EntityAuthenticationScheme.MT_PROTECTED, data.getScheme());
        assertEquals(eAuthdata, data.getEncapsulatedAuthdata());
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(authdata);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MasterTokenProtectedAuthenticationData moData = new MasterTokenProtectedAuthenticationData(ctx, authdata);
        assertEquals(data.getIdentity(), moData.getIdentity());
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getEncapsulatedAuthdata(), moData.getEncapsulatedAuthdata());
        assertEquals(data, moData);
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        // The authdata will not be equal as it is regenerated.
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // The encode will not be equal as it is regenerated.
    }
    
    @Test
    public void mslObject() throws MslMasterTokenException, MslCryptoException, MslEntityAuthException, MslEncoderException, MslEncodingException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        assertEquals(EntityAuthenticationScheme.MT_PROTECTED.toString(), mo.getString(KEY_SCHEME));
        final MslObject authdata = mo.getMslObject(KEY_AUTHDATA, encoder);

        final MslObject masterTokenMo = MslTestUtils.toMslObject(encoder, masterToken);
        final MslObject moMasterTokenMo = authdata.getMslObject(KEY_MASTER_TOKEN, encoder);
        assertTrue(MslEncoderUtils.equalObjects(masterTokenMo, moMasterTokenMo));

        final byte[] ciphertext = authdata.getBytes(KEY_AUTHDATA);
        final byte[] signature = authdata.getBytes(KEY_SIGNATURE);
        assertNotNull(signature);
        // Signature and ciphertext may not be predictable depending on the
        // master token encryption and signature algorithms.

        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject moEAuthdataMo = encoder.parseObject(plaintext);
        final EntityAuthenticationData moEAuthdata = EntityAuthenticationData.create(ctx, moEAuthdataMo);
        assertEquals(eAuthdata, moEAuthdata);
    }
    
    @Test
    public void create() throws MslCryptoException, MslEntityAuthException, MslEncodingException, MslEncoderException, MslMasterTokenException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, mo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof MasterTokenProtectedAuthenticationData);
        
        final MasterTokenProtectedAuthenticationData moData = (MasterTokenProtectedAuthenticationData)entitydata;
        assertEquals(data.getIdentity(), moData.getIdentity());
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getEncapsulatedAuthdata(), moData.getEncapsulatedAuthdata());
        assertEquals(data, moData);
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        // The authdata will not be equal as it is regenerated.

        final MslObject masterTokenMo = MslTestUtils.toMslObject(encoder, masterToken);
        final MslObject moMasterTokenMo = moAuthdata.getMslObject(KEY_MASTER_TOKEN, encoder);
        assertTrue(MslEncoderUtils.equalObjects(masterTokenMo, moMasterTokenMo));

        final byte[] ciphertext = moAuthdata.getBytes(KEY_AUTHDATA);
        final byte[] signature = moAuthdata.getBytes(KEY_SIGNATURE);
        assertNotNull(signature);
        // Signature and ciphertext may not be predictable depending on the
        // master token encryption and signature algorithms.

        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject moEAuthdataMo = encoder.parseObject(plaintext);
        final EntityAuthenticationData moEAuthdata = EntityAuthenticationData.create(ctx, moEAuthdataMo);
        assertEquals(eAuthdata, moEAuthdata);
        
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // The encode will not be equal as it is regenerated.
    }
    
    @Test
    public void missingMasterToken() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_MASTER_TOKEN);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidMasterToken() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_MASTER_TOKEN, "x");
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void corruptMasterToken() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_MASTERTOKEN_INVALID);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_MASTER_TOKEN, new MslObject());
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void missingAuthdata() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_AUTHENTICATION_DATA);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidAuthdata() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_AUTHENTICATION_DATA, true);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Ignore
    @Test
    public void corruptAuthdata() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_CIPHERTEXT_INVALID);

        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_AUTHENTICATION_DATA, new byte[] { 'x' });
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void missingSignature() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_SIGNATURE);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidSignature() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_SIGNATURE, true);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Ignore
    @Test
    public void corruptSignature() throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslEncoderException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_SIGNATURE_INVALID);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_SIGNATURE, new byte[] { 'x' });
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void equalsMasterToken() throws MslEntityAuthException, MslEncodingException, MslCryptoException, MslEncoderException {
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 2L, 2L);
        final MasterTokenProtectedAuthenticationData dataA = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MasterTokenProtectedAuthenticationData dataB = new MasterTokenProtectedAuthenticationData(ctx, masterTokenB, eAuthdata);
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
    public void equalsAuthdata() throws MslEntityAuthException, MslEncodingException, MslCryptoException, MslEncoderException {
        final EntityAuthenticationData eAuthdataB = new UnauthenticatedAuthenticationData(IDENTITY + "B");
        final MasterTokenProtectedAuthenticationData dataA = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MasterTokenProtectedAuthenticationData dataB = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdataB);
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
    public void equalsObject() throws MslCryptoException, MslEntityAuthException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        assertFalse(data.equals(null));
        assertFalse(data.equals(IDENTITY));
        assertTrue(data.hashCode() != IDENTITY.hashCode());
    }
}
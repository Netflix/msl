/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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

import org.json.JSONException;
import org.json.JSONObject;
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
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Master token protected entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterTokenProtectedAuthenticationDataTest {
    /** JSON key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    
    /** JSON key master token. */
    protected static final String KEY_MASTER_TOKEN = "mastertoken";
    /** JSON key authentication data. */
    protected static final String KEY_AUTHENTICATION_DATA = "authdata";
    /** JSON key signature. */
    protected static final String KEY_SIGNATURE = "signature";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    private static final String IDENTITY = "identity";

    /** MSL context. */
    private static MslContext ctx;
    /** Master token. */
    private static MasterToken masterToken;
    /** Encapsulated entity authentication data. */
    private static EntityAuthenticationData eAuthdata;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        eAuthdata = new UnauthenticatedAuthenticationData(IDENTITY);
    }
    
    @AfterClass
    public static void teardown() {
        eAuthdata = null;
        masterToken = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslCryptoException, MslEntityAuthException, MslEncodingException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        assertEquals(eAuthdata.getIdentity(), data.getIdentity());
        assertEquals(EntityAuthenticationScheme.MT_PROTECTED, data.getScheme());
        assertEquals(eAuthdata, data.getEncapsulatedAuthdata());
        final JSONObject authdata = data.getAuthData();
        assertNotNull(authdata);
        final String jsonString = data.toJSONString();
        assertNotNull(jsonString);
        
        final MasterTokenProtectedAuthenticationData joData = new MasterTokenProtectedAuthenticationData(ctx, authdata);
        assertEquals(data.getIdentity(), joData.getIdentity());
        assertEquals(data.getScheme(), joData.getScheme());
        assertEquals(data.getEncapsulatedAuthdata(), joData.getEncapsulatedAuthdata());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(authdata, joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void jsonString() throws MslMasterTokenException, MslCryptoException, MslEntityAuthException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject jo = new JSONObject(data.toJSONString());
        assertEquals(EntityAuthenticationScheme.MT_PROTECTED.toString(), jo.getString(KEY_SCHEME));
        final JSONObject authdata = jo.getJSONObject(KEY_AUTHDATA);

        final String masterTokenStr = masterToken.toJSONString();
        assertTrue(JsonUtils.equals(new JSONObject(masterTokenStr), authdata.getJSONObject(KEY_MASTER_TOKEN)));
        // Signature and ciphertext may not be predictable depending on the
        // master token encryption and signature algorithms.
    }
    
    @Test
    public void create() throws MslCryptoException, MslEntityAuthException, MslEncodingException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final String jsonString = data.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, jo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof MasterTokenProtectedAuthenticationData);
        
        final MasterTokenProtectedAuthenticationData joData = (MasterTokenProtectedAuthenticationData)entitydata;
        assertEquals(data.getIdentity(), joData.getIdentity());
        assertEquals(data.getScheme(), joData.getScheme());
        assertEquals(data.getEncapsulatedAuthdata(), joData.getEncapsulatedAuthdata());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(data.getAuthData(), joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void missingMasterToken() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_MASTER_TOKEN);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidMasterToken() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.put(KEY_MASTER_TOKEN, "x");
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void corruptMasterToken() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_MASTERTOKEN_INVALID);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.put(KEY_MASTER_TOKEN, new JSONObject());
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void missingAuthdata() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_AUTHENTICATION_DATA);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidAuthdata() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.put(KEY_AUTHENTICATION_DATA, true);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Ignore
    @Test
    public void corruptAuthdata() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_CIPHERTEXT_INVALID);

        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.put(KEY_AUTHENTICATION_DATA, "x");
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void missingSignature() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_SIGNATURE);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidSignature() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.put(KEY_SIGNATURE, true);
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Ignore
    @Test
    public void corruptSignature() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_SIGNATURE_INVALID);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject authdata = data.getAuthData();
        authdata.put(KEY_SIGNATURE, "x");
        new MasterTokenProtectedAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void equalsMasterToken() throws MslEntityAuthException, MslEncodingException, MslCryptoException, JSONException {
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 2L, 2L);
        final MasterTokenProtectedAuthenticationData dataA = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MasterTokenProtectedAuthenticationData dataB = new MasterTokenProtectedAuthenticationData(ctx, masterTokenB, eAuthdata);
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
    public void equalsAuthdata() throws MslEntityAuthException, MslEncodingException, MslCryptoException, JSONException {
        final EntityAuthenticationData eAuthdataB = new UnauthenticatedAuthenticationData(IDENTITY + "B");
        final MasterTokenProtectedAuthenticationData dataA = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final MasterTokenProtectedAuthenticationData dataB = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdataB);
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
    public void equalsObject() throws MslCryptoException, MslEntityAuthException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        assertFalse(data.equals(null));
        assertFalse(data.equals(IDENTITY));
        assertTrue(data.hashCode() != IDENTITY.hashCode());
    }
}
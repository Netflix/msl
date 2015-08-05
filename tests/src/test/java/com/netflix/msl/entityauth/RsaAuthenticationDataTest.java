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

import static org.junit.Assert.*;

import java.io.IOException;

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
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * RSA entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class RsaAuthenticationDataTest {
    /** JSON key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** JSON key entity identity. */
    private static final String KEY_IDENTITY = "identity";
    /** JSON key public key ID. */
    private static final String KEY_PUBKEY_ID = "pubkeyid";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws IOException, MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
    }
    
    @AfterClass
    public static void teardown() {
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslEncodingException, JSONException, MslCryptoException {
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        assertEquals(MockRsaAuthenticationFactory.RSA_ESN, data.getIdentity());
        assertEquals(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, data.getPublicKeyId());
        assertEquals(EntityAuthenticationScheme.RSA, data.getScheme());
        final JSONObject authdata = data.getAuthData();
        assertNotNull(authdata);
        final String jsonString = data.toJSONString();
        assertNotNull(jsonString);
        
        final RsaAuthenticationData joData = new RsaAuthenticationData(authdata);
        assertEquals(data.getIdentity(), joData.getIdentity());
        assertEquals(data.getPublicKeyId(), joData.getPublicKeyId());
        assertEquals(data.getScheme(), joData.getScheme());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(authdata, joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void jsonString() throws JSONException, MslCryptoException {
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final JSONObject jo = new JSONObject(data.toJSONString());
        assertEquals(EntityAuthenticationScheme.RSA.toString(), jo.getString(KEY_SCHEME));
        final JSONObject authdata = jo.getJSONObject(KEY_AUTHDATA);
        assertEquals(MockRsaAuthenticationFactory.RSA_ESN, authdata.getString(KEY_IDENTITY));
        assertEquals(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, authdata.get(KEY_PUBKEY_ID));
    }
    
    @Test
    public void create() throws JSONException, MslEntityAuthException, MslEncodingException, MslCryptoException {
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final String jsonString = data.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, jo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof RsaAuthenticationData);
        
        final RsaAuthenticationData joData = (RsaAuthenticationData)entitydata;
        assertEquals(data.getIdentity(), joData.getIdentity());
        assertEquals(data.getPublicKeyId(), joData.getPublicKeyId());
        assertEquals(data.getScheme(), joData.getScheme());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(data.getAuthData(), joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void missingIdentity() throws MslEncodingException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final JSONObject authdata = data.getAuthData();
        assertNotNull(authdata.remove(KEY_IDENTITY));
        new RsaAuthenticationData(authdata);
    }

    @Test
    public void missingPubkeyId() throws MslEncodingException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final JSONObject authdata = data.getAuthData();
        assertNotNull(authdata.remove(KEY_PUBKEY_ID));
        new RsaAuthenticationData(authdata);
    }
    
    @Test
    public void equalsIdentity() throws MslEncodingException, JSONException, MslEntityAuthException, MslCryptoException {
        final String identityA = MockRsaAuthenticationFactory.RSA_ESN + "A";
        final String identityB = MockRsaAuthenticationFactory.RSA_ESN + "B";
        final RsaAuthenticationData dataA = new RsaAuthenticationData(identityA, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final RsaAuthenticationData dataB = new RsaAuthenticationData(identityB, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
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
    public void equalsPubKeyId() throws MslEncodingException, JSONException, MslEntityAuthException, MslCryptoException {
        final String pubkeyidA = MockRsaAuthenticationFactory.RSA_PUBKEY_ID + "A";
        final String pubkeyidB = MockRsaAuthenticationFactory.RSA_PUBKEY_ID + "B";
        final RsaAuthenticationData dataA = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, pubkeyidA);
        final RsaAuthenticationData dataB = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, pubkeyidB);
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
    public void equalsObject() {
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        assertFalse(data.equals(null));
        assertFalse(data.equals(KEY_IDENTITY));
        assertTrue(data.hashCode() != KEY_IDENTITY.hashCode());
    }

    /** MSL context. */
    private static MslContext ctx;
}

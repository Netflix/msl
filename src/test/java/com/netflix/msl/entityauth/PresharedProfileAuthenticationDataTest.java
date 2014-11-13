/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
 * Preshared keys profile entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PresharedProfileAuthenticationDataTest {
    /** JSON key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** JSON key entity preshared keys identity. */
    private static final String KEY_PSKID = "pskid";
    /** JSON key entity profile. */
    private static final String KEY_PROFILE = "profile";
    
    /** Identity concatenation character. */
    private static final String CONCAT_CHAR = "-";
    
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
    public void ctors() throws MslEncodingException, JSONException {
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        assertEquals(MockPresharedProfileAuthenticationFactory.PSK_ESN + CONCAT_CHAR + MockPresharedProfileAuthenticationFactory.PROFILE, data.getIdentity());
        assertEquals(MockPresharedProfileAuthenticationFactory.PSK_ESN, data.getPresharedKeysId());
        assertEquals(MockPresharedProfileAuthenticationFactory.PROFILE, data.getProfile());
        assertEquals(EntityAuthenticationScheme.PSK_PROFILE, data.getScheme());
        final JSONObject authdata = data.getAuthData();
        assertNotNull(authdata);
        final String jsonString = data.toJSONString();
        assertNotNull(jsonString);
        
        final PresharedProfileAuthenticationData joData = new PresharedProfileAuthenticationData(authdata);
        assertEquals(data.getIdentity(), joData.getIdentity());
        assertEquals(data.getPresharedKeysId(), joData.getPresharedKeysId());
        assertEquals(data.getProfile(), joData.getProfile());
        assertEquals(data.getScheme(), joData.getScheme());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(authdata, joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void jsonString() throws JSONException {
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final JSONObject jo = new JSONObject(data.toJSONString());
        assertEquals(EntityAuthenticationScheme.PSK_PROFILE.toString(), jo.getString(KEY_SCHEME));
        final JSONObject authdata = jo.getJSONObject(KEY_AUTHDATA);
        assertEquals(MockPresharedProfileAuthenticationFactory.PSK_ESN, authdata.getString(KEY_PSKID));
        assertEquals(MockPresharedProfileAuthenticationFactory.PROFILE, authdata.getString(KEY_PROFILE));
    }
    
    @Test
    public void create() throws JSONException, MslEntityAuthException, MslEncodingException, MslCryptoException {
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final String jsonString = data.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, jo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof PresharedProfileAuthenticationData);
        
        final PresharedProfileAuthenticationData joData = (PresharedProfileAuthenticationData)entitydata;
        assertEquals(data.getIdentity(), joData.getIdentity());
        assertEquals(data.getPresharedKeysId(), joData.getPresharedKeysId());
        assertEquals(data.getProfile(), joData.getProfile());
        assertEquals(data.getScheme(), joData.getScheme());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(data.getAuthData(), joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void missingPskId() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_PSKID);
        new PresharedProfileAuthenticationData(authdata);
    }
    
    @Test
    public void missingProfile() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_PROFILE);
        new PresharedProfileAuthenticationData(authdata);
    }
    
    @Test
    public void equalsPskId() throws MslEncodingException, JSONException, MslEntityAuthException, MslCryptoException {
        final String pskIdA = MockPresharedProfileAuthenticationFactory.PSK_ESN + "A";
        final String pskIdB = MockPresharedProfileAuthenticationFactory.PSK_ESN + "B";
        final PresharedProfileAuthenticationData dataA = new PresharedProfileAuthenticationData(pskIdA, MockPresharedProfileAuthenticationFactory.PROFILE);
        final PresharedProfileAuthenticationData dataB = new PresharedProfileAuthenticationData(pskIdB, MockPresharedProfileAuthenticationFactory.PROFILE);
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
    public void equalsProfile() throws MslEncodingException, JSONException, MslEntityAuthException, MslCryptoException {
        final String profileA = MockPresharedProfileAuthenticationFactory.PROFILE + "A";
        final String profileB = MockPresharedProfileAuthenticationFactory.PROFILE + "B";
        final PresharedProfileAuthenticationData dataA = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, profileA);
        final PresharedProfileAuthenticationData dataB = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, profileB);
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
        final PresharedProfileAuthenticationData data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        assertFalse(data.equals(null));
        assertFalse(data.equals(KEY_PSKID));
        assertTrue(data.hashCode() != KEY_PSKID.hashCode());
    }

    /** MSL context. */
    private static MslContext ctx;
}

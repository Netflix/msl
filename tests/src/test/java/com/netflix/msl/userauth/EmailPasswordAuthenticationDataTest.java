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
package com.netflix.msl.userauth;

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
import com.netflix.msl.MslError;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * Email/password user authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class EmailPasswordAuthenticationDataTest {
    /** JSON key user authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key user authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** JSON email key. */
    private static final String KEY_EMAIL = "email";
    /** JSON password key. */
    private static final String KEY_PASSWORD = "password";

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
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        assertEquals(UserAuthenticationScheme.EMAIL_PASSWORD, data.getScheme());
        assertEquals(MockEmailPasswordAuthenticationFactory.EMAIL, data.getEmail());
        assertEquals(MockEmailPasswordAuthenticationFactory.PASSWORD, data.getPassword());
        final JSONObject authdata = data.getAuthData();
        assertNotNull(authdata);
        final String jsonString = data.toJSONString();
        
        final EmailPasswordAuthenticationData joData = new EmailPasswordAuthenticationData(authdata);
        assertEquals(data.getScheme(), joData.getScheme());
        assertEquals(data.getEmail(), joData.getEmail());
        assertEquals(data.getPassword(), joData.getPassword());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(authdata, joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void jsonString() throws JSONException {
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final JSONObject jo = new JSONObject(data.toJSONString());
        assertEquals(UserAuthenticationScheme.EMAIL_PASSWORD.toString(), jo.getString(KEY_SCHEME));
        final JSONObject authdata = jo.getJSONObject(KEY_AUTHDATA);
        assertEquals(MockEmailPasswordAuthenticationFactory.EMAIL, authdata.getString(KEY_EMAIL));
        assertEquals(MockEmailPasswordAuthenticationFactory.PASSWORD, authdata.getString(KEY_PASSWORD));
    }
    
    @Test
    public void create() throws MslUserAuthException, MslEncodingException, JSONException, MslCryptoException {
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final String jsonString = data.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        final UserAuthenticationData userdata = UserAuthenticationData.create(ctx, null, jo);
        assertNotNull(userdata);
        assertTrue(userdata instanceof EmailPasswordAuthenticationData);
        
        final EmailPasswordAuthenticationData joData = (EmailPasswordAuthenticationData)userdata;
        assertEquals(data.getScheme(), joData.getScheme());
        assertEquals(data.getEmail(), joData.getEmail());
        assertEquals(data.getPassword(), joData.getPassword());
        final JSONObject joAuthdata = joData.getAuthData();
        assertNotNull(joAuthdata);
        assertTrue(JsonUtils.equals(data.getAuthData(), joAuthdata));
        final String joJsonString = joData.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void missingEmail() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_EMAIL);
        new EmailPasswordAuthenticationData(authdata);
    }
    
    @Test
    public void missingPassword() throws MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final JSONObject authdata = data.getAuthData();
        authdata.remove(KEY_PASSWORD);
        new EmailPasswordAuthenticationData(authdata);
    }
    
    @Test
    public void equalsEmail() throws MslEncodingException {
        final EmailPasswordAuthenticationData dataA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "A", MockEmailPasswordAuthenticationFactory.PASSWORD);
        final EmailPasswordAuthenticationData dataB = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "B", MockEmailPasswordAuthenticationFactory.PASSWORD);
        final EmailPasswordAuthenticationData dataA2 = new EmailPasswordAuthenticationData(dataA.getAuthData());
        
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
        final EmailPasswordAuthenticationData dataA2 = new EmailPasswordAuthenticationData(dataA.getAuthData());
        
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
}

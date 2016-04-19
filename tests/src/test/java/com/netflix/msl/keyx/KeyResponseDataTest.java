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
package com.netflix.msl.keyx;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Key response data unit tests.
 * 
 * Successful calls to
 * {@link KeyResponseData#create(com.netflix.msl.util.MslContext, org.json.JSONObject)}
 * covered in the individual key response data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KeyResponseDataTest {
    /** JSON key master token. */
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    /** JSON key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key key request data. */
    private static final String KEY_KEYDATA = "keydata";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    private static MasterToken MASTER_TOKEN;

    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1, 1);
    }
    
    @AfterClass
    public static void teardown() {
        MASTER_TOKEN = null;
        ctx = null;
    }
    
    @Test
    public void noMasterToken() throws JSONException, MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JSONObject jo = new JSONObject();
        jo.put(KEY_MASTER_TOKEN + "x", new JSONObject(MASTER_TOKEN.toJSONString()));
        jo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name());
        jo.put(KEY_KEYDATA, new JSONObject());
        KeyResponseData.create(ctx, jo);
    }
    
    @Test
    public void noScheme() throws JSONException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JSONObject jo = new JSONObject();
        jo.put(KEY_MASTER_TOKEN, new JSONObject(MASTER_TOKEN.toJSONString()));
        jo.put(KEY_SCHEME + "x", KeyExchangeScheme.ASYMMETRIC_WRAPPED.name());
        jo.put(KEY_KEYDATA, new JSONObject());
        KeyResponseData.create(ctx, jo);
    }
    
    @Test
    public void noKeydata() throws JSONException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JSONObject jo = new JSONObject();
        jo.put(KEY_MASTER_TOKEN, new JSONObject(MASTER_TOKEN.toJSONString()));
        jo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name());
        jo.put(KEY_KEYDATA + "x", new JSONObject());
        KeyResponseData.create(ctx, jo);
    }
    
    @Test
    public void invalidMasterToken() throws JSONException, MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final byte[] encryptionKey = new byte[0];
        final byte[] hmacKey = new byte[0];
        final KeyResponseData response = new SymmetricWrappedExchange.ResponseData(MASTER_TOKEN, KeyId.PSK, encryptionKey, hmacKey);

        final JSONObject jo = new JSONObject();
        jo.put(KEY_MASTER_TOKEN, new JSONObject());
        jo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name());
        jo.put(KEY_KEYDATA, response.getKeydata());
        KeyResponseData.create(ctx, jo);
    }
    
    @Test
    public void unidentifiedScheme() throws JSONException, MslException {
        thrown.expect(MslKeyExchangeException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_SCHEME);

        final JSONObject jo = new JSONObject();
        jo.put(KEY_MASTER_TOKEN, new JSONObject(MASTER_TOKEN.toJSONString()));
        jo.put(KEY_SCHEME, "x");
        jo.put(KEY_KEYDATA, new JSONObject());
        KeyResponseData.create(ctx, jo);
    }
    
    @Test
    public void keyxFactoryNotFound() throws JSONException, MslException {
        thrown.expect(MslKeyExchangeException.class);
        thrown.expectMslError(MslError.KEYX_FACTORY_NOT_FOUND);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        ctx.removeKeyExchangeFactories(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        final JSONObject jo = new JSONObject();
        jo.put(KEY_MASTER_TOKEN, new JSONObject(MASTER_TOKEN.toJSONString()));
        jo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name());
        jo.put(KEY_KEYDATA, new JSONObject());
        KeyResponseData.create(ctx, jo);
    }
    
    /** MSL context. */
    private static MslContext ctx;
}

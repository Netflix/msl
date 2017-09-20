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
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * User authentication data unit tests.
 * 
 * Successful calls to
 * {@link UserAuthenticationData#create(com.netflix.msl.util.MslContext, org.json.MslObject)}
 * covered in the individual user authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UserAuthenticationDataTest {
    /** Key user authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key user authentication data. */
    private static final String KEY_AUTHDATA = "authdata";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
    }
    
    @AfterClass
    public static void teardown() {
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void noScheme() throws MslEncoderException, MslUserAuthException, MslEncodingException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final MslObject mo = encoder.createObject();
        mo.put(KEY_SCHEME + "x", UserAuthenticationScheme.EMAIL_PASSWORD.name());
        mo.put(KEY_AUTHDATA, encoder.createObject());
        UserAuthenticationData.create(ctx, null, mo);
    }
    
    @Test
    public void noAuthdata() throws MslEncoderException, MslUserAuthException, MslEncodingException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final MslObject mo = encoder.createObject();
        mo.put(KEY_SCHEME, UserAuthenticationScheme.EMAIL_PASSWORD.name());
        mo.put(KEY_AUTHDATA + "x", encoder.createObject());
        UserAuthenticationData.create(ctx, null, mo);
    }
    
    @Test
    public void unidentifiedScheme() throws MslEncoderException, MslUserAuthException, MslEncodingException, MslCryptoException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_USERAUTH_SCHEME);

        final MslObject mo = encoder.createObject();
        mo.put(KEY_SCHEME, "x");
        mo.put(KEY_AUTHDATA, encoder.createObject());
        UserAuthenticationData.create(ctx, null, mo);
    }
    
    @Test
    public void authFactoryNotFound() throws MslEncoderException, MslUserAuthException, MslEncodingException, MslCryptoException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_FACTORY_NOT_FOUND);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        ctx.removeUserAuthenticationFactory(UserAuthenticationScheme.EMAIL_PASSWORD);
        final MslObject mo = encoder.createObject();
        mo.put(KEY_SCHEME, UserAuthenticationScheme.EMAIL_PASSWORD.name());
        mo.put(KEY_AUTHDATA, encoder.createObject());
        UserAuthenticationData.create(ctx, null, mo);
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
}

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
package com.netflix.msl.client.tests;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.concurrent.ExecutionException;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.client.common.BaseTestClass;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.client.configuration.ServerConfiguration;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.Url;
import com.netflix.msl.io.Url.Connection;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * User: skommidi
 * Date: 10/16/14
 */
public class UserIdTokenTests extends BaseTestClass {

    private static final String PATH = "/test";
    private static final int TIME_OUT = 60000; // 60 Seconds
    private static final String USER_ID = "userId";

    @BeforeClass
    public void setup() throws IOException, URISyntaxException, MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException {
        super.loadProperties();
        serverConfig = new ServerConfiguration()
                .resetDefaultConfig()
                .setHost(getRemoteEntityUrl())
                .setPath(PATH);
        serverConfig.commitToServer();

        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.SYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        super.setServerMslCryptoContext();
    }

    @AfterMethod
    public void afterTest() throws IOException {
        if(out != null) { out.close(); out = null;}
        if(in != null) { in.close(); out = null; }
        clientConfig.getMslContext().getMslStore().clearCryptoContexts();
    }

    @BeforeMethod
    public void beforeTest() throws IOException, ExecutionException, InterruptedException {
        try {
            final Url remoteEntity = clientConfig.getRemoteEntity();
            remoteEntity.setTimeout(TIME_OUT);
            final Connection connection = remoteEntity.openConnection();

            out = connection.getOutputStream();
            in = connection.getInputStream();
        } catch (final IOException e) {
            if(out != null) out.close();
            if(in != null) in.close();

            throw e;
        }
    }

    @Test(testName = "userIdtoken happy case")
    public void validUserIdToken() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = getInitialMasterToken(TIME_OUT);

        final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 20000);
        final UserIdToken userIdToken = getUserIdToken(masterToken, renewalWindow, expiration, TIME_OUT);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, null, true /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final UserIdToken newUserIdToken = message.getMessageHeader().getUserIdToken();

        validateUserIdTokenEqual(userIdToken, newUserIdToken, masterToken);
    }

    @Test(testName = "expired userIdToken with renewable flag set true, expect renewed userIdToken")
    public void expiredUserIdTokenWithRenewableTrue() throws ExecutionException, InterruptedException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = getInitialMasterToken(TIME_OUT);

        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final UserIdToken userIdToken = getUserIdToken(masterToken, renewalWindow, expiration, TIME_OUT);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, null, true /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final UserIdToken newUserIdToken = message.getMessageHeader().getUserIdToken();

        validateUserIdTokenNotEqual(userIdToken, newUserIdToken, masterToken);
    }

    @Test(testName = "expired userIdToken with renewable flag set false, expect renewed userIdToken")
    public void expiredUserIdTokenWithRenewableFalse() throws ExecutionException, InterruptedException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = getInitialMasterToken(TIME_OUT);

        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final UserIdToken userIdToken = getUserIdToken(masterToken, renewalWindow, expiration, TIME_OUT);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, null, false /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final UserIdToken newUserIdToken = message.getMessageHeader().getUserIdToken();

        validateUserIdTokenNotEqual(userIdToken, newUserIdToken, masterToken);
    }

    @Test(testName = "renewable userIdToken with renewable flag set true, expect renewed userIdToken")
    public void renewableUserIdTokenWithRenewableTrue() throws ExecutionException, InterruptedException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = getInitialMasterToken(TIME_OUT);

        final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 10000);
        final UserIdToken userIdToken = getUserIdToken(masterToken, renewalWindow, expiration, TIME_OUT);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, null, true /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final UserIdToken newUserIdToken = message.getMessageHeader().getUserIdToken();

        validateUserIdTokenNotEqual(userIdToken, newUserIdToken, masterToken);
    }

    @Test(testName = "renewable userIdToken with renewable flag set false, expect renewed userIdToken")
    public void renewableUserIdTokenWithRenewableFalse() throws ExecutionException, InterruptedException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = getInitialMasterToken(TIME_OUT);

        final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 10000);
        final UserIdToken userIdToken = getUserIdToken(masterToken, renewalWindow, expiration, TIME_OUT);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, null, false /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final UserIdToken newUserIdToken = message.getMessageHeader().getUserIdToken();

        validateUserIdTokenEqual(userIdToken, newUserIdToken, masterToken);
    }

    private void validateUserIdTokenEqual(final UserIdToken userIdToken, final UserIdToken newUserIdToken, final MasterToken masterToken) {
        final Date now = new Date();

        assertEquals(newUserIdToken.getSerialNumber(), userIdToken.getSerialNumber());
        assertEquals(newUserIdToken.getMasterTokenSerialNumber(), userIdToken.getMasterTokenSerialNumber());
        assertTrue(newUserIdToken.getExpiration().after(newUserIdToken.getRenewalWindow()));
        assertEquals(newUserIdToken.getRenewalWindow(), userIdToken.getRenewalWindow());
        assertEquals(newUserIdToken.getExpiration(), userIdToken.getExpiration());
        assertTrue(newUserIdToken.isBoundTo(masterToken));
        assertFalse(newUserIdToken.isVerified());
        assertFalse(newUserIdToken.isDecrypted());
        assertTrue(newUserIdToken.isExpired(now) == userIdToken.isExpired(now));
        assertTrue(newUserIdToken.isRenewable(now) == userIdToken.isRenewable(now));
    }

    private void validateUserIdTokenNotEqual(final UserIdToken userIdToken, final UserIdToken newUserIdToken, final MasterToken masterToken) {
        final Date now = new Date();

        assertEquals(newUserIdToken.getSerialNumber(), userIdToken.getSerialNumber());
        assertEquals(newUserIdToken.getMasterTokenSerialNumber(), userIdToken.getMasterTokenSerialNumber());
        assertTrue(newUserIdToken.getExpiration().after(newUserIdToken.getRenewalWindow()));
        assertTrue(newUserIdToken.getRenewalWindow().after(userIdToken.getRenewalWindow()));
        assertTrue(newUserIdToken.getExpiration().compareTo(userIdToken.getExpiration()) > 0);
        assertTrue(newUserIdToken.isBoundTo(masterToken));
        assertFalse(newUserIdToken.isVerified());
        assertFalse(newUserIdToken.isDecrypted());
        assertFalse(newUserIdToken.isExpired(now));
        assertFalse(newUserIdToken.isRenewable(now));
        //User is not able to decrypt the customer information
    }


    private ServerConfiguration serverConfig;
    private final int numThreads = 0;
    private OutputStream out;
    private InputStream in;
}

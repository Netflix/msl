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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
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
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslStore;

/**
 * User: skommidi
 * Date: 10/17/14
 */
public class ServiceTokenTests extends BaseTestClass {

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
        final MslStore store = clientConfig.getMslContext().getMslStore();
        store.clearCryptoContexts();
        store.clearServiceTokens();
        store.clearUserIdTokens();
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

    @DataProvider(name = "ServiceTokenTypes")
    public Object[][] testDataServiceTokenTypes() {
        return new Object[][] {
                {ServiceTokenType.BOTH, true},
                {ServiceTokenType.MASTER_BOUND, true},
                {ServiceTokenType.BOTH, false},
                {ServiceTokenType.MASTER_BOUND, false},
        };
    }



    @Test(groups = "UnboundServiceTokenTests")
    public void unboundServiceTokenWithData() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = getMasterToken(new Date(System.currentTimeMillis() + 10000) /*renewableWindow*/,
                new Date(System.currentTimeMillis() + 20000) /*expiration*/, TIME_OUT, 0  /*sequenceNumberOffset*/);

        // Create an expired userId token
        final UserIdToken userIdToken = getUserIdToken(masterToken, new Date(System.currentTimeMillis() + 10000) /*renewableWindow*/,
                new Date(System.currentTimeMillis() + 20000) /*expiration*/, TIME_OUT);

        final Set<ServiceToken> serviceTokens = getServiceToken(masterToken, userIdToken, ServiceTokenType.NONE, true);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, serviceTokens, false /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final Set<ServiceToken> returnedServiceTokens = message.getMessageHeader().getServiceTokens();

        assertEquals(returnedServiceTokens.size(), 1, "Numner of returned service tokens != sent service tokens");
        assertEquals(serviceTokens, returnedServiceTokens, "Retured service tokens are not the same as the sent");
    }

    @Test(dependsOnMethods = "unboundServiceTokenWithData", groups = "UnboundServiceTokenTests")
    public void testUnboundServiceTokenWithoutData() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = getMasterToken(new Date(System.currentTimeMillis() + 10000) /*renewableWindow*/,
                new Date(System.currentTimeMillis() + 20000) /*expiration*/, TIME_OUT, 0  /*sequenceNumberOffset*/);

        // Create an expired userId token
        final UserIdToken userIdToken = getUserIdToken(masterToken, new Date(System.currentTimeMillis() + 10000) /*renewableWindow*/,
                new Date(System.currentTimeMillis() + 20000) /*expiration*/, TIME_OUT);

        final Set<ServiceToken> serviceTokens = getServiceToken(masterToken, userIdToken, ServiceTokenType.NONE, false);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, serviceTokens, false /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final Set<ServiceToken> returnedServiceTokens = message.getMessageHeader().getServiceTokens();

        assertEquals(returnedServiceTokens.size(), 1, "Numner of returned service tokens != sent service tokens");
        assertEquals(serviceTokens, returnedServiceTokens, "Retured service tokens are not the same as the sent");
    }

    @Test(testName = "service token test", dataProvider = "ServiceTokenTypes", dependsOnGroups = "UnboundServiceTokenTests")
    public void boundServiceToken(final ServiceTokenType serviceTokenType, final boolean withData) throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {

        final MasterToken masterToken = getMasterToken(new Date(System.currentTimeMillis() + 10000) /*renewableWindow*/,
                new Date(System.currentTimeMillis() + 20000) /*expiration*/, TIME_OUT, 0  /*sequenceNumberOffset*/);

        // Create an expired userId token
        final UserIdToken userIdToken = getUserIdToken(masterToken, new Date(System.currentTimeMillis() + 10000) /*renewableWindow*/,
                new Date(System.currentTimeMillis() + 20000) /*expiration*/, TIME_OUT);

        final Set<ServiceToken> serviceTokens = getServiceToken(masterToken, userIdToken, serviceTokenType, withData);

        final MessageInputStream message = sendReceive(out, in, masterToken, userIdToken, serviceTokens, false /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final Set<ServiceToken> returnedServiceTokens = message.getMessageHeader().getServiceTokens();

        assertEquals(returnedServiceTokens.size(), 1, "Numner of returned service tokens != sent service tokens");
        assertEquals(serviceTokens, returnedServiceTokens, "Retured service tokens are not the same as the sent");
    }

    private ServerConfiguration serverConfig;
    private final int numThreads = 0;
    private OutputStream out;
    private InputStream in;
}

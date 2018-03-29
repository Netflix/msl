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

import com.netflix.msl.MslConstants;
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
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * User: skommidi
 * Date: 10/13/14
 */
public class MasterTokenTests extends BaseTestClass {

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



    @Test(testName = "mastertoken happy case")
    public void validMasterToken() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 20000);
        final MasterToken masterToken = getMasterToken(renewalWindow, expiration, TIME_OUT, 0 /*sequenceNumberOffset*/);

        final MessageInputStream message = sendReceive(out, in, masterToken, null, null, true /*isRenewable*/, false /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final MasterToken newMasterToken = message.getMessageHeader().getMasterToken();

        validateMasterTokenEquals(masterToken, newMasterToken);
    }

    @Test(testName = "expired master token, with renewable set true, expect renewed master token")
    public void expiredMasterTokenRenewable() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = getMasterToken(renewalWindow, expiration, TIME_OUT, 0 /*sequenceNumberOffset*/);

        final MessageInputStream message = sendReceive(out, in, masterToken, null, null, true /*isRenewable*/, true /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final MasterToken newMasterToken = message.getMessageHeader().getKeyResponseData().getMasterToken();

        validateMasterTokenNotEquals(masterToken, newMasterToken);
    }

    @Test(testName = "expired master token, with renewable flag set false")
    public void expiredMasterTokenNonRenewable() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = getMasterToken(renewalWindow, expiration, TIME_OUT, 0 /*sequenceNumberOffset*/);

        final MessageInputStream message = sendReceive(out, in, masterToken, null, null, false /*isRenewable*/, true /*addKeyRequestData*/);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.EXPIRED);
    }

    @Test(testName = "renewable master token, with sequence number out of range")
    public void renewableMasterTokenSequenceNumOutOfRangeError() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 10000);
        final MasterToken masterToken = getMasterToken(renewalWindow, expiration, TIME_OUT, 33 /*sequenceNumberOffset*/);

        final MessageInputStream message = sendReceive(out, in, masterToken, null, null, true /*isRenewable*/, true /*addKeyRequestData*/);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.ENTITY_REAUTH);
    }

    @Test(testName = "renewable master token")
    public void renewableMasterTokenWithRenewableTrue() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 10000);
        final MasterToken masterToken = getMasterToken(renewalWindow, expiration, TIME_OUT, 0 /*sequenceNumberOffset*/);

        final MessageInputStream message = sendReceive(out, in, masterToken, null, null, true /*isRenewable*/, true /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final MasterToken newMasterToken = message.getMessageHeader().getKeyResponseData().getMasterToken();

        validateMasterTokenNotEquals(masterToken, newMasterToken);
    }

    @Test(testName = "renewable master token")
    public void renewableMasterTokenWithRenewableFalse() throws InterruptedException, ExecutionException, MslException, IOException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 10000);
        final MasterToken masterToken = getMasterToken(renewalWindow, expiration, TIME_OUT, 0 /*sequenceNumberOffset*/);

        final MessageInputStream message = sendReceive(out, in, masterToken, null, null, false /*isRenewable*/, true /*addKeyRequestData*/);

        thenThe(message)
                .shouldHave().validBuffer();

        final MasterToken newMasterToken = message.getMessageHeader().getMasterToken();

        validateMasterTokenEquals(masterToken, newMasterToken);
    }

    //@Test(testName = "replayed master token")
    public void testReplayedMasterTokenWithoutKeyRequestData() throws InterruptedException, ExecutionException, MslException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, URISyntaxException, MslEncoderException {
        clientConfig.setMessageNonReplayable(true)
                .commitConfiguration();

        final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);   // Renewable in the past
        final Date expiration = new Date(System.currentTimeMillis() + 20000);   // Expiration in the past
        final MasterToken masterToken = getMasterToken(renewalWindow, expiration, TIME_OUT, 0 /*sequenceNumberOffset*/);

        final MessageInputStream message = sendReceive(out, in, masterToken, null, null, true /*isRenewable*/, false /*addKeyRequestData*/);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.REPLAYED);

    }


    private void validateMasterTokenNotEquals(final MasterToken masterToken, final MasterToken newMasterToken) {
        assertTrue(newMasterToken.isNewerThan(masterToken), "New masterToken is not newer than old masterToken.");
        assertTrue(newMasterToken.getSequenceNumber() > masterToken.getSequenceNumber(), "New sequence number is not greater than old sequence number.");
        assertTrue(newMasterToken.getRenewalWindow().after(new Date(System.currentTimeMillis())), "New renewal window timestamp is not after current timestamp");
        assertTrue(newMasterToken.getExpiration().after(new Date(System.currentTimeMillis())), "New expiration timestamp is not after current timestamp");
        assertTrue(newMasterToken.getExpiration().after(newMasterToken.getRenewalWindow()), "New expiration timestamp is not after new renewal window timestamp");
    }


    private void validateMasterTokenEquals(final MasterToken masterToken, final MasterToken newMasterToken) {
        assertTrue(newMasterToken.getSequenceNumber() == masterToken.getSequenceNumber(), "New sequence number is expected to be equal to old sequence number.");
        assertTrue(newMasterToken.getRenewalWindow().equals(masterToken.getRenewalWindow()), "New renewal window timestamp is expected to be equal to old renewal window timestamp");
        assertTrue(newMasterToken.getExpiration().equals(masterToken.getExpiration()), "New expiration timestamp is expected to be equal to old expiration timestamp");
        assertTrue(newMasterToken.getExpiration().after(newMasterToken.getRenewalWindow()), "New expiration timestamp is not after new renewal window timestamp");
    }

    private final int numThreads = 0;
    private ServerConfiguration serverConfig;
    private OutputStream out;
    private InputStream in;
}

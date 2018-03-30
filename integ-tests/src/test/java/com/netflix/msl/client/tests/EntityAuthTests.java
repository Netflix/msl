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
package com.netflix.msl.client.tests;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.client.common.BaseTestClass;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.client.configuration.ServerConfiguration;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class EntityAuthTests extends BaseTestClass {
    private final int numThreads = 0;
    private ServerConfiguration serverConfig = null;
    private static final int TIME_OUT = 60000; //60 seconds
    private static final String PATH = "/test";
    private static final String USER_ID = "userId";
    private static final String INVALID_ENTITY_IDENTITY = "invalidEntityIdentity";

    @BeforeMethod
    public void setup() throws IOException, URISyntaxException {
        if (serverConfig == null) {
            super.loadProperties();
            serverConfig = new ServerConfiguration()
                    .setHost(getRemoteEntityUrl())
                    .setPath(PATH);
            serverConfig.commitToServer();
        }
    }
    
    @Test(testName = "Correct Remote Entity Identity")
    public void correctRemoteEntityIdentity() throws MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, URISyntaxException, IOException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
            .setScheme("http")
            .setHost(getRemoteEntityUrl())
            .setPath(PATH)
            .setNumThreads(numThreads)
            .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
            .setIsPeerToPeer(false)
            // FIXME There should be a better way to know the remote entity identity for this test.
            .setRemoteEntityIdentity("MOCKUNAUTH-ESN")
            .setUserId(USER_ID)
            .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
            .setKeyRequestData(KeyExchangeScheme.SYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthPSKMsg()
                .shouldHave().validBuffer();

        message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validateSecondMsg()
                .shouldHave().validBuffer();
    }
    
    @Test(testName = "Incorrect Remote Entity Identity")
    public void incorrectRemoteEntityIdentity() throws MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, URISyntaxException, IOException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
            .setScheme("http")
            .setHost(getRemoteEntityUrl())
            .setPath(PATH)
            .setNumThreads(numThreads)
            .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
            .setIsPeerToPeer(false)
            .setRemoteEntityIdentity(INVALID_ENTITY_IDENTITY)
            .setUserId(USER_ID)
            .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
            .setKeyRequestData(KeyExchangeScheme.SYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();
        
        try {
            sendReceive(TIME_OUT);
        } catch (final ExecutionException e) {
            final Throwable cause = e.getCause();
            assertTrue(cause instanceof MslException);
            final MslException me = (MslException)cause;
            assertEquals(MslError.MESSAGE_SENDER_MISMATCH, me.getError());
        }
    }

    /**
     *
     *
     * @throws MslEncodingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws ExecutionException
     * @throws InterruptedException
     * @throws IOException
     * @throws MslKeyExchangeException
     */
    @Test(testName = "Valid Entity Auth - PSK")
    public void validEntityAuthPSK() throws MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslCryptoException, URISyntaxException, ExecutionException, InterruptedException, IOException, MslKeyExchangeException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.SYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthPSKMsg()
                .shouldHave().validBuffer();

        message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validateSecondMsg()
                .shouldHave().validBuffer();

    }

    /**
     *
     *
     * @throws MslEncodingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws ExecutionException
     * @throws InterruptedException
     * @throws IOException
     * @throws MslKeyExchangeException
     */
    @Test(testName = "Invalid Entity Auth - PSK")
    public void invalidEntityAuthPSK() throws MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslCryptoException, URISyntaxException, ExecutionException, InterruptedException, IOException, MslKeyExchangeException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setInvalidEntityAuthData()
                .setMaxEntityAuthRetryCount(4)
                .resetCurrentEntityAuthRetryCount()
                .setIsPeerToPeer(false)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.SYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.FAIL);

    }

    /**
     *
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @Test(testName = "Valid Entity Auth - RSA")
    public void validEntityAuthRSA() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.RSA)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthRSAMsg()
                .shouldHave().validBuffer();

        message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validateSecondMsg()
                .shouldHave().validBuffer();

    }

    /**
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @Test(testName = "Invalid Entity Auth - RSA")
    public void invalidEntityAuthRSA() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.RSA)
                .setInvalidEntityAuthData()
                .setMaxEntityAuthRetryCount(5)
                .resetCurrentEntityAuthRetryCount()
                .setIsPeerToPeer(false)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.ENTITYDATA_REAUTH);

    }

    /**
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @Test(testName = "Entity Auth RSA, Bad -> Good")
    public void invalidEntityAuthRSABadToGood() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.RSA)
                .setInvalidEntityAuthData()
                //Retry Count after which it will send good entity auth data.
                .setMaxEntityAuthRetryCount(2)
                .resetCurrentEntityAuthRetryCount()
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthRSAMsg()
                .shouldHave().validBuffer();
    }

    /**
     *
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @Test(testName = "Valid Entity Auth - ECC")
    public void validEntityAuthECC() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.ECC)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthECCMsg()
                .shouldHave().validBuffer();

        message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validateSecondMsg()
                .shouldHave().validBuffer();

    }

    /**
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @Test(testName = "Invalid Entity Auth - ECC")
    public void invalidEntityAuthECC() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.ECC)
                .setInvalidEntityAuthData()
                .setMaxEntityAuthRetryCount(5)
                .resetCurrentEntityAuthRetryCount()
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.ENTITYDATA_REAUTH);

    }

    /**
     *
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @Test(testName = "Valid Entity Auth - X509")
    public void validEntityAuthX509() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.X509)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.DIFFIE_HELLMAN);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthX509Msg()
                .shouldHave().validBuffer();

        message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validateSecondMsg()
                .shouldHave().validBuffer();

    }


    /**
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    //@Test(testName = "Invalid Entity Auth - X509")
    public void invalidEntityAuthX509() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.X509)
                .setInvalidEntityAuthData()
                .setMaxEntityAuthRetryCount(5)
                .resetCurrentEntityAuthRetryCount()
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.ENTITYDATA_REAUTH);

    }


    /**
     *
     *
     * @throws InvalidAlgorithmParameterException
     * @throws MslEncodingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws MslCryptoException
     * @throws URISyntaxException
     * @throws MslKeyExchangeException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @Test(testName = "Valid Entity Auth - NONE")
    public void validEntityAuthNONE() throws InvalidAlgorithmParameterException, MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.NONE)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthNONEMsg()
                .shouldHave().validBuffer();

        message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validateSecondMsg()
                .shouldHave().validBuffer();

    }

    @Test(testName = "clear key request data from request")
    public void keyRequestDataErr() throws ExecutionException, InterruptedException, IOException, MslEncodingException, NoSuchAlgorithmException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .clearKeyRequestData();
        clientConfig.commitConfiguration();

        serverConfig.isMessageEncrypted(true)
                .commitToServer();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.KEYX_REQUIRED);


    }

}

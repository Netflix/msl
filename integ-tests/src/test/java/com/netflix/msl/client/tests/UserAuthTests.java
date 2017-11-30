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

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.client.common.BaseTestClass;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.client.configuration.ServerConfiguration;
import com.netflix.msl.client.configuration.msg.InvalidUserAuthScheme;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * User: skommidi
 * Date: 8/28/14
 */
public class UserAuthTests extends BaseTestClass {
    private static final int TIME_OUT = 60000; // 60 Seconds
    private final int numThreads = 0;
    private ServerConfiguration serverConfig;
    private static final String PATH = "/test";
    private static final String USER_ID = "userId";

    @BeforeClass
    public void setup() throws IOException, URISyntaxException {
        super.loadProperties();
        serverConfig = new ServerConfiguration()
                .setHost(getRemoteEntityUrl())
                .setPath(PATH);
        serverConfig.commitToServer();
    }

    @Test(testName = "Valid User Auth - EMAIL_PASSWORD")
    public void validUserAuthEmailPassword() throws MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.NONE)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.DIFFIE_HELLMAN);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthNONEMsg()
                .shouldHave().validBuffer();
    }

    @Test(testName = "Invalid Email User Auth - EMAIL_PASSWORD")
    public void invalidEmailUserAuthEmailPassword() throws MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setInvalidUserAuthData(InvalidUserAuthScheme.INVALID_EMAIL)
                .setMaxUserAuthRetryCount(5)
                .resetCurrentUserAuthRetryCount()
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.USERDATA_REAUTH);
    }

    @Test(testName = "Invalid Password User Auth - EMAIL_PASSWORD")
    public void invalidPasswordUserAuthEmailPassword() throws MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setInvalidUserAuthData(InvalidUserAuthScheme.INVALID_PASSWORD)
                .setMaxUserAuthRetryCount(5)
                .resetCurrentUserAuthRetryCount()
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.USERDATA_REAUTH);
    }

    @Test(testName = "Empty Email User Auth - EMAIL_PASSWORD")
    public void emptyEmailUserAuthEmailPassword() throws MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setInvalidUserAuthData(InvalidUserAuthScheme.EMPTY_EMAIL)
                .setMaxUserAuthRetryCount(5)
                .resetCurrentUserAuthRetryCount()
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.USERDATA_REAUTH);
    }

    @Test(testName = "Empty Password User Auth - EMAIL_PASSWORD")
    public void emptyPasswordUserAuthEmailPassword() throws MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.PSK)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setInvalidUserAuthData(InvalidUserAuthScheme.EMPTY_PASSWORD)
                .setMaxUserAuthRetryCount(5)
                .resetCurrentUserAuthRetryCount()
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.USERDATA_REAUTH);
    }

    @Test(testName = "Null User Auth - EMAIL_PASSWORD")
    public void nullUserAuthEmailPassword() throws MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.NONE)
                .setIsPeerToPeer(false)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.DIFFIE_HELLMAN)
                .setNullUserAuthData();
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthNONEMsg(clientConfig.isSetNullUserAuthData())
                .shouldHave().validBuffer();

        message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validateSecondMsg(clientConfig.isSetNullUserAuthData())
                .shouldHave().validBuffer();
    }

    @Test
    public void invalidUserAuthEmailPasswordBadToGood() throws MslEncodingException, NoSuchAlgorithmException, IOException, MslCryptoException, URISyntaxException, InvalidAlgorithmParameterException, MslKeyExchangeException, ExecutionException, InterruptedException {
        clientConfig = new ClientConfiguration()
                .setScheme("http")
                .setHost(getRemoteEntityUrl())
                .setPath(PATH)
                .setNumThreads(numThreads)
                .setEntityAuthenticationScheme(EntityAuthenticationScheme.X509)
                .setUserId(USER_ID)
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setInvalidUserAuthData(InvalidUserAuthScheme.INVALID_EMAIL)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED)
                .setMaxUserAuthRetryCount(2)
                .resetCurrentUserAuthRetryCount();
        clientConfig.commitConfiguration();

        final MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthX509Msg()
                .shouldHave().validBuffer();
    }
}

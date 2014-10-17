package com.netflix.msl.client.tests;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.client.common.BaseTestClass;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.client.configuration.ServerConfiguration;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class EntityAuthTests extends BaseTestClass {
    private int numThreads = 0;
    private ServerConfiguration serverConfig;
    private static final int TIME_OUT = 60000; //60 seconds
    private static final String PATH = "/test";

    @BeforeClass
    public void setup() throws IOException, URISyntaxException {
        super.loadProperties();
        serverConfig = new ServerConfiguration()
                .setHost(getRemoteEntityUrl())
                .setPath(PATH);
        serverConfig.commitToServer();
    }

    /**
     *
     *
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.security.NoSuchAlgorithmException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws java.util.concurrent.ExecutionException
     * @throws InterruptedException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslKeyExchangeException
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
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.security.NoSuchAlgorithmException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws java.util.concurrent.ExecutionException
     * @throws InterruptedException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslKeyExchangeException
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

        MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.FAIL);

    }

    /**
     *
     *
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws com.netflix.msl.MslKeyExchangeException
     * @throws java.util.concurrent.ExecutionException
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
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws com.netflix.msl.MslKeyExchangeException
     * @throws java.util.concurrent.ExecutionException
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

        MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.ENTITYDATA_REAUTH);

    }

    /**
     *
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws com.netflix.msl.MslKeyExchangeException
     * @throws java.util.concurrent.ExecutionException
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
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenThe(message)
                .shouldBe().validFirstEntityAuthRSAMsg()
                .shouldHave().validBuffer();
    }



    /**
     *
     *
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws com.netflix.msl.MslKeyExchangeException
     * @throws java.util.concurrent.ExecutionException
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
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws com.netflix.msl.MslKeyExchangeException
     * @throws java.util.concurrent.ExecutionException
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
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        clientConfig.commitConfiguration();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.ENTITYDATA_REAUTH);

    }


    /**
     *
     *
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws com.netflix.msl.MslEncodingException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     * @throws com.netflix.msl.MslCryptoException
     * @throws java.net.URISyntaxException
     * @throws com.netflix.msl.MslKeyExchangeException
     * @throws java.util.concurrent.ExecutionException
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
                .setUserAuthenticationScheme(UserAuthenticationScheme.EMAIL_PASSWORD)
                .clearKeyRequestData();
        clientConfig.commitConfiguration();

        serverConfig.isMessageEncrypted(true)
                .commitToServer();

        MessageInputStream message = sendReceive(TIME_OUT);

        thenTheErr(message)
                .shouldBe().validateHdr()
                .shouldHave().validateErrCode(MslConstants.ResponseCode.KEYX_REQUIRED);


    }

}

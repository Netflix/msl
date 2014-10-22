package com.netflix.msl.client.configuration;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.client.configuration.entityauth.TestPresharedAuthenticationFactory;
import com.netflix.msl.client.configuration.entityauth.TestRsaAuthenticationFactory;
import com.netflix.msl.client.configuration.entityauth.TestX509AuthenticationFactory;
import com.netflix.msl.client.configuration.msg.ClientMessageContext;
import com.netflix.msl.client.configuration.msg.InvalidUserAuthScheme;
import com.netflix.msl.client.configuration.util.ClientMslContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.entityauth.X509AuthenticationData;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MockAuthenticationUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class ClientConfiguration {

    public static final String input = "Hello";
    public static final String serverError = "Error";

    private MslControl mslControl;
    private ClientMslContext mslContext;
    private ClientMessageContext messageContext;
    private URL remoteEntity;
    private String scheme = "http";
    private String remoteHost = "localhost";
    private String path = "";
    private static final String USER_ID = "userid";
    private boolean isPeerToPeer = false;
    private EntityAuthenticationScheme entityAuthenticationScheme = EntityAuthenticationScheme.PSK;
    private UserAuthenticationScheme userAuthenticationScheme = UserAuthenticationScheme.EMAIL_PASSWORD;
    private KeyExchangeScheme keyExchangeScheme = KeyExchangeScheme.SYMMETRIC_WRAPPED;
    private boolean nonReplayable = false;
    private int entityAuthRetryCount = 0;
    private boolean resetEntityAuthRetryCount = false;
    private int userAuthRetryCount = 0;
    private boolean resetUserAuthRetryCount = false;
    private InvalidUserAuthScheme setInvalidUserAuthData = null;
    private boolean setInvalidEntityAuthData = false;
    private boolean isNullCryptoContext = false;
    private boolean isMessageEncrypted = true;
    private boolean setNullUserAuthData = false;
    private boolean isIntegrityProtected = true;
    private boolean clearKeyRequestData = false;

    public ClientConfiguration setEntityAuthenticationScheme(EntityAuthenticationScheme scheme) {
        entityAuthenticationScheme = scheme;
        return this;
    }



    public ClientConfiguration setUserAuthenticationScheme(UserAuthenticationScheme scheme) {
        userAuthenticationScheme = scheme;
        return this;
    }


    public ClientConfiguration setIsMessageEncrypted(boolean messageEncrypted) {
        this.isMessageEncrypted = messageEncrypted;
        return this;
    }


    public ClientConfiguration setIsIntegrityProtected(boolean integrityProtected) {
        this.isIntegrityProtected = integrityProtected;
        return this;
    }

    public ClientConfiguration setKeyRequestData(KeyExchangeScheme scheme) {
        keyExchangeScheme = scheme;
        return this;
    }

    /*
     * Test utility function to get different corrupted entityAuthSchemes
     */
    public ClientConfiguration setInvalidEntityAuthData() {
        setInvalidEntityAuthData = true;
        return this;
    }

    public ClientConfiguration setInvalidUserAuthData(InvalidUserAuthScheme scheme) {
        setInvalidUserAuthData = scheme;
        return this;
    }

    public ClientConfiguration setMaxEntityAuthRetryCount(int value) {
        this.entityAuthRetryCount = value;
        return this;
    }


    public ClientConfiguration resetCurrentEntityAuthRetryCount() {
        this.resetEntityAuthRetryCount = true;
        return this;
    }

    public ClientConfiguration setMaxUserAuthRetryCount(int value) {
        this.userAuthRetryCount = value;
        return this;
    }

    public ClientConfiguration resetCurrentUserAuthRetryCount() {
        this.resetUserAuthRetryCount = true;
        return this;
    }

    public ClientConfiguration setScheme(String scheme) {
        this.scheme = scheme;
        return this;
    }

    public ClientConfiguration setHost(String remoteHost) {
        this.remoteHost = remoteHost;
        return this;
    }

    public ClientConfiguration setPath(String path) {
        this.path = path;
        return this;
    }

    public ClientConfiguration setIsPeerToPeer(boolean isPeerToPeer) {
        this.isPeerToPeer = isPeerToPeer;
        return this;
    }

    public ClientConfiguration setMessageNonReplayable(boolean nonReplayable) {
        this.nonReplayable = nonReplayable;
        return this;
    }

    public ClientConfiguration setIsNullCryptoContext(boolean isNullCryptoContext) {
        this.isNullCryptoContext = isNullCryptoContext;
        return this;
    }

    public void commitConfiguration() throws URISyntaxException, IOException, MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException {
        remoteEntity = new URL(scheme + "://" + remoteHost + path);

        /** create msl context and configure */
        mslContext = new ClientMslContext(entityAuthenticationScheme, isPeerToPeer, isNullCryptoContext);
        //Setting the maxRetryCount for mslContext
        mslContext.setMaxRetryCount(this.entityAuthRetryCount);
        if(this.resetEntityAuthRetryCount) {
            mslContext.resetCurrentRetryCount();
        }
        if(setInvalidEntityAuthData) {
            mslContext.removeEntityAuthenticationFactory(entityAuthenticationScheme);

            final AuthenticationUtils authutils = new MockAuthenticationUtils();
            EntityAuthenticationFactory entityAuthenticationFactory;

            if (EntityAuthenticationScheme.PSK.equals(entityAuthenticationScheme))
                entityAuthenticationFactory = new TestPresharedAuthenticationFactory();
            else if (EntityAuthenticationScheme.X509.equals(entityAuthenticationScheme))
                entityAuthenticationFactory = new TestX509AuthenticationFactory();
            else if (EntityAuthenticationScheme.RSA.equals(entityAuthenticationScheme))
                entityAuthenticationFactory = new TestRsaAuthenticationFactory();
            else if (EntityAuthenticationScheme.NONE.equals(entityAuthenticationScheme))
                entityAuthenticationFactory = new UnauthenticatedAuthenticationFactory(authutils);
            else
                throw new IllegalArgumentException("Unsupported authentication type: " + entityAuthenticationScheme.name());

            mslContext.addEntityAuthenticationFactory(entityAuthenticationFactory);

            EntityAuthenticationData entityAuthenticationData;

            if (EntityAuthenticationScheme.PSK.equals(entityAuthenticationScheme))
                entityAuthenticationData = new PresharedAuthenticationData(TestPresharedAuthenticationFactory.PSK_ESN);
            else if (EntityAuthenticationScheme.X509.equals(entityAuthenticationScheme))
                entityAuthenticationData = new X509AuthenticationData(TestX509AuthenticationFactory.X509_CERT);
            else if (EntityAuthenticationScheme.RSA.equals(entityAuthenticationScheme))
                entityAuthenticationData = new RsaAuthenticationData(TestRsaAuthenticationFactory.RSA_ESN, TestRsaAuthenticationFactory.RSA_PUBKEY_ID);
            else if (EntityAuthenticationScheme.NONE.equals(entityAuthenticationScheme))
                entityAuthenticationData = new UnauthenticatedAuthenticationData("identity-test");
            else
                throw new IllegalArgumentException("Unsupported authentication type: " + entityAuthenticationScheme.name());


            mslContext.setEntityAuthenticationData(entityAuthenticationData);
        }

        /** create message context and configure */
        messageContext = new ClientMessageContext(mslContext, USER_ID, userAuthenticationScheme, isMessageEncrypted, isIntegrityProtected);
        messageContext.resetKeyRequestData(keyExchangeScheme);
        if(this.clearKeyRequestData) {
            messageContext.clearKeyRequestData();
        }
        messageContext.setBuffer(input.getBytes());
        messageContext.setNonReplayable(nonReplayable);
        //Setting the maxRetryCount for msgContext
        messageContext.setMaxRetryCount(this.userAuthRetryCount);
        if(this.resetUserAuthRetryCount) {
            messageContext.resetCurrentRetryCount();
        }

        if(setNullUserAuthData) {
            messageContext.setUserAuthData(null);
        }

        if(setInvalidUserAuthData != null) {
            UserAuthenticationData userAuthenticationData = null;

            if(UserAuthenticationScheme.EMAIL_PASSWORD.equals(userAuthenticationScheme)) {
                switch (setInvalidUserAuthData) {
                    case INVALID_EMAIL:
                        userAuthenticationData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "Test", MockEmailPasswordAuthenticationFactory.PASSWORD);
                        break;
                    case INVALID_PASSWORD:
                        userAuthenticationData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "Test");
                        break;
                    case EMPTY_EMAIL:
                        userAuthenticationData = new EmailPasswordAuthenticationData("", MockEmailPasswordAuthenticationFactory.PASSWORD);
                        break;
                    case EMPTY_PASSWORD:
                        userAuthenticationData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, "");
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported user auth error type ");
                }
            }

            messageContext.setUserAuthData(userAuthenticationData);
        }
    }

    public ClientConfiguration setNumThreads(int numThreads) {
        mslControl = new MslControl(numThreads);
        //mslControl.setFilterFactory(new TestConsoleFilterStreamFactory());
        return this;
    }

    public MslControl getMslControl() {
        return mslControl;
    }

    public ClientMslContext getMslContext() {
        return mslContext;
    }

    public ClientMessageContext getMessageContext() {
        return messageContext;
    }

    public URL getRemoteEntity() {
        return remoteEntity;
    }

    public ClientConfiguration setNullUserAuthData() {
        this.setNullUserAuthData = true;
        return this;
    }

    public boolean isSetNullUserAuthData() {
        return setNullUserAuthData;
    }

    public ClientConfiguration clearKeyRequestData() {
        this.clearKeyRequestData = true;
        return this;
    }


}

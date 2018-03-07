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
package com.netflix.msl.client.configuration.msg;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.MockDiffieHellmanParameters;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MockMessageContext;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslContext;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class ClientMessageContext extends MockMessageContext {
    private final UserAuthenticationScheme schemeUsed;
    private int currentRetryCount;
    private byte[] buffer;
    private int maxRetryCount;
    private static final String RSA_KEYPAIR_ID = "rsaKeypairId";

    /**
     * Create a new test message context.
     * <p/>
     * The message will not be encrypted or non-replayable.
     *
     *
     *
     * @param ctx    MSL context.
     * @param userId user ID.
     * @param scheme user authentication scheme.
     * @param isMessageEncrypted
     * @param isIntegrityProtected
     * @throws NoSuchAlgorithmException
     *                         if a key generation algorithm is not
     *                         found.
     * @throws InvalidAlgorithmParameterException
     *                         if key generation parameters
     *                         are invalid.
     * @throws MslCryptoException
     *                         if the service token crypto context keys are
     *                         the wrong length.
     * @throws MslKeyExchangeException
     *                         if there is an error accessing Diffie-
     *                         Hellman parameters.
     */
    public ClientMessageContext(final MslContext ctx, final String userId, final UserAuthenticationScheme scheme, final boolean isMessageEncrypted, final boolean isIntegrityProtected) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslCryptoException, MslKeyExchangeException {
        super(ctx, userId, scheme);
        super.setEncrypted(isMessageEncrypted);
        super.setIntegrityProtected(isIntegrityProtected);
        schemeUsed = scheme;
        maxRetryCount = 0;
        currentRetryCount = 0;
    }

    public void setBuffer(final byte[] dataToWrite) {
        buffer = dataToWrite;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MockMessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.write(buffer);
        output.close();
    }

    public void setMaxRetryCount(final int maxRetryCount) {
        this.maxRetryCount = maxRetryCount;
    }

    public void resetCurrentRetryCount() {
        currentRetryCount = 0;
    }

    /*
    public void setInvalidUserAuthData(InvalidUserAuthScheme tags) {
        final UserAuthenticationData userAuthData;
        switch (tags) {
            case invalidEmail:
                //Invalid email
                userAuthData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "test", MockEmailPasswordAuthenticationFactory.PASSWORD);
                break;
            case invalidPasswd:
                //Invalid passwd
                userAuthData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "test");
                break;
            case emptyStrEmail:
                //Empty str email
                userAuthData = new EmailPasswordAuthenticationData("", MockEmailPasswordAuthenticationFactory.PASSWORD);
                break;
            case emptyStrPasswd:
                //Empty str passwd
                userAuthData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, "");
                break;
            default:
                throw new IllegalArgumentException("Unsupported user auth error type ");
        }

        super.setUserAuthData(userAuthData);
    }
    */

    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauth, final boolean renewable, final boolean required) {
        if(reauth == ReauthCode.USERDATA_REAUTH) {
            if(currentRetryCount++ == maxRetryCount)
            {
                final UserAuthenticationData userAuthData;

                if (UserAuthenticationScheme.EMAIL_PASSWORD.equals(schemeUsed)) {
                    userAuthData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
                } else {
                    throw new IllegalArgumentException("Unsupported authentication type: " + schemeUsed.name());
                }

                super.setUserAuthData(userAuthData);
            }
        }
        return super.getUserAuthData(reauth, renewable, required);
    }

    public void clearKeyRequestData() {
        final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();
        super.setKeyRequestData(keyRequestData);
    }

    /**
     * Remove all entries and set to the specified key exchange scheme.
     *
     * @param scheme .
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws MslCryptoException
     */
    public void resetKeyRequestData(final KeyExchangeScheme scheme) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslCryptoException, MslKeyExchangeException {

        final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();

        // Not intending to send key request data
        if(scheme == null) {
            super.setKeyRequestData(keyRequestData);
            return;
        }

        if(KeyExchangeScheme.DIFFIE_HELLMAN.equals(scheme)) {

            final DiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
            final DHParameterSpec paramSpec = params.getParameterSpec(MockDiffieHellmanParameters.DEFAULT_ID);
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            generator.initialize(paramSpec);
            final KeyPair requestKeyPair = generator.generateKeyPair();
            final BigInteger publicKey = ((DHPublicKey)requestKeyPair.getPublic()).getY();
            final DHPrivateKey privateKey = (DHPrivateKey)requestKeyPair.getPrivate();
            keyRequestData.add(new DiffieHellmanExchange.RequestData(MockDiffieHellmanParameters.DEFAULT_ID, publicKey, privateKey));

        } else if(KeyExchangeScheme.ASYMMETRIC_WRAPPED.equals(scheme)) {

            final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
            final KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
            final PublicKey publicKey = rsaKeyPair.getPublic();
            final PrivateKey privateKey = rsaKeyPair.getPrivate();
            keyRequestData.add(new AsymmetricWrappedExchange.RequestData(RSA_KEYPAIR_ID, AsymmetricWrappedExchange.RequestData.Mechanism.JWE_RSA, publicKey, privateKey));

        } else if(KeyExchangeScheme.SYMMETRIC_WRAPPED.equals(scheme)) {

            keyRequestData.add(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));

        } else {

            throw new IllegalArgumentException("Unsupported key exchange scheme: " + scheme.name());

        }

        super.setKeyRequestData(keyRequestData);
    }

}

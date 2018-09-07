/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.entityauth;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.EccCryptoContext;
import com.netflix.msl.crypto.EccCryptoContext.Mode;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * Test ECC asymmetric keys authentication factory.
 */
public class MockEccAuthenticationFactory extends EntityAuthenticationFactory {

	/** ECC public key. */
    private static String ECC_PUBKEY_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExgY6uU5xZkvDLVlo5PpKjhRJnyqS" +
        "j4+LNcQ+x+kdPbZf1GwiJy2sRiJwghsXl9X8ffRpUqiLeNW0oOE/+dG2iw==";

    /** ECC private key. */
    private static String ECC_PRIVKEY_B64 =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrNqzpcZOpGRqlVGZ" +
        "nelA4i7N/E96nJ8Ntk1ZXhPzKcChRANCAATGBjq5TnFmS8MtWWjk+kqOFEmfKpKP" +
        "j4s1xD7H6R09tl/UbCInLaxGInCCGxeX1fx99GlSqIt41bSg4T/50baL";

    /** ECC ESN. */
    public static final String ECC_ESN = "ECCPREFIX-ESN";
    /** ECC public key ID. */
    public static final String ECC_PUBKEY_ID = "mockECCKeyId";
    /** ECC public key. */
    public static final PublicKey ECC_PUBKEY;
    /** ECC private key. */
    public static final PrivateKey ECC_PRIVKEY;

    
    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            final byte[] pubKeyEncoded = Base64.decode(ECC_PUBKEY_B64);
            final byte[] privKeyEncoded = Base64.decode(ECC_PRIVKEY_B64);
            final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
            ECC_PUBKEY = keyFactory.generatePublic(pubKeySpec);
            ECC_PRIVKEY = keyFactory.generatePrivate(privKeySpec);
        } catch (final InvalidKeySpecException e) {
            throw new MslInternalException("ECC key generation failure: InvalidKeySpecException", e);
        } catch (final NoSuchAlgorithmException e) {
        	throw new MslInternalException("ECC key generation failure.", e);
        }
    }

    /**
     * Create a new test ECC authentication factory.
     */
    public MockEccAuthenticationFactory() {
        super(EntityAuthenticationScheme.ECC);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslCryptoException {
        return new EccAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EccAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof EccAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final EccAuthenticationData rad = (EccAuthenticationData)authdata;
        
        // Try to return the test crypto context.
        final String pubkeyid = rad.getPublicKeyId();
        if (ECC_PUBKEY_ID.equals(pubkeyid)) {
            final String identity = rad.getIdentity();
            return new EccCryptoContext(identity, ECC_PRIVKEY, ECC_PUBKEY, Mode.SIGN_VERIFY);
        }
        
        // Entity not found.
        throw new MslEntityAuthException(MslError.ECC_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);
    }
}

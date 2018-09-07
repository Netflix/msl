/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext.Mode;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * Test RSA asymmetric keys authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockRsaAuthenticationFactory extends EntityAuthenticationFactory {
	/** 1024-bit RSA public key. */
    private static String RSA_PUBKEY_B64 = 
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeJpiH5nikd3XeAo2rHjLJVVChM/p6l" +
        "VnQHyFh77w0Efbppi1P1pNy8BxJ++iFKt2dV/4ZKkUKqtlIu3KX19kcCAwEAAQ==";
    /** 1024-bit RSA private key. */
    private static String RSA_PRIVKEY_B64 =
        "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAt4mmIfmeKR3dd4Cj" +
        "aseMslVUKEz+nqVWdAfIWHvvDQR9ummLU/Wk3LwHEn76IUq3Z1X/hkqRQqq2Ui7c" +
        "pfX2RwIDAQABAkEAlB6YXq7uv0wE4V6Fg7VLjNhkNKn+itXwMW/eddp/D8cC4QbH" +
        "+0Ejt0e3F+YcY0RBsTUk7hz89VW7BtpjXRrU0QIhAOyjvUsihGzImq+WDiEWvnXX" +
        "lVaUaJXaaNElE37V/BE1AiEAxo25k2z2SDbFC904Zk020kISi95KNNv5ceEFcGu0" +
        "dQsCIQDUgj7uCHNv1b7ETDcoE+q6nP2poOFDIb7bgzY8wyH4uQIgf+02YO82auam" +
        "5HL+8KLVLHkXm/h31UDZoe66Y2lxlmsCIQC+cKulQATpKNnMV1RVtpH07A0+X72s" +
        "wpu2pmaRSYgw/w==";

    /** RSA ESN. */
    public static final String RSA_ESN = "RSAPREFIX-ESN";
    /** RSA public key ID. */
    public static final String RSA_PUBKEY_ID = "mockRSAKeyId";
    /** RSA public key. */
    public static final PublicKey RSA_PUBKEY;
    /** RSA private key. */
    public static final PrivateKey RSA_PRIVKEY;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            final byte[] pubKeyEncoded = Base64.decode(RSA_PUBKEY_B64);
            final byte[] privKeyEncoded = Base64.decode(RSA_PRIVKEY_B64);
            final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSA_PUBKEY = keyFactory.generatePublic(pubKeySpec);
            RSA_PRIVKEY = keyFactory.generatePrivate(privKeySpec);
        } catch (final InvalidKeySpecException e) {
            throw new MslInternalException("RSA key generation failure: InvalidKeySpecException", e);
        } catch (final NoSuchAlgorithmException e) {
        	throw new MslInternalException("RSA key generation failure.", e);
        }
    }

    /**
     * Create a new test RSA authentication factory.
     */
    public MockRsaAuthenticationFactory() {
        super(EntityAuthenticationScheme.RSA);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslCryptoException {
        return new RsaAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.RsaAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof RsaAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final RsaAuthenticationData rad = (RsaAuthenticationData)authdata;
        
        // Try to return the test crypto context.
        final String pubkeyid = rad.getPublicKeyId();
        if (RSA_PUBKEY_ID.equals(pubkeyid)) {
            final String identity = rad.getIdentity();
            return new RsaCryptoContext(ctx, identity, RSA_PRIVKEY, RSA_PUBKEY, Mode.SIGN_VERIFY);
        }
        
        // Entity not found.
        throw new MslEntityAuthException(MslError.RSA_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);
    }
}

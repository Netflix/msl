package com.netflix.msl.client.configuration.entityauth;

import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.util.MslContext;

/**
 * User: skommidi
 * Date: 7/29/14
 */
public class TestRsaAuthenticationFactory extends MockRsaAuthenticationFactory {

    /** RSA public key ID. */
    public static final String RSA_PUBKEY_ID = "mockRSAKeyId-test";

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
            return new RsaCryptoContext(ctx, identity, RSA_PRIVKEY, RSA_PUBKEY, RsaCryptoContext.Mode.SIGN_VERIFY);
        }
        if (MockRsaAuthenticationFactory.RSA_PUBKEY_ID.equals(pubkeyid)) {
            final String identity = rad.getIdentity();
            return new RsaCryptoContext(ctx, identity, RSA_PRIVKEY, RSA_PUBKEY, RsaCryptoContext.Mode.SIGN_VERIFY);
        }

        // Entity not found.
        throw new MslEntityAuthException(MslError.RSA_PUBLICKEY_NOT_FOUND, pubkeyid).setEntity(rad);
    }
}

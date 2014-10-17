package com.netflix.msl.client.configuration.entityauth;

import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.util.MslContext;

/**
 * User: skommidi
 * Date: 7/29/14
 *
 * Test Preshared Entity Authentication Factory
 */
public class TestPresharedAuthenticationFactory extends MockPresharedAuthenticationFactory {

    /** PSK ESN. */
    public static final String PSK_ESN = "PSK-ESN-TEST";

    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof PresharedAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final PresharedAuthenticationData pad = (PresharedAuthenticationData)authdata;

        // Try to return the test crypto context.
        final String identity = pad.getIdentity();
        if (PSK_ESN.equals(identity))
            return new SymmetricCryptoContext(ctx, identity, KPE2, KPH2, KPW2);

        // Entity not found.
        throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "psk " + identity).setEntity(pad);
    }

}

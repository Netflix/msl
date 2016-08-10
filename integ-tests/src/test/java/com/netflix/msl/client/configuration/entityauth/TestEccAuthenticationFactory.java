/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.client.configuration.entityauth;

import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.EccCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.MockEccAuthenticationFactory;
import com.netflix.msl.entityauth.EccAuthenticationData;
import com.netflix.msl.util.MslContext;

public class TestEccAuthenticationFactory extends MockEccAuthenticationFactory {

    /** ECC public key ID. */
    public static final String ECC_PUBKEY_ID = "mockECCKeyId-test";

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
            return new EccCryptoContext(identity, ECC_PRIVKEY, ECC_PUBKEY, EccCryptoContext.Mode.SIGN_VERIFY);
        }
        if (MockEccAuthenticationFactory.ECC_PUBKEY_ID.equals(pubkeyid)) {
            final String identity = rad.getIdentity();
            return new EccCryptoContext(identity, ECC_PRIVKEY, ECC_PUBKEY, EccCryptoContext.Mode.SIGN_VERIFY);
        }

        // Entity not found.
        throw new MslEntityAuthException(MslError.ECC_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);
    }
}

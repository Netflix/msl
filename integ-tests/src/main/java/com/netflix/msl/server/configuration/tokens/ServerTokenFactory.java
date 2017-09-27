/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.server.configuration.tokens;

import java.sql.Date;

import javax.crypto.SecretKey;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MockTokenFactory;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslUtils;

/**
 * User: skommidi
 * Date: 7/24/14
 */
public class ServerTokenFactory extends MockTokenFactory {
    public ServerTokenFactory(final TokenFactoryType tokenFactoryType) {
        this.tokenFactoryType = tokenFactoryType;
    }

    @Override
    public MslError acceptNonReplayableId(final MslContext mslContext, final MasterToken masterToken, final long nonReplayableId) throws MslMasterTokenException, MslException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        if (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE)
            throw new MslException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "nonReplayableId " + nonReplayableId);

        if(this.tokenFactoryType == TokenFactoryType.ACCEPT_NON_REPLAYABLE_ID) {
            return null;
        } else {
            return MslError.MESSAGE_REPLAYED;
        }

    }

    @Override
    public MasterToken renewMasterToken(final MslContext ctx, final MasterToken masterToken, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslMasterTokenException, MslCryptoException, MslEncodingException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);

        final long oldSequenceNumber = masterToken.getSequenceNumber();
        if(oldSequenceNumber > this.sequenceNumber + 30) {
            throw new MslMasterTokenException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, masterToken);
        }

        this.sequenceNumber++;

        return super.renewMasterToken(ctx, masterToken, encryptionKey, hmacKey, issuerData);
    }

    @Override
    public MasterToken createMasterToken(final MslContext ctx, final EntityAuthenticationData entityAuthData, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
        final Date expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
        this.sequenceNumber++;
        final long sequenceNumber = this.sequenceNumber;
        final long serialNumber = MslUtils.getRandomLong(ctx);
        final String identity = entityAuthData.getIdentity();
        return new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, null, identity, encryptionKey, hmacKey);
    }

    private final TokenFactoryType tokenFactoryType;
}

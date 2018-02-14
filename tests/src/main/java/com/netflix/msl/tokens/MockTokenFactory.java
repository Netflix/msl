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
package com.netflix.msl.tokens;

import java.sql.Date;

import javax.crypto.SecretKey;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslUtils;

/**
 * Token factory for unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockTokenFactory implements TokenFactory {
    /** Renewal window start offset in milliseconds. */
    protected static final int RENEWAL_OFFSET = 60000;
    /** Expiration offset in milliseconds. */
    protected static final int EXPIRATION_OFFSET = 120000;
    /** Non-replayable ID acceptance window. */
    private static final long NON_REPLAYABLE_ID_WINDOW = 65536;
    
    /**
     * @param sequenceNumber the newest master token sequence number, or -1 to
     *        accept all master tokens as the newest.
     */
    public void setNewestMasterToken(final long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }
    
    /**
     * @param masterToken the master token to consider revoked or {@code null}
     *        to unset.
     */
    public void setRevokedMasterToken(final MasterToken masterToken) {
        this.revokedMasterToken = masterToken;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRevoked(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        if (this.revokedMasterToken != null && this.revokedMasterToken.getIdentity().equals(masterToken.getIdentity()))
            return MslError.MASTERTOKEN_IDENTITY_REVOKED;
        return null;
    }

    /**
     * @param nonReplayableId the largest non-replayable ID, or -1 to accept
     *        all non-replayable IDs.
     */
    public void setLargestNonReplayableId(final long nonReplayableId) {
        this.largestNonReplayableId = nonReplayableId;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#acceptNonReplayableId(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, long)
     */
    @Override
    public MslError acceptNonReplayableId(final MslContext ctx, final MasterToken masterToken, final long nonReplayableId) throws MslMasterTokenException, MslException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        if (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE)
            throw new MslException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "nonReplayableId " + nonReplayableId);
        
        // Reject if the non-replayable ID is equal or just a few messages
        // behind. The sender can recover by incrementing.
        final long catchupWindow = MslConstants.MAX_MESSAGES / 2;
        if (nonReplayableId <= largestNonReplayableId &&
            nonReplayableId > largestNonReplayableId - catchupWindow)
        {
            return MslError.MESSAGE_REPLAYED;
        }
        
        // Reject if the non-replayable ID is larger by more than the
        // acceptance window. The sender cannot recover quickly.
        if (nonReplayableId - NON_REPLAYABLE_ID_WINDOW > largestNonReplayableId)
            return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;

        // If the non-replayable ID is smaller reject it if it is outside the
        // wrap-around window. The sender cannot recover quickly.
        if (nonReplayableId < largestNonReplayableId) {
            final long cutoff = largestNonReplayableId - MslConstants.MAX_LONG_VALUE + NON_REPLAYABLE_ID_WINDOW;
            if (nonReplayableId >= cutoff)
                return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;
        }
        
        // Accept the non-replayable ID.
        largestNonReplayableId = nonReplayableId;
        return null;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData, javax.crypto.SecretKey, javax.crypto.SecretKey, com.netflix.msl.io.MslObject)
     */
    @Override
    public MasterToken createMasterToken(final MslContext ctx, final EntityAuthenticationData entityAuthData, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
        final Date expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
        final long sequenceNumber = 0;
        final long serialNumber = MslUtils.getRandomLong(ctx);
        final String identity = entityAuthData.getIdentity();
        return new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRenewable(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRenewable(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        // Always succeed.
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, javax.crypto.SecretKey, javax.crypto.SecretKey, com.netflix.msl.io.MslObject)
     */
    @Override
    public MasterToken renewMasterToken(final MslContext ctx, final MasterToken masterToken, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        final Date renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
        final Date expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
        final long oldSequenceNumber = masterToken.getSequenceNumber();
        final long sequenceNumber;
        if (this.sequenceNumber == -1) {
            sequenceNumber = (oldSequenceNumber == MslConstants.MAX_LONG_VALUE) ? 0 : oldSequenceNumber + 1;
        } else {
            this.sequenceNumber = (this.sequenceNumber == MslConstants.MAX_LONG_VALUE) ? 0 : this.sequenceNumber + 1;
            sequenceNumber = this.sequenceNumber;
        }
        final long serialNumber = masterToken.getSerialNumber();
        final MslObject mtIssuerData = masterToken.getIssuerData();
        final MslObject mergedIssuerData;
        try {
            mergedIssuerData = MslEncoderUtils.merge(mtIssuerData, issuerData);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MASTERTOKEN_ISSUERDATA_ENCODE_ERROR, "mt issuerdata " + mtIssuerData + "; issuerdata " + issuerData, e);
        }
        final String identity = masterToken.getIdentity();
        return new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, mergedIssuerData, identity, encryptionKey, hmacKey);
    }

    /**
     * @param userIdToken the user ID token to consider revoked or {@code null}
     *        to unset.
     */
    public void setRevokedUserIdToken(final UserIdToken userIdToken) {
        this.revokedUserIdToken = userIdToken;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isUserIdTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslError isUserIdTokenRevoked(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken) throws MslUserIdTokenException, MslMasterTokenException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        if (!userIdToken.isDecrypted())
            throw new MslUserIdTokenException(MslError.USERIDTOKEN_NOT_DECRYPTED, userIdToken);
        
        if (userIdToken.equals(this.revokedUserIdToken))
            return MslError.USERIDTOKEN_REVOKED;
        return null;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createUserIdToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MslUser, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public UserIdToken createUserIdToken(final MslContext ctx, final MslUser user, final MasterToken masterToken) throws MslEncodingException, MslCryptoException {
        final MslObject issuerData = null;
        final Date renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
        final Date expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
        final long serialNumber = MslUtils.getRandomLong(ctx);
        return new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewUserIdToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.UserIdToken, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public UserIdToken renewUserIdToken(final MslContext ctx, final UserIdToken userIdToken, final MasterToken masterToken) throws MslEncodingException, MslCryptoException, MslUserIdTokenException {
        if (!userIdToken.isDecrypted())
            throw new MslUserIdTokenException(MslError.USERIDTOKEN_NOT_DECRYPTED, userIdToken).setMasterToken(masterToken);

        final MslObject issuerData = null;
        final Date renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
        final Date expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
        final long serialNumber = userIdToken.getSerialNumber();
        final MslUser user = userIdToken.getUser();
        return new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createUser(com.netflix.msl.util.MslContext, byte[])
     */
    @Override
    public MslUser createUser(final MslContext ctx, final String userdata) throws MslException {
        try {
            return new MockMslUser(userdata);
        } catch (final IllegalArgumentException e) {
            throw new MslException(MslError.USERIDTOKEN_IDENTITY_INVALID, userdata, e);
        }
    }

    /**
     * Reset the token factory state.
     */
    public void reset() {
        sequenceNumber = -1;
        revokedMasterToken = null;
        largestNonReplayableId = 0;
        revokedUserIdToken = null;
    }

    /** Newest master token sequence number. (-1 accepts all master tokens.) */
    protected long sequenceNumber = -1;
    /** Revoked master token. (null accepts all master tokens.) */
    private MasterToken revokedMasterToken = null;
    /** Current largest non-replayable ID. */
    private long largestNonReplayableId = 0;
    /** Revoked user ID token. (null accepts all user ID tokens.) */
    private UserIdToken revokedUserIdToken = null;
}

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
package server.userauth;

import java.sql.Date;
import java.util.concurrent.ConcurrentHashMap;

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
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslUtils;

/**
 * <p>A memory-backed token factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleTokenFactory implements TokenFactory {
    /** Renewal window start offset in milliseconds. */
    private static final int RENEWAL_OFFSET = 60000;
    /** Expiration offset in milliseconds. */
    private static final int EXPIRATION_OFFSET = 120000;
    /** Non-replayable ID acceptance window. */
    private static final long NON_REPLAYABLE_ID_WINDOW = 65536;
    
    /**
     * Return true if the provided master token is the newest master token
     * as far as we know.
     * 
     * @param masterToken the master token.
     * @return true if this is the newest master token.
     * @throws MslMasterTokenException if the master token is not decrypted.
     */
    private boolean isNewestMasterToken(final MasterToken masterToken) throws MslMasterTokenException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        // Return true if we have no sequence number records or if the master
        // token sequence number is the most recently issued one.
        final Long newestSeqNo = mtSequenceNumbers.get(masterToken.getIdentity());
        return (newestSeqNo == null || newestSeqNo.longValue() == masterToken.getSequenceNumber());
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRevoked(final MslContext ctx, final MasterToken masterToken) {
        // No support for revoked master tokens.
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#acceptNonReplayableId(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, long)
     */
    @Override
    public MslError acceptNonReplayableId(final MslContext ctx, final MasterToken masterToken, final long nonReplayableId) throws MslException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        if (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE)
            throw new MslException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "nonReplayableId " + nonReplayableId);
        
        // Accept if there is no non-replayable ID.
        final String key = masterToken.getIdentity() + ":" + masterToken.getSerialNumber();
        final Long largestNonReplayableId = nonReplayableIds.putIfAbsent(key, nonReplayableId);
        if (largestNonReplayableId == null) {
            return null;
        }
        
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
        //
        // This is not perfect, since it's possible a smaller value will
        // overwrite a larger value, but it's good enough for the example.
        nonReplayableIds.put(key, nonReplayableId);
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
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey);
        
        // Remember the sequence number.
        //
        // This is not perfect, since it's possible a smaller value will
        // overwrite a larger value, but it's good enough for the example.
        mtSequenceNumbers.put(identity, sequenceNumber);
        
        // Return the new master token.
        return masterToken;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRenewable(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRenewable(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        if (!isNewestMasterToken(masterToken))
            return MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC;
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, javax.crypto.SecretKey, javax.crypto.SecretKey, com.netflix.msl.io.MslObject)
     */
    @Override
    public MasterToken renewMasterToken(final MslContext ctx, final MasterToken masterToken, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        if (!isNewestMasterToken(masterToken))
            throw new MslMasterTokenException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC, masterToken);
        
        // Renew master token.
        final MslObject mtIssuerData = masterToken.getIssuerData();
        final MslObject mergedIssuerData;
        try {
            mergedIssuerData = MslEncoderUtils.merge(mtIssuerData, issuerData);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MASTERTOKEN_ISSUERDATA_ENCODE_ERROR, "mt issuerdata " + mtIssuerData + "; issuerdata " + issuerData, e);
        }
        final Date renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
        final Date expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
        final long oldSequenceNumber = masterToken.getSequenceNumber();
        final long sequenceNumber = (oldSequenceNumber == MslConstants.MAX_LONG_VALUE) ? 0 : oldSequenceNumber + 1;
        final long serialNumber = masterToken.getSerialNumber();
        final String identity = masterToken.getIdentity();
        final MasterToken newMasterToken = new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, mergedIssuerData, identity, encryptionKey, hmacKey);
        
        // Remember the sequence number.
        //
        // This is not perfect, since it's possible a smaller value will
        // overwrite a larger value, but it's good enough for the example.
        mtSequenceNumbers.put(identity, sequenceNumber);
        
        // Return the new master token.
        return newMasterToken;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isUserIdTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslError isUserIdTokenRevoked(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken) {
        // No support for revoked user ID tokens.
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
     * @see com.netflix.msl.tokens.TokenFactory#createUser(com.netflix.msl.util.MslContext, java.lang.String)
     */
    @Override
    public MslUser createUser(final MslContext ctx, final String userdata) {
        return new SimpleUser(userdata);
    }
    
    /** Map of entity identities onto sequence numbers. */
    private final ConcurrentHashMap<String,Long> mtSequenceNumbers = new ConcurrentHashMap<String,Long>();
    /** Map of entity identities and serial numbers onto non-replayable IDs. */
    private final ConcurrentHashMap<String,Long> nonReplayableIds = new ConcurrentHashMap<String,Long>();
}

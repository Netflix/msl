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

package mslcli.server.tokens;

import java.math.BigInteger;
import java.sql.Date;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import org.json.JSONObject;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;

import mslcli.common.tokens.SimpleUser;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.SharedUtil;

/**
 * <p>A server-side memory-backed token factory.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */
public class ServerTokenFactory implements TokenFactory {
    /** Master Token Renewal window start offset in milliseconds. */
    private final int renewalOffset;
    /** Master Token Expiration offset in milliseconds. */
    private final int expirationOffset;
    /** Master Token Non-replayable ID acceptance window. */
    private final long nonReplayIdWindow;

    /** User ID Token Renewal window start offset in milliseconds. */
    private final int uitRenewalOffset;
    /** User ID Expiration offset in milliseconds. */
    private final int uitExpirationOffset;

    /** app context */
    private final AppContext appCtx;

    private static final int MAX_LONG_VALUE_BITS = BigInteger.valueOf(MslConstants.MAX_LONG_VALUE).bitLength();

    /*
     * @param appCtx application context
     */
    public ServerTokenFactory(final AppContext appCtx) throws ConfigurationException {
        if (appCtx == null) {
            throw new IllegalArgumentException("NULL app context");
        }
        this.appCtx = appCtx;
        this.renewalOffset = appCtx.getProperties().getMasterTokenRenewalOffset();
        this.expirationOffset = appCtx.getProperties().getMasterTokenExpirationOffset();
        this.nonReplayIdWindow = appCtx.getProperties().getMasterTokenNonReplayIdWindow();
        this.uitRenewalOffset = appCtx.getProperties().getUserIdTokenRenewalOffset();
        this.uitExpirationOffset = appCtx.getProperties().getUserIdTokenExpirationOffset();
    }

    private static final int MAX_LOST_MTOKENS = 5;

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isNewestMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public boolean isNewestMasterToken(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        // Return false if we have no sequence number records
        final SeqNumPair seqNumPair = mtSequenceNumbers.get(masterToken.getIdentity());
        if (seqNumPair == null)
            return false;

        // if it's the first MasterToken issued, its serial number must be the one we recorded
        if (seqNumPair.oldSeqNum == null) {
             return seqNumPair.newSeqNum.longValue() == masterToken.getSequenceNumber();
        // if it's not the first master token, it must be either the last issued
        // ... or the last used for issuing the last issued, in case all subsequent issued ones were lost on its way to the client
        // ... as long as not too many were lost
        } else {
             return ((seqNumPair.oldSeqNum.longValue() == masterToken.getSequenceNumber()) ||
                    (seqNumPair.newSeqNum.longValue() == masterToken.getSequenceNumber())) &&
                    ((seqNumPair.newSeqNum.longValue() - seqNumPair.oldSeqNum.longValue()) < MAX_LOST_MTOKENS);
        }
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
        synchronized (nonReplayableIdsLock) {
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        if (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE)
            throw new MslException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "nonReplayableId " + nonReplayableId);
        
        // Accept if there is no non-replayable ID.
        final String key = masterToken.getIdentity() + ":" + masterToken.getSerialNumber();
        final Long largestNonReplayableId = nonReplayableIds.putIfAbsent(key, nonReplayableId);
        if (largestNonReplayableId == null) {
            appCtx.info(String.format("%s: First Non-Replayable ID %d", key, nonReplayableId));
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
        if (nonReplayableId - nonReplayIdWindow > largestNonReplayableId)
            return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;
        
        // If the non-replayable ID is smaller reject it if it is outside the
        // wrap-around window. The sender cannot recover quickly.
        if (nonReplayableId < largestNonReplayableId) {
            final long cutoff = largestNonReplayableId - MslConstants.MAX_LONG_VALUE + nonReplayIdWindow;
            if (nonReplayableId >= cutoff)
                return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;
        }
        
        // Accept the non-replayable ID.
        //
        // This is not perfect, since it's possible a smaller value will
        // overwrite a larger value, but it's good enough for the example.
        nonReplayableIds.put(key, nonReplayableId);
        appCtx.info(String.format("%s: Update Non-Replayable ID %d", key, nonReplayableId));
        return null;
        } // synchronized (nonReplayableIdsLock)
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createMasterToken(com.netflix.msl.util.MslContext, java.lang.String, javax.crypto.SecretKey, javax.crypto.SecretKey)
     */
    @Override
    public MasterToken createMasterToken(final MslContext ctx, final String identity, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncodingException, MslCryptoException {
        appCtx.info("Creating MasterToken for " + identity);
        final Date renewalWindow = new Date(ctx.getTime() + renewalOffset);
        final Date expiration = new Date(ctx.getTime() + expirationOffset);
        final long sequenceNumber = 0;
        final long serialNumber = generateSerialNumber(ctx.getRandom());
        final JSONObject issuerData = null;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey);
        
        // Remember the sequence number.
        //
        // This is not perfect, since it's possible a smaller value will
        // overwrite a larger value, but it's good enough for the example.
        mtSequenceNumbers.put(identity, new SeqNumPair(null, sequenceNumber));
        
        // Return the new master token.
        return masterToken;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRenewable(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRenewable(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        if (!isNewestMasterToken(ctx, masterToken))
            return MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC;
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, javax.crypto.SecretKey, javax.crypto.SecretKey)
     */
    @Override
    public MasterToken renewMasterToken(final MslContext ctx, final MasterToken masterToken, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        appCtx.info("Renewing " + SharedUtil.getMasterTokenInfo(masterToken));
        if (!isNewestMasterToken(ctx, masterToken))
            throw new MslMasterTokenException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC, masterToken);
        
        // Renew master token.
        final JSONObject issuerData = null;
        final Date renewalWindow = new Date(ctx.getTime() + renewalOffset);
        final Date expiration = new Date(ctx.getTime() + expirationOffset);
        final String identity = masterToken.getIdentity();
        final SeqNumPair seqNumPair = mtSequenceNumbers.get(identity);
        final long lastSequenceNumber = seqNumPair.newSeqNum;
        final long nextSequenceNumber = (lastSequenceNumber == MslConstants.MAX_LONG_VALUE) ? 0 : lastSequenceNumber + 1;
        final long serialNumber = masterToken.getSerialNumber();
        final MasterToken newMasterToken = new MasterToken(ctx, renewalWindow, expiration, nextSequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey);
        
        // Remember the sequence number.
        //
        // This is not perfect, since it's possible a smaller value will
        // overwrite a larger value, but it's good enough for the example.
        mtSequenceNumbers.put(identity, new SeqNumPair(masterToken.getSequenceNumber(), nextSequenceNumber));
        
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
        appCtx.info("Creating UserIdToken for user " + ((user != null) ? user.getEncoded() : null));
        final JSONObject issuerData = null;
        final Date renewalWindow = new Date(ctx.getTime() + uitRenewalOffset);
        final Date expiration = new Date(ctx.getTime() + uitExpirationOffset);
        final long serialNumber = generateSerialNumber(ctx.getRandom());
        return new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewUserIdToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.UserIdToken, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public UserIdToken renewUserIdToken(final MslContext ctx, final UserIdToken userIdToken, final MasterToken masterToken) throws MslEncodingException, MslCryptoException, MslUserIdTokenException {
        appCtx.info("Renewing " + SharedUtil.getUserIdTokenInfo(userIdToken));
        if (!userIdToken.isDecrypted())
            throw new MslUserIdTokenException(MslError.USERIDTOKEN_NOT_DECRYPTED, userIdToken).setEntity(masterToken);

        final JSONObject issuerData = null;
        final Date renewalWindow = new Date(ctx.getTime() + uitRenewalOffset);
        final Date expiration = new Date(ctx.getTime() + uitExpirationOffset);
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
    
    /*
     * helper - generate random serial number in [0 ... MslConstants.MAX_LONG_VALUE] range
     */
    private long generateSerialNumber(final Random r) {
        long serialNumber = -1L;
        do {
            serialNumber = new BigInteger(MAX_LONG_VALUE_BITS, r).longValue();
            appCtx.info(String.format("Serial Number %x, Max %x", serialNumber, MslConstants.MAX_LONG_VALUE));
        } while (serialNumber > MslConstants.MAX_LONG_VALUE);
        return serialNumber;
    }

    /** Map of entity identities onto sequence numbers. */
    private final ConcurrentHashMap<String,SeqNumPair> mtSequenceNumbers = new ConcurrentHashMap<String,SeqNumPair>();
    /** Map of entity identities and serial numbers onto non-replayable IDs. */
    private final ConcurrentHashMap<String,Long> nonReplayableIds = new ConcurrentHashMap<String,Long>();
    private final Object nonReplayableIdsLock = new Object();

    private static final class SeqNumPair {
        private Long oldSeqNum;
        private Long newSeqNum;
        SeqNumPair(final Long oldSeqNum, final Long newSeqNum) {
            this.oldSeqNum = oldSeqNum;
            this.newSeqNum = newSeqNum;
        }
    }
}

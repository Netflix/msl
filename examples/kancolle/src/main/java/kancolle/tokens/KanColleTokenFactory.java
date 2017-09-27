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
package kancolle.tokens;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import kancolle.userauth.Officer;
import kancolle.util.KanColleAuthenticationUtils;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
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
 * <p>The KanColle token factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleTokenFactory implements TokenFactory {
    // The master token renewal window is how often a ship or port may acquire
    // new session keys. The expiration specifies when new session keys must be
    // acquired.
    //
    // Ship or port revocation is checked separately. 
    /** Master token renewal window offset in seconds. */
    private static final int mtRenewalOffset = 3600; // 1 hour
    /** Master token expiration offset in seconds. */
    private static final int mtExpirationOffset = 24 * 3600; // 24 hours
    
    // The user ID token renewal window is how often a user may have its user
    // data or state checked and updated. The expiration specifies when the 
    // user data must be checked and updated.
    //
    // Officer revocation is checked separately.
    /** User ID token renewal window offset in seconds. */
    private static final int uitRenewalOffset = 600; // 10 minutes
    /** User ID token expiration offset in seconds. */
    private static final int uitExpirationOffset = 3600; // 1 hour

    /** Non-replayable ID acceptance window. */
    private static final long NON_REPLAYABLE_ID_WINDOW = 65536;
    
    /**
     * <p>Create a KanColle token factory with the provided authentication
     * utilities.</p>
     * 
     * @param utils KanColle utilities.
     */
    public KanColleTokenFactory(final KanColleAuthenticationUtils utils) {
        this.utils = utils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRevoked(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        // Fail if the master token is not decrypted.
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);

        // Extract the entity identity. It may be a ship or a naval port.
        final String identity = masterToken.getIdentity();
        
        // Check for revocation.
        final MslError kanmusuRevoked = utils.isKanmusuRevoked(identity);
        if (kanmusuRevoked != null) return kanmusuRevoked;
        return utils.isNavalPortRevoked(identity);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#acceptNonReplayableId(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, long)
     */
    @Override
    public MslError acceptNonReplayableId(final MslContext ctx, final MasterToken masterToken, final long nonReplayableId) throws MslException {
        // Fail if the master token is not decrypted.
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        // Fail if the non-replayable ID is out of range.
        if (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE)
            throw new MslException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "nonReplayableId " + nonReplayableId);
        
        
        // Pull the last-seen non-replayable ID.
        final String identity = masterToken.getIdentity();
        final long serialNumber = masterToken.getSerialNumber();
        final String key = identity + "+" + Long.toString(serialNumber);
        final Long lastSeenId = nonReplayableIds.get(key);
        
        // If we've never seen a non-replayable ID then accept and remember
        // this one.
        if (lastSeenId == null) {
            nonReplayableIds.put(key, Long.valueOf(nonReplayableId));
            return null;
        }
        
        // Reject if the non-replayable ID is equal or just a few messages
        // behind. The sender can recover by incrementing.
        final long catchupWindow = MslConstants.MAX_MESSAGES / 2;
        if (nonReplayableId <= lastSeenId &&
            nonReplayableId > lastSeenId - catchupWindow)
        {
            return MslError.MESSAGE_REPLAYED;
        }

        // Reject if the non-replayable ID is larger by more than the
        // acceptance window. The sender cannot recover quickly.
        if (nonReplayableId - NON_REPLAYABLE_ID_WINDOW > lastSeenId)
            return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;
        
        // If the non-replayable ID is smaller reject it if it is outside the
        // wrap-around window. The sender cannot recover quickly.
        if (nonReplayableId < lastSeenId) {
            final long cutoff = lastSeenId - MslConstants.MAX_LONG_VALUE + NON_REPLAYABLE_ID_WINDOW;
            if (nonReplayableId >= cutoff)
                return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;
        }
        
        // Accept the non-replayable ID.
        nonReplayableIds.put(key, Long.valueOf(nonReplayableId));
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData, javax.crypto.SecretKey, javax.crypto.SecretKey, com.netflix.msl.io.MslObject)
     */
    @Override
    public MasterToken createMasterToken(final MslContext ctx, final EntityAuthenticationData entityAuthData, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslEncodingException, MslCryptoException {
        final Date renewal = new Date(ctx.getTime() + mtRenewalOffset);
        final Date expiration = new Date(ctx.getTime() + mtExpirationOffset);
        final long sequenceNumber = 0;
        final long serialNumber = MslUtils.getRandomLong(ctx);
        final String identity = entityAuthData.getIdentity();
        return new MasterToken(ctx, renewal, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isMasterTokenRenewable(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public MslError isMasterTokenRenewable(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        // Fail if the master token is not decrypted.
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        // Check sequence number.
        final String identity = masterToken.getIdentity();
        final long oldSequenceNumber = masterToken.getSequenceNumber();
        final Long lastSequenceNumber = sequenceNumbers.get(identity);
        if (lastSequenceNumber != null && lastSequenceNumber.longValue() != oldSequenceNumber)
            return MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC;
        
        // Renewable.
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewMasterToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, javax.crypto.SecretKey, javax.crypto.SecretKey, com.netflix.msl.io.MslObject)
     */
    @Override
    public MasterToken renewMasterToken(final MslContext ctx, final MasterToken masterToken, final SecretKey encryptionKey, final SecretKey hmacKey, final MslObject issuerData) throws MslMasterTokenException, MslEncodingException, MslCryptoException {
        // Fail if the master token is not decrypted.
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        // Check sequence number.
        final String identity = masterToken.getIdentity();
        final long oldSequenceNumber = masterToken.getSequenceNumber();
        final Long lastSequenceNumber = sequenceNumbers.get(identity);
        if (lastSequenceNumber != null && lastSequenceNumber.longValue() != oldSequenceNumber)
            throw new MslMasterTokenException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC, masterToken);
        final long sequenceNumber = (oldSequenceNumber == MslConstants.MAX_LONG_VALUE) ? 0 : oldSequenceNumber + 1;
        
        // Renew master token.
        final Date renewal = new Date(ctx.getTime() + mtRenewalOffset);
        final Date expiration = new Date(ctx.getTime() + mtExpirationOffset);
        final long serialNumber = masterToken.getSerialNumber();
        final MslObject mtIssuerData = masterToken.getIssuerData();
        final MslObject mergedIssuerData;
        try {
            mergedIssuerData = MslEncoderUtils.merge(mtIssuerData, issuerData);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MASTERTOKEN_ISSUERDATA_ENCODE_ERROR, "mt issuerdata " + mtIssuerData + "; issuerdata " + issuerData, e);
        }
        return new MasterToken(ctx, renewal, expiration, sequenceNumber, serialNumber, mergedIssuerData, identity, encryptionKey, hmacKey);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#isUserIdTokenRevoked(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslError isUserIdTokenRevoked(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken) throws MslMasterTokenException, MslUserIdTokenException {
        // Verify the master token and user ID token.
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        if (!userIdToken.isDecrypted())
            throw new MslUserIdTokenException(MslError.USERIDTOKEN_NOT_DECRYPTED, userIdToken);
        
        // Check for revocation.
        final MslUser user = userIdToken.getUser();
        if (!(user instanceof Officer))
            throw new MslInternalException("The user ID token MSL user is not an instance of " + Officer.class.getName() + ".");
        final Officer officer = (Officer)user;
        return utils.isOfficerRevoked(officer.getName());
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createUserIdToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MslUser, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public UserIdToken createUserIdToken(final MslContext ctx, final MslUser user, final MasterToken masterToken) throws MslEncodingException, MslCryptoException {
        final long now = ctx.getTime();
        final Date renewal = new Date(now + uitRenewalOffset);
        final Date expiration = new Date(now + uitExpirationOffset);
        final long serialNumber = MslUtils.getRandomLong(ctx);
        final MslObject issuerData = null;
        return new UserIdToken(ctx, renewal, expiration, masterToken, serialNumber, issuerData, user);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#renewUserIdToken(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.UserIdToken, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public UserIdToken renewUserIdToken(final MslContext ctx, final UserIdToken userIdToken, final MasterToken masterToken) throws MslUserIdTokenException, MslEncodingException, MslCryptoException {
        // Fail if the user ID token is not decrypted.
        if (!userIdToken.isDecrypted())
            throw new MslUserIdTokenException(MslError.USERIDTOKEN_NOT_DECRYPTED, userIdToken).setMasterToken(masterToken);

        final long now = ctx.getTime();
        final Date renewal = new Date(now + uitRenewalOffset);
        final Date expiration = new Date(now + uitExpirationOffset);
        final long serialNumber = userIdToken.getSerialNumber();
        final MslObject issuerData = null;
        final MslUser user = userIdToken.getUser();
        return new UserIdToken(ctx, renewal, expiration, masterToken, serialNumber, issuerData, user);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.tokens.TokenFactory#createUser(com.netflix.msl.util.MslContext, String)
     */
    @Override
    public MslUser createUser(final MslContext ctx, final String userdata) {
        return new Officer(userdata);
    }

    /** Latest master token sequence numbers by entity identity. */
    private final Map<String,Long> sequenceNumbers = new HashMap<String,Long>();
    /** Last-seen non-replayable IDs by entity identity + serial number. */
    private final Map<String,Long> nonReplayableIds = new HashMap<String,Long>();
    
    /** KanColle utilities. */
    private final KanColleAuthenticationUtils utils;
}

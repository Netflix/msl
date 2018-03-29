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

/**
 * Token factory for unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var TokenFactory = require('msl-core/tokens/TokenFactory.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    var MslError = require('msl-core/MslError.js');
    var MslException = require('msl-core/MslException.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MslEncoderUtils = require('msl-core/io/MslEncoderUtils.js');
    var MslEncoderException = require('msl-core/io/MslEncoderException.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var MslUserIdTokenException = require('msl-core/MslUserIdTokenException.js');
    var UserIdToken = require('msl-core/tokens/UserIdToken.js');
    var MslUtils = require('msl-core/util/MslUtils.js');
    
    var MockMslUser = require('../tokens/MockMslUser.js');

    /** Renewal window start offset in milliseconds. */
    var RENEWAL_OFFSET = 60000;
    /** Expiration offset in milliseconds. */
    var EXPIRATION_OFFSET = 120000;
    /** Non-replayable ID acceptance window. */
    var NON_REPLAYABLE_ID_WINDOW = 65536;

    var MockTokenFactory = module.exports = TokenFactory.extend({
        /**
         * Create a new mock token factory.
         *
         * @constructor
         * @implements {TokenFactory}
         */
        init: function init() {
            init.base.call(this);

            // The properties.
            var props = {
                _sequenceNumber: { value: -1, writable: true, enumerable: false, configurable: false },
                _revokedMasterToken: { value: null, writable: true, enumerable: false, configurable: false },
                _largestNonReplayableId: { value: 0, writable: true, enumerable: false, configurable: false },
                _revokedUserIdToken: { value: null, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @param sequenceNumber the newest master token sequence number, or -1 to
         *        accept all master tokens as the newest.
         */
        setNewestMasterToken: function setNewestMasterToken(sequenceNumber) {
            this._sequenceNumber = sequenceNumber;
        },

        /**
         * @param {MasterToken} masterToken the master token to consider revoked or {@code null}
         *        to unset.
         */
        setRevokedMasterToken: function setRevokedMasterToken(masterToken) {
            this._revokedMasterToken = masterToken;
        },

        /** @inheritDoc */
        isMasterTokenRevoked: function isMasterTokenRevoked(ctx, masterToken, callback) {
            AsyncExecutor(callback, function() {
                if (!masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);

                if (this._revokedMasterToken && (masterToken.identity == this._revokedMasterToken.identity))
                    return MslError.MASTERTOKEN_IDENTITY_REVOKED;
                return null;
            }, this);
        },

        /**
         * @param {number} nonReplayableId the largest non-replayable ID, or -1 to accept
         *        all non-replayable IDs.
         */
        setLargestNonReplayableId: function(nonReplayableId) {
            this._largestNonReplayableId = nonReplayableId;
        },

        /** @inheritDoc */
        acceptNonReplayableId: function(ctx, masterToken, nonReplayableId, callback) {
            AsyncExecutor(callback, function() {
                if (!masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
                if (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE)
                    throw new MslException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "nonReplayableId " + nonReplayableId);

                // Reject if the non-replayable ID is equal or just a few messages
                // behind. The sender can recover by incrementing.
                var catchupWindow = Math.floor(MslConstants.MAX_MESSAGES / 2);
                if (nonReplayableId <= this._largestNonReplayableId &&
                    nonReplayableId > this._largestNonReplayableId - catchupWindow)
                {
                    return MslError.MESSAGE_REPLAYED;
                }

                // Reject if the non-replayable ID is larger by more than the
                // acceptance window. The sender cannot recover quickly.
                if (nonReplayableId - NON_REPLAYABLE_ID_WINDOW > this._largestNonReplayableId)
                    return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;

                // If the non-replayable ID is smaller reject it if it is outside the
                // wrap-around window. The sender cannot recover quickly.
                if (nonReplayableId < this._largestNonReplayableId) {
                    var cutoff = this._largestNonReplayableId - MslConstants.MAX_LONG_VALUE + NON_REPLAYABLE_ID_WINDOW;
                    if (nonReplayableId >= cutoff)
                        return MslError.MESSAGE_REPLAYED_UNRECOVERABLE;
                }

                // Accept the non-replayable ID.
                this._largestNonReplayableId = nonReplayableId;
                return null;
            }, this);
        },

        /** @inheritDoc */
        createMasterToken: function(ctx, entityAuthData, encryptionKey, hmacKey, issuerData, callback) {
            AsyncExecutor(callback, function() {
                var renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
                var expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
                var sequenceNumber = 0;
                var serialNumber = MslUtils.getRandomLong(ctx);
                var identity = entityAuthData.getIdentity();
                MasterToken.create(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey, callback);
            }, this);
        },
        
        /** @inheritDoc */
        isMasterTokenRenewable: function(ctx, masterToken, callback) {
            AsyncExecutor(callback, function() {
                if (!masterToken.isDecrypted())
                    return MslError.MASTERTOKEN_UNTRUSTED;
                return null;
            }, this);
        },

        /** @inheritDoc */
        renewMasterToken: function(ctx, masterToken, encryptionKey, hmacKey, issuerData, callback) {
            AsyncExecutor(callback, function() {
                if (!masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
                
                var mtIssuerData = masterToken.issuerData;
                var mergedIssuerData;
                try {
                    mergedIssuerData = MslEncoderUtils.merge(masterToken.issuerData, issuerData);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MASTERTOKEN_ISSUERDATA_ENCODE_ERROR, "mt issuerdata " + mtIssuerData + "; issuerdata " + issuerData, e);
                    throw e;
                }
                var renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
                var expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
                var oldSequenceNumber = masterToken.sequenceNumber;
                var sequenceNumber;
                if (this._sequenceNumber == -1) {
                    sequenceNumber = (oldSequenceNumber == MslConstants.MAX_LONG_VALUE) ? 0 : oldSequenceNumber + 1;
                } else {
                    this._sequenceNumber = (this._sequenceNumber == MslConstants.MAX_LONG_VALUE) ? 0 : this._sequenceNumber + 1;
                    sequenceNumber = this._sequenceNumber;
                }
                var serialNumber = masterToken.serialNumber;
                var identity = masterToken.identity;
                MasterToken.create(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, mergedIssuerData, identity, encryptionKey, hmacKey, callback);
            }, this);
        },

        /**
         * @param {UserIdToken} userIdToken the user ID token to consider revoked or {@code null}
         *        to unset.
         */
        setRevokedUserIdToken: function setRevokedUserIdToken(userIdToken) {
            this._revokedUserIdToken = userIdToken;
        },

        /** @inheritDoc */
        isUserIdTokenRevoked: function isUserIdTokenRevoked(ctx, masterToken, userIdToken, callback) {
            AsyncExecutor(callback, function() {
                if (!userIdToken.isDecrypted())
                    throw new MslUserIdTokenException(MslError.USERIDTOKEN_NOT_DECRYPTED, userIdToken);

                if (userIdToken.equals(this._revokedUserIdToken))
                    return MslError.USERIDTOKEN_REVOKED;
                return null;
            }, this);
        },

        /** @inheritDoc */
        createUserIdToken: function createUserIdToken(ctx, user, masterToken, callback) {
            AsyncExecutor(callback, function() {
                var issuerData = null;
                var renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
                var expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
                var serialNumber = MslUtils.getRandomLong(ctx);
                UserIdToken.create(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, callback);
            }, this);
        },

        /** @inheritDoc */
        renewUserIdToken: function renewUserIdToken(ctx, userIdToken, masterToken, callback) {
            AsyncExecutor(callback, function() {
                if (!userIdToken.isDecrypted())
                    throw new MslUserIdTokenException(MslError.USERIDTOKEN_NOT_DECRYPTED, userIdToken);

                var issuerData = null;
                var renewalWindow = new Date(ctx.getTime() + RENEWAL_OFFSET);
                var expiration = new Date(ctx.getTime() + EXPIRATION_OFFSET);
                var serialNumber = userIdToken.serialNumber;
                var user = userIdToken.user;
                UserIdToken.create(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, callback);
            }, this);
        },
        
        /** @inheritDoc */
        createUser: function createUser(ctx, userdata, callback) {
            AsyncExecutor(callback, function() {
                return MockMslUser.parse(userdata);
            }, this);
        },
        
        /**
         * Reset the token factory state.
         */
        reset: function reset() {
            this._sequenceNumber = -1;
            this._revokedMasterToken = null;
            this._largestNonReplayableId = 0;
            this._revokedUserIdToken = null;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockTokenFactory'));
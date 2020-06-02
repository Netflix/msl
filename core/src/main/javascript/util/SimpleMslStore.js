/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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
 * <p>A simple MSL store that maintains state.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @implements {MslStore}
 */
(function(require, module) {
	"use strict";
	
	var MslStore = require('../util/MslStore.js');
	var MslConstants = require('../MslConstants.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslException = require('../MslException.js');
	var MslError = require('../MslError.js');

    /**
     * Increments the provided non-replayable ID by 1, wrapping around to zero
     * if the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
     *
     * @param {number} id the non-replayable ID to increment.
     * @return {number} the non-replayable ID + 1.
     * @throws MslInternalException if the provided non-replayable ID is out of
     *         range.
     */
    function incrementNonReplayableId(id) {
        if (id < 0 || id > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Non-replayable ID " + id + " is outside the valid range.");
        return (id == MslConstants.MAX_LONG_VALUE) ? 0 : id + 1;
    }

    var SimpleMslStore = module.exports = MslStore.extend({
        /**
         * Create a new simple MSL store.
         */
        init: function init() {
            init.base.call(this);

            /**
             * Map of master token keys onto master tokens.
             * @type {Object.<string,MasterToken>}
             */
            var masterTokens = {};
            /**
             * Map of master token keys onto crypto contexts.
             * @type {Object.<string,ICryptoContext>}
             */
            var cryptoContexts = {};
            /**
             * Map of local user IDs onto User ID tokens.
             * @type {Object.<string,UserIdToken>}
             */
            var userIdTokens = {};

            /**
             * Map of master token serial numbers onto non-replayable IDs.
             * @type {Object.<number,number>}
             */
            var nonReplayableIds = {};

            /**
             * Map of service token keys onto of unbound service tokens.
             * @type {Object.<string,ServiceToken>}
             */
            var unboundServiceTokens = {};
            /**
             * Map of master token serial numbers onto a map of service token keys
             * onto master token bound service tokens.
             * @type {Object.<number,Object.<string,ServiceToken>>}
             */
            var mtServiceTokens = {};
            /**
             * Map of user ID token serial numbers onto a map of service token keys
             * onto user ID token bound service tokens.
             * @type {Object.<number,Object.<string,ServiceToken>>}
             */
            var uitServiceTokens = {};

            // The properties.
            var props = {
                masterTokens: { value: masterTokens, writable: false, enumerable: false, configurable: false },
                cryptoContexts: { value: cryptoContexts, writable: false, enumerable: false, configurable: false },
                userIdTokens: { value: userIdTokens, writable: false, enumerable: false, configurable: false },
                nonReplayableIds: { value: nonReplayableIds, writable: false, enumerable: false, configurable: false },
                unboundServiceTokens: { value: unboundServiceTokens, writable: false, enumerable: false, configurable: false },
                mtServiceTokens: { value: mtServiceTokens, writable: false, enumerable: false, configurable: false },
                uitServiceTokens: { value: uitServiceTokens, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        setCryptoContext: function setCryptoContext(masterToken, cryptoContext) {
            if (!cryptoContext) {
                this.removeCryptoContext(masterToken);
            } else {
                var key = masterToken.uniqueKey();
                this.masterTokens[key] = masterToken;
                this.cryptoContexts[key] = cryptoContext;
            }
        },

        /** @inheritDoc */
        getMasterToken: function getMasterToken() {
            var masterToken = null;
            for (var key in this.masterTokens) {
                var storedMasterToken = this.masterTokens[key];
                if (!masterToken || storedMasterToken.isNewerThan(masterToken))
                    masterToken = storedMasterToken;
            }
            return masterToken;
        },

        /** @inheritDoc */
        getNonReplayableId: function getNonReplayableId(masterToken) {
            // Return the next largest non-replayable ID, or 1 if there is none.
            var serialNumber = masterToken.serialNumber;
            var currentId = (this.nonReplayableIds[serialNumber] !== undefined)
                ? this.nonReplayableIds[serialNumber]
                : 0;
            var nextId = incrementNonReplayableId(currentId);
            this.nonReplayableIds[serialNumber] = nextId;
            return nextId;
        },

        /** @inheritDoc */
        getCryptoContext: function getCryptoContext(masterToken) {
            return this.cryptoContexts[masterToken.uniqueKey()];
        },

        /** @inheritDoc */
        removeCryptoContext: function removeCryptoContext(masterToken) {
            // We must perform the removal operations in reverse-dependency order.
            // This ensures the store is in the correct state, allowing all logical
            // and safety checks to pass.
            //
            // First any bound user ID tokens are removed (which first removes any
            // service tokens bound to those user ID tokens), then bound service
            // tokens, and finally the non-replayable ID and crypto context and
            // master token pair.
            var keyToRemove = masterToken.uniqueKey();
            if (this.masterTokens[keyToRemove]) {
                // Look for a second master token with the same serial number. If
                // there is one, then just remove this master token and its crypto
                // context but do not remove any bound user ID tokens, service
                // tokens, or the non-replayable ID as those are still associated
                // with the master token that remains.
                var serialNumber = masterToken.serialNumber;
                for (var key in this.masterTokens) {
                    var token = this.masterTokens[key];
                    if (!token.equals(masterToken) && token.serialNumber == serialNumber) {
                        delete this.masterTokens[keyToRemove];
                        delete this.cryptoContexts[keyToRemove];
                        return;
                    }
                }

                // Remove bound user ID tokens and service tokens.
                var userIds = Object.keys(this.userIdTokens);
                userIds.forEach(function(userId) {
                    var userIdToken = this.userIdTokens[userId];
                    if (userIdToken.isBoundTo(masterToken))
                        this.removeUserIdToken(userIdToken);
                }, this);
                try {
                    this.removeServiceTokens(null, masterToken, null);
                } catch (e) {
                    // This should not happen since we are only providing a
                    // master token.
                    if (e instanceof MslException)
                        throw new MslInternalException("Unexpected exception while removing master token bound service tokens.", e);
                    throw e;
                }

                // Remove the non-replayable ID.
                delete this.nonReplayableIds[serialNumber];
                
                // Finally remove the crypto context.
                delete this.masterTokens[keyToRemove];
                delete this.cryptoContexts[keyToRemove];
            }
        },

        /** @inheritDoc */
        clearCryptoContexts: function clearCryptoContexts() {
            var maps = [this.masterTokens, this.cryptoContexts, this.nonReplayableIds, this.userIdTokens, this.uitServiceTokens, this.mtServiceTokens];
            maps.forEach(function(map) {
                for (var key in map)
                    delete map[key];
            }, this);
        },

        /** @inheritDoc */
        addUserIdToken: function addUserIdToken(userId, userIdToken) {
            var foundMasterToken = false;
            for (var key in this.masterTokens) {
                var masterToken = this.masterTokens[key];
                if (userIdToken.isBoundTo(masterToken)) {
                    foundMasterToken = true;
                    break;
                }
            }
            if (!foundMasterToken)
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NOT_FOUND, "uit mtserialnumber " + userIdToken.mtSerialNumber);
            this.userIdTokens[userId] = userIdToken;
        },

        /** @inheritDoc */
        getUserIdToken: function getUserIdToken(userId) {
            return this.userIdTokens[userId];
        },

        /** @inheritDoc */
        removeUserIdToken: function removeUserIdToken(userIdToken) {
            // Find the master token this user ID token is bound to.
            var masterToken = null;
            for (var key in this.masterTokens) {
                var token = this.masterTokens[key];
                if (userIdToken.isBoundTo(token)) {
                    masterToken = token;
                    break;
                }
            }

            // If we didn't find a master token we shouldn't be able to find a user
            // ID token, but it doesn't hurt to try anyway and clean things up.
            var userIds = Object.keys(this.userIdTokens);
            userIds.forEach(function(userId) {
                if (this.userIdTokens[userId].equals(userIdToken)) {
                    try {
                        this.removeServiceTokens(null, masterToken, userIdToken);
                    } catch (e) {
                        if (e instanceof MslException)
                            // This should not happen since we have already confirmed
                            // that the user ID token is bound to the master token.
                            throw new MslInternalException("Unexpected exception while removing user ID token bound service tokens.", e);
                        throw e;
                    }
                    delete this.userIdTokens[userId];
                }
            }, this);
        },

        /** @inheritDoc */
        clearUserIdTokens: function clearUserIdTokens() {
            for (var userId in this.userIdTokens) {
                var token = this.userIdTokens[userId];
                this.removeUserIdToken(token);
            }
        },

        /** @inheritDoc */
        addServiceTokens: function addServiceTokens(tokens) {
            // Verify we recognize the bound service tokens.
            tokens.forEach(function(token) {
                // Verify master token bound.
                if (token.isMasterTokenBound()) {
                    var foundMasterToken = false;
                    for (var key in this.masterTokens) {
                        var masterToken = this.masterTokens[key];
                        if (token.isBoundTo(masterToken)) {
                            foundMasterToken = true;
                            break;
                        }
                    }
                    if (!foundMasterToken)
                        throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_NOT_FOUND, "st mtserialnumber " + token.mtSerialNumber);
                }
                
                // Verify user token bound.
                if (token.isUserIdTokenBound()) {
                    var foundUserIdToken = false;
                    for (var userId in this.userIdTokens) {
                        var userIdToken = this.userIdTokens[userId];
                        if (token.isBoundTo(userIdToken)) {
                            foundUserIdToken = true;
                            break;
                        }
                    }
                    if (!foundUserIdToken)
                        throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_NOT_FOUND, "st uitserialnumber " + token.uitSerialNumber);
                }
            }, this);
            
            // Add service tokens.
            tokens.forEach(function(token) {
                // Unbound?
                if (token.isUnbound()) {
                    this.unboundServiceTokens[token.uniqueKey()] = token;
                    return;
                }

                // Master token bound?
                if (token.isMasterTokenBound()) {
                    var mtTokenSet = this.mtServiceTokens[token.mtSerialNumber];
                    if (!mtTokenSet)
                        mtTokenSet = {};
                    mtTokenSet[token.uniqueKey()] = token;
                    this.mtServiceTokens[token.mtSerialNumber] = mtTokenSet;
                }

                // User ID token bound?
                if (token.isUserIdTokenBound()) {
                    var uitTokenSet = this.uitServiceTokens[token.uitSerialNumber];
                    if (!uitTokenSet)
                        uitTokenSet = {};
                    uitTokenSet[token.uniqueKey()] = token;
                    this.uitServiceTokens[token.uitSerialNumber] = uitTokenSet;
                }
            }, this);
        },

        /** @inheritDoc */
        getServiceTokens: function getServiceTokens(masterToken, userIdToken) {
            // Validate arguments.
            if (userIdToken) {
                if (!masterToken)
                    throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NULL);
                if (!userIdToken.isBoundTo(masterToken))
                    throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.mtSerialNumber + "; mt " + masterToken.serialNumber);
            }

            // Grab service tokens. We start with the set of unbound service
            // tokens.
            var serviceTokens = {};
            for (var key in this.unboundServiceTokens) {
                var unboundToken = this.unboundServiceTokens[key];
                serviceTokens[unboundToken.uniqueKey()] = unboundToken;
            }
            // If we have a master token add the set of master token bound service
            // tokens that are not bound to any user ID tokens.
            if (masterToken) {
                var mtTokens = this.mtServiceTokens[masterToken.serialNumber];
                if (mtTokens) {
                    for (var mtKey in mtTokens) {
                        var mtToken = mtTokens[mtKey];
                        if (!mtToken.isUserIdTokenBound())
                            serviceTokens[mtKey] = mtToken;
                    }
                }
            }
            // If we have a user ID token (and because of the check above a master
            // token) add the set of user ID token bound service tokens that are
            // also bound to the same master token.
            if (userIdToken) {
                var uitTokens = this.uitServiceTokens[userIdToken.serialNumber];
                if (uitTokens) {
                    for (var uitKey in uitTokens) {
                        var uitToken = uitTokens[uitKey];
                        if (uitToken.isBoundTo(masterToken))
                            serviceTokens[uitKey] = uitToken;
                    }
                }
            }

            // Convert the map of service tokens into an array.
            var list = [];
            for (var stKey in serviceTokens)
                list.push(serviceTokens[stKey]);
            return list;
        },

        /** @inheritDoc */
        removeServiceTokens: function removeServiceTokens(name, masterToken, userIdToken) {
            var mtTokenSet, uitTokenSet;
            var mtBoundKeys, uitBoundKeys;
            var uitSerialNumber;
            
            // Validate arguments.
            if (userIdToken && masterToken &&
                !userIdToken.isBoundTo(masterToken))
            {
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.mtSerialNumber + "; mt " + masterToken.serialNumber);
            }

            // If only a name was provided remove all unbound tokens with that
            // name.
            if (name && !masterToken && !userIdToken) {
                // Remove all unbound tokens with the specified name.
                var unboundKeys = Object.keys(this.unboundServiceTokens);
                unboundKeys.forEach(function(key) {
                    var unboundToken = this.unboundServiceTokens[key];
                    if (unboundToken.name == name)
                        delete this.unboundServiceTokens[key];
                }, this);
            }

            // If a master token was provided but no user ID token was provided,
            // remove all tokens bound to the master token. If a name was also
            // provided then limit removal to tokens with the specified name.
            if (masterToken && !userIdToken) {
                mtTokenSet = this.mtServiceTokens[masterToken.serialNumber];
                if (mtTokenSet) {
                    mtBoundKeys = Object.keys(mtTokenSet);
                    mtBoundKeys.forEach(function(key) {
                        var token = mtTokenSet[key];

                        // Skip if the name was provided and it does not match.
                        if (name && token.name != name)
                            return;

                        // Remove the token.
                        delete mtTokenSet[key];
                    }, this);
                    this.mtServiceTokens[masterToken.serialNumber] = mtTokenSet;
                }
            }

            // If a user ID token was provided remove all tokens bound to the user
            // ID token. If a name was also provided then limit removal to tokens
            // with the specified name.
            if (userIdToken) {
                uitTokenSet = this.uitServiceTokens[userIdToken.serialNumber];
                if (uitTokenSet) {
                    uitBoundKeys = Object.keys(uitTokenSet);
                    uitBoundKeys.forEach(function(key) {
                        var token = uitTokenSet[key];

                        // Skip if the name was provided and it does not match.
                        if (name && token.name != name)
                            return;

                        // Remove the token.
                        delete uitTokenSet[key];
                    }, this);
                    this.uitServiceTokens[userIdToken.serialNumber] = uitTokenSet;
                }
            }
        },

        /** @inheritDoc */
        clearServiceTokens: function clearServiceTokens() {
            var maps = [this.unboundServiceTokens, this.mtServiceTokens, this.uitServiceTokens];
            maps.forEach(function(map) {
                for (var key in map)
                    delete map[key];
            }, this);
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleMslStore'));

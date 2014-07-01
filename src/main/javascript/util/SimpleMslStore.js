/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
var SimpleMslStore;
(function() {
    "use strict";

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
        if (id < 0 || id > MslConstants$MAX_LONG_VALUE)
            throw new MslInternalException("Non-replayable ID " + id + " is outside the valid range.");
        return (id == MslConstants$MAX_LONG_VALUE) ? 0 : id + 1;
    }

    SimpleMslStore = MslStore.extend({
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
            var keyToRemove = masterToken.uniqueKey();
            if (this.masterTokens[keyToRemove]) {
                delete this.masterTokens[keyToRemove];
                delete this.cryptoContexts[keyToRemove];

                // Remove bound user ID tokens, service tokens, and the non-
                // replayable ID if we no longer have a master token with the same
                // serial number.
                var serialNumber = masterToken.serialNumber;
                for (var key in this.masterTokens) {
                    var token = this.masterTokens[key];
                    if (token.serialNumber == serialNumber)
                        return;
                }

                // Remove the non-replayable ID.
                delete this.nonReplayableIds[serialNumber];

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
                    delete this.userIdTokens[userId];
                    try {
                        this.removeServiceTokens(null, masterToken, userIdToken);
                    } catch (e) {
                        if (e instanceof MslException)
                            // This should not happen since we have already confirmed
                            // that the user ID token is bound to the master token.
                            throw new MslInternalException("Unexpected exception while removing user ID token bound service tokens.", e);
                        throw e;
                    }
                }
            }, this);
        },

        /** @inheritDoc */
        clearUserIdTokens: function clearUserIdTokens() {
            for (var userId in this.userIdTokens) {
                var userIdToken = this.userIdTokens[userId];
                try {
                    this.removeServiceTokens(null, null, userIdToken);
                } catch (e) {
                    if (e instanceof MslException)
                        // This should not happen since we are only providing a user ID
                        // token.
                        throw new MslInternalException("Unexpected exception while removing user ID token bound service tokens.", e);
                    throw e;
                }
                delete this.userIdTokens[userId];
            }
        },

        /** @inheritDoc */
        addServiceTokens: function addServiceTokens(tokens) {
            tokens.forEach(function(token) {
                // Unbound?
                if (token.isUnbound()) {
                    this.unboundServiceTokens[token.uniqueKey()] = token;
                    return;
                }

                // Verify we recognize the bound service tokens.
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

                // Master token bound?
                if (token.isMasterTokenBound()) {
                    var tokenSet = this.mtServiceTokens[token.mtSerialNumber];
                    if (!tokenSet)
                        tokenSet = {};
                    tokenSet[token.uniqueKey()] = token;
                    this.mtServiceTokens[token.mtSerialNumber] = tokenSet;
                }

                // User ID token bound?
                if (token.isUserIdTokenBound()) {
                    var tokenSet = this.uitServiceTokens[token.uitSerialNumber];
                    if (!tokenSet)
                        tokenSet = {};
                    tokenSet[token.uniqueKey()] = token;
                    this.uitServiceTokens[token.uitSerialNumber] = tokenSet;
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
                    for (var key in mtTokens) {
                        var mtToken = mtTokens[key];
                        if (!mtToken.isUserIdTokenBound())
                            serviceTokens[key] = mtToken;
                    }
                }
            }
            // If we have a user ID token (and because of the check above a master
            // token) add the set of user ID token bound service tokens that are
            // also bound to the same master token.
            if (userIdToken) {
                var uitTokens = this.uitServiceTokens[userIdToken.serialNumber];
                if (uitTokens) {
                    for (var key in uitTokens) {
                        var uitToken = uitTokens[key];
                        if (uitToken.isBoundTo(masterToken))
                            serviceTokens[key] = uitToken;
                    }
                }
            }

            // Convert the map of service tokens into an array.
            var list = [];
            for (var key in serviceTokens)
                list.push(serviceTokens[key]);
            return list;
        },

        /** @inheritDoc */
        removeServiceTokens: function removeServiceTokens(name, masterToken, userIdToken) {
            // Validate arguments.
            if (userIdToken && masterToken && !userIdToken.isBoundTo(masterToken))
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + userIdToken.mtSerialNumber + "; mt " + masterToken.serialNumber);

            // If only a name was provided remove all tokens with that name.
            if (name && !masterToken && !userIdToken) {
                // Remove all unbound tokens with the specified name.
                var unboundKeys = Object.keys(this.unboundServiceTokens);
                unboundKeys.forEach(function(key) {
                    var unboundToken = this.unboundServiceTokens[key];
                    if (unboundToken.name == name)
                        delete this.unboundServiceTokens[key];
                }, this);

                // Remove all master bound tokens with the specified name.
                for (var mtSerialNumber in this.mtServiceTokens) {
                    var tokenSet = this.mtServiceTokens[mtSerialNumber];
                    var mtBoundKeys = Object.keys(tokenSet);
                    mtBoundKeys.forEach(function(key) {
                        var token = tokenSet[key];

                        // Skip if the name was provided and it does not match.
                        if (token.name != name)
                            return;

                        // Remove the token.
                        delete tokenSet[key];
                    }, this);
                    this.mtServiceTokens[mtSerialNumber] = tokenSet;
                }

                // Remove all user ID tokens with the specified name.
                for (var uitSerialNumber in this.uitServiceTokens) {
                    var tokenSet = this.uitServiceTokens[uitSerialNumber];
                    var uitBoundKeys = Object.keys(tokenSet);
                    uitBoundKeys.forEach(function(key) {
                        var token = tokenSet[key];

                        // Skip if the name was provided and it does not match.
                        if (token.name != name)
                            return;

                        // Remove the token.
                        delete tokenSet[key];
                    }, this);
                    this.uitServiceTokens[uitSerialNumber] = tokenSet;
                }
            }

            // If a master token was provided but no user ID token was provided,
            // remove all tokens bound to the master token. If a name was also
            // provided then limit removal to tokens with the specified name.
            if (masterToken && !userIdToken) {
                var tokenSet = this.mtServiceTokens[masterToken.serialNumber];
                if (tokenSet) {
                    var mtBoundKeys = Object.keys(tokenSet);
                    mtBoundKeys.forEach(function(key) {
                        var token = tokenSet[key];

                        // Skip if the name was provided and it does not match.
                        if (name && token.name != name)
                            return;

                        // Remove the token.
                        delete tokenSet[key];
                    }, this);
                    this.mtServiceTokens[masterToken.serialNumber] = tokenSet;
                }

                // Remove all user ID tokens (with the specified name if any).
                for (var uitSerialNumber in this.uitServiceTokens) {
                    var uitTokenSet = this.uitServiceTokens[uitSerialNumber];
                    var uitBoundKeys = Object.keys(uitTokenSet);
                    uitBoundKeys.forEach(function(key) {
                        var token = uitTokenSet[key];

                        // Skip if the name was provided and it does not match.
                        if (name && token.name != name)
                            return;

                        // Skip if the token is not bound to the master token.
                        if (!token.isBoundTo(masterToken))
                            return;

                        // Remove the token.
                        delete uitTokenSet[key];
                    }, this);
                    this.uitServiceTokens[uitSerialNumber] = uitTokenSet;
                }
            }

            // If a user ID token was provided remove all tokens bound to the user
            // ID token. If a name was also provided then limit removal to tokens
            // with the specified name. If a master token was also provided then
            // limit removal to tokens bound to the master token.
            if (userIdToken) {
                var tokenSet = this.uitServiceTokens[userIdToken.serialNumber];
                if (tokenSet) {
                    var uitBoundKeys = Object.keys(tokenSet);
                    uitBoundKeys.forEach(function(key) {
                        var token = tokenSet[key];

                        // Skip if the name was provided and it does not match.
                        if (name && token.name != name)
                            return;

                        // Skip if the master token was provided and the token is
                        // not bound to it.
                        if (masterToken && !token.isBoundTo(masterToken))
                            return;

                        // Remove the token.
                        delete tokenSet[key];
                    }, this);
                    this.uitServiceTokens[userIdToken.serialNumber] = tokenSet;
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
})();

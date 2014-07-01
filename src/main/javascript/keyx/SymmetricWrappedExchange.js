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
 * <p>Symmetric key wrapped key exchange.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var SymmetricWrappedExchange;
var SymmetricWrappedExchange$KeyId;
var SymmetricWrappedExchange$RequestData;
var SymmetricWrappedExchange$RequestData$parse;
var SymmetricWrappedExchange$ResponseData;
var SymmetricWrappedExchange$ResponseData$parse;

(function() {
    /**
     * Key ID.
     * @enum {string}
     */
    var KeyId = SymmetricWrappedExchange$KeyId = {
        PSK: "PSK",
        SESSION: "SESSION",
    };

    /**
     * JSON key symmetric key ID.
     * @const
     * @type {string}
     */
    var KEY_KEY_ID = "keyid";
    /**
     * JSON key wrapped encryption key.
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /**
     * JSON key wrapped HMAC key.
     * @const
     * @type {string}
     */
    var KEY_HMAC_KEY = "hmackey";

    /**
     * <p>Symmetric key wrapped key request data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid" ],
     *   "keyid" : "string"
     * } where:
     * <ul>
     * <li>{@code keyid} identifies the key that should be used to wrap the session keys</li>
     * </ul></p>
     */
    var RequestData = SymmetricWrappedExchange$RequestData = KeyRequestData.extend({
        /**
         * Create a new symmetric key wrapped key request data instance with
         * the specified key ID.
         *
         * @param {KeyId} keyId symmetric key identifier.
         */
        init: function init(keyId) {
            init.base.call(this, KeyExchangeScheme.SYMMETRIC_WRAPPED);

            // The properties.
            var props = {
                keyId: { value: keyId, writable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata() {
            var keydata = {};
            keydata[KEY_KEY_ID] = this.keyId;
            return keydata;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof SymmetricWrappedExchange$RequestData)) return false;
            return equals.base.call(this, that) && this.keyId == that.keyId;
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return uniqueKey.base.call(this) + ':' + this.keyId;
        },
    });

    /**
     * Create a new symmetric key wrapped key request data instance from
     * the provided JSON object.
     *
     * @param {Object} keyDataJO the JSON object.
     * @return {RequestData} the request data.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslKeyExchangeException if the key ID is not recognized.
     */
    var RequestData$parse = SymmetricWrappedExchange$RequestData$parse = function RequestData$parse(keyDataJO) {
        // Pull key data.
        var keyId = keyDataJO[KEY_KEY_ID];

        // Verify key data.
        if (!keyId || typeof keyId !== 'string')
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + JSON.stringify(keyDataJO));

        // Verify key ID.
        if (!KeyId[keyId])
            throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID, keyId);

        // Return request data.
        return new RequestData(keyId);
    };

    /**
     * <p>Symmetric key wrapped key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid", "encryptionkey", "hmackey" ],
     *   "keyid" : "string",
     *   "encryptionkey" : "base64",
     *   "hmackey" : "base64"
     * } where:
     * <ul>
     * <li>{@code keyid} identifies the key that was used to wrap the session keys</li>
     * <li>{@code encryptionkey} the Base64-encoded wrapped session encryption key</li>
     * <li>{@code hmackey} the Base64-encoded wrapped session HMAC key</li>
     * </ul></p>
     */
    var ResponseData = SymmetricWrappedExchange$ResponseData = KeyResponseData.extend({
        /**
         * Create a new symmetric key wrapped key response data instance with
         * the provided master token, specified key ID and wrapped encryption
         * and HMAC keys.
         *
         * @param {MasterToken} masterToken the master token.
         * @param {KeyId} keyId the wrapping key ID.
         * @param {Uint8Array} encryptionKey the wrapped encryption key.
         * @param {Uint8Array} hmacKey the wrapped HMAC key.
         */
        init: function init(masterToken, keyId, encryptionKey, hmacKey) {
            init.base.call(this, masterToken, KeyExchangeScheme.SYMMETRIC_WRAPPED);

            // The properties.
            var props = {
                keyId: { value: keyId, writable: false, configurable: false },
                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                hmacKey: { value: hmacKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata() {
            var keydata = {};
            keydata[KEY_KEY_ID] = this.keyId;
            keydata[KEY_ENCRYPTION_KEY] = base64$encode(this.encryptionKey);
            keydata[KEY_HMAC_KEY] = base64$encode(this.hmacKey);
            return keydata;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof SymmetricWrappedExchange$ResponseData)) return false;
            return equals.base.call(this, that) && this.keyId == that.keyId &&
                Arrays$equal(this.encryptionKey, that.encryptionKey) &&
                Arrays$equal(this.hmacKey, that.hmacKey);
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return uniqueKey.base.call(this) + ':' + this.keyId +
                ':' + Arrays$hashCode(this.encryptionKey) +
                ':' + Arrays$hashCode(this.hmacKey);
        },
    });

    /**
     * Create a new symmetric key wrapped key response data instance with
     * the provided master token from the provided JSON object.
     *
     * @param {MasterToken} masterToken the master token.
     * @param {Object} keyDataJO the JSON object.
     * @return {ResponseData} the response data.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if an encoded key is invalid.
     * @throws MslKeyExchangeException if the key ID is not recognized.
     */
    var ResponseData$parse = SymmetricWrappedExchange$ResponseData$parse = function ResponseData$parse(masterToken, keyDataJO) {
        // Pull key response data.
        var keyId = keyDataJO[KEY_KEY_ID];
        var encryptionKeyB64 = keyDataJO[KEY_ENCRYPTION_KEY];
        var hmacKeyB64 = keyDataJO[KEY_HMAC_KEY];

        // Verify key response data.
        if (!keyId || typeof keyId !== 'string' ||
            !encryptionKeyB64 || typeof encryptionKeyB64 !== 'string' ||
            !hmacKeyB64 || typeof hmacKeyB64 !== 'string')
        {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + JSON.stringify(keyDataJO));
        }

        // Verify key ID.
        if (!KeyId[keyId])
            throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID, keyId);

        // Decode keys.
        var encryptionKey;
        try {
            encryptionKey = base64$decode(encryptionKeyB64);
        } catch (e) {
            throw new MslCryptoException(MslError.INVALID_ENCRYPTION_KEY, "keydata " + JSON.stringify(keyDataJO), e);
        }
        var hmacKey;
        try {
            hmacKey = base64$decode(hmacKeyB64);
        } catch (e) {
            throw new MslCryptoException(MslError.INVALID_HMAC_KEY, "keydata " + JSON.stringify(keyDataJO), e);
        }

        // Return the response data.
        return new ResponseData(masterToken, keyId, encryptionKey, hmacKey);
    };

    /**
     * Create the crypto context identified by the key ID.
     *
     * @param {MslContext} ctx MSL context.
     * @param {KeyId} keyId the key ID.
     * @param {?MasterToken} the existing master token, which may be null.
     * @param {?string} the entity identity.
     * @param {{result: function(ICryptoContext}, error: function(Error)}}
     *        callback the callback that will receive the crypto context or any
     *        thrown exceptions.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslKeyExchangeException if the key ID is unsupported or a
     *         master token is required.
     * @throws MslEntityAuthException if there is an problem with the master
     *         token identity.
     */
    function createCryptoContext(ctx, keyId, masterToken, identity, callback) {
        AsyncExecutor(callback, function() {
            switch (keyId) {
            case KeyId.SESSION:
            {
                // If the master token is null session wrapped is unsupported.
                if (!masterToken)
                    throw new MslKeyExchangeException(MslError.KEYX_MASTER_TOKEN_MISSING, keyId);

                // Use a stored master token crypto context if we have one.
                var cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);
                if (cachedCryptoContext)
                    return cachedCryptoContext;

                // If there was no stored crypto context try making one from
                // the master token. We can only do this if we can open up the
                // master token.
                if (!masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
                var cryptoContext = new SessionCryptoContext(ctx, masterToken);
                return cryptoContext;
            }
            case KeyId.PSK:
            {
                var authdata = new PresharedAuthenticationData(identity);
                var factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                if (!factory)
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_KEY_ID, keyId);
                return factory.getCryptoContext(ctx, authdata);
            }
            default:
                throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_KEY_ID, keyId);
            }
        });
    }

    SymmetricWrappedExchange = KeyExchangeFactory.extend({
        /**
         * Create a new symmetric wrapped key exchange factory.
         */
        init: function init() {
            init.base.call(this, KeyExchangeScheme.SYMMETRIC_WRAPPED);
        },

        /** @inheritDoc */
        createRequestData: function createRequestData(ctx, keyRequestJO, callback) {
            AsyncExecutor(callback, function() {
                return RequestData$parse(keyRequestJO);
            }, this);
        },

        /** @inheritDoc */
        createResponseData: function createResponseData(ctx, masterToken, keyDataJO) {
            return ResponseData$parse(masterToken, keyDataJO);
        },

        /** @inheritDoc */
        generateResponse: function generateResponse(ctx, keyRequestData, entityToken, callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                if (!(keyRequestData instanceof RequestData))
                    throw new MslInternalException("Key request data " + JSON.stringify(keyRequestData) + " was not created by this factory.");

                // Create random AES-128 encryption and SHA-256 HMAC keys.
                this.generateSessionKeys(ctx, {
                    result: function(sessionkeys) {
                        var encryptionKey = sessionkeys.encryptionKey;
                        var hmacKey = sessionkeys.hmacKey;
                        wrapKeys(encryptionKey, hmacKey);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException && entityToken instanceof MasterToken)
                                e.setEntity(entityToken);
                            throw e;
                        }, self);
                    }
                });
            }, self);

            function wrapKeys(encryptionKey, hmacKey) {
                AsyncExecutor(callback, function() {
                    var request = keyRequestData;

                    // If we are renewing a master token then pull the identity
                    // from the master token. Otherwise we were provided the
                    // identity and will be issuing a new master token.
                    var masterToken, identity;
                    if (typeof entityToken !== 'string') {
                        // If the master token was not issued by the local entity then we
                        // should not be generating a key response for it.
                        if (!entityToken.isVerified())
                            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, entityToken);

                        masterToken = entityToken;
                        identity = masterToken.identity;
                    } else {
                        masterToken = null;
                        identity = entityToken;
                    }

                    // Wrap session keys with identified key.
                    var keyId = request.keyId;
                    createCryptoContext(ctx, keyId, masterToken, identity, {
                        result: function(wrapCryptoContext) {
                            wrapCryptoContext.wrap(encryptionKey, {
                                result: function(wrappedEncryptionKey) {
                                    wrapCryptoContext.wrap(hmacKey, {
                                        result: function(wrappedHmacKey) {
                                            createMasterToken(encryptionKey, wrappedEncryptionKey, hmacKey, wrappedHmacKey);
                                        },
                                        error: function(e) {
                                            AsyncExecutor(callback, function() {
                                                if (e instanceof MslException)
                                                    e.setEntity(masterToken);
                                                throw e;
                                            }, self);
                                        }
                                    });
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (e instanceof MslException)
                                            e.setEntity(masterToken);
                                        throw e;
                                    }, self);
                                }
                            });
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException)
                                    e.setEntity(masterToken);
                                throw e;
                            }, self);
                        }
                    });
                }, self);
            }

            function createMasterToken(encryptionKey, wrappedEncryptionKey, hmacKey, wrappedHmacKey) {
                AsyncExecutor(callback, function() {
                    var request = keyRequestData;

                    // Create the master token.
                    var tokenFactory = ctx.getTokenFactory();
                    if (entityToken instanceof MasterToken) {
                        tokenFactory.renewMasterToken(ctx, entityToken, encryptionKey, hmacKey, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create crypto context.
                                    var cryptoContext;
                                    try {
                                        cryptoContext = new SessionCryptoContext(ctx, masterToken);
                                    } catch (e) {
                                        if (e instanceof MslMasterTokenException)
                                            throw new MslInternalException("Master token constructed by token factory is not trusted.", e);
                                        if (e instanceof MslException)
                                            e.setEntity(entityToken);
                                        throw e;
                                    }

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, request.keyId, wrappedEncryptionKey, wrappedHmacKey);
                                    return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext);
                                }, self);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException)
                                        e.setEntity(entityToken);
                                    throw e;
                                }, self);
                            }
                        });
                    } else {
                        tokenFactory.createMasterToken(ctx, entityToken, encryptionKey, hmacKey, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create crypto context.
                                    var cryptoContext;
                                    try {
                                        cryptoContext = new SessionCryptoContext(ctx, masterToken);
                                    } catch (e) {
                                        if (e instanceof MslMasterTokenException)
                                            throw new MslInternalException("Master token constructed by token factory is not trusted.", e);
                                        throw e;
                                    }

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, request.keyId, wrappedEncryptionKey, wrappedHmacKey);
                                    return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext);
                                }, self);
                            },
                            error: callback.error,
                        });
                    }
                }, self);
            }
        },

        /** @inheritDoc */
        getCryptoContext: function getCryptoContext(ctx, keyRequestData, keyResponseData, masterToken, callback) {
            var self = this;
            var entityAuthData;

            AsyncExecutor(callback, function() {
                if (!(keyRequestData instanceof RequestData))
                    throw new MslInternalException("Key request data " + JSON.stringify(keyRequestData) + " was not created by this factory.");
                var request = keyRequestData;
                if (!(keyResponseData instanceof ResponseData))
                    throw new MslInternalException("Key response data " + JSON.stringify(keyResponseData) + " was not created by this factory.");
                var response = keyResponseData;

                // Verify response matches request.
                var requestKeyId = request.keyId;
                var responseKeyId = response.keyId;
                if (requestKeyId != responseKeyId)
                    throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestKeyId + "; response " + responseKeyId).setEntity(masterToken);

                // Unwrap session keys with identified key.
                ctx.getEntityAuthenticationData(null, {
                    result: function(ead) {
                        AsyncExecutor(callback, function() {
                            entityAuthData = ead;
                            var identity = entityAuthData.getIdentity();
                            createCryptoContext(ctx, responseKeyId, masterToken, identity, {
                                result: function(unwrapCryptoContext) {
                                    unwrapCryptoContext.unwrap(response.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                                        result: function(encryptionKey) {
                                            unwrapCryptoContext.unwrap(response.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                                                result: function(hmacKey) {
                                                    // Create crypto context.
                                                    ctx.getEntityAuthenticationData(null, {
                                                        result: function(entityAuthData) {
                                                            AsyncExecutor(callback, function() {
                                                                var identity = entityAuthData.getIdentity();
                                                                var responseMasterToken = response.masterToken;
                                                                return new SessionCryptoContext(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
                                                            }, self);
                                                        },
                                                        error: handleError,
                                                    });
                                                },
                                                error: handleError,
                                            });
                                        },
                                        error: handleError,
                                    });
                                },
                                error: handleError,
                            });
                        }, self);
                    },
                    error: handleError,
                });
            }, self);
            
            function handleError(e) {
                AsyncExecutor(callback, function() {
                    if (e instanceof MslException) {
                        e.setEntity(masterToken);
                        e.setEntity(entityAuthData);
                    }
                    throw e;
                }, self);
            }
        },
    });
})();

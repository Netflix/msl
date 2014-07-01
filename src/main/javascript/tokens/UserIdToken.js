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
 * <p>A user ID token provides proof of user identity. While there can be
 * multiple versions of a user ID token, this class should encapsulate support
 * for all of those versions.</p>
 *
 * <p>User ID tokens are bound to a specific master token by the master token's
 * serial number.</p>
 *
 * <p>The renewal window indicates the time after which the user ID token will
 * be renewed if requested by the entity. The expiration is the time after
 * which the user ID token will be renewed no matter what.</p>
 *
 * <p>User ID tokens are represented as
 * {@code
 * useridtoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the Base64-encoded user ID token data (usertokendata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the user ID token data</li>
 * </ul>
 *
 * <p>The token data is represented as
 * {@code
 * usertokendata = {
 *   "#mandatory" : [ "renewalwindow", "expiration", "mtserialnumber", "serialnumber", "userdata" ],
 *   "renewalwindow" : "int64(0,-)",
 *   "expiration" : "int64(0,-)",
 *   "mtserialnumber" : "int64(0,2^53^)",
 *   "serialnumber" : "int64(0,2^53^)",
 *   "userdata" : "base64"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code mtserialnumber} is the master token serial number</li>
 * <li>{@code serialnumber} is the user ID token serial number</li>
 * <li>{@code userdata} is the Base64-encoded encrypted user data (userdata)</li>
 * </ul></p>
 *
 * <p>The decrypted user data is represented as
 * {@code
 * userdata = {
 *   "#mandatory" : [ "user" ],
 *   "issuerdata" : object,
 *   "identity" : "string"
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the user ID token issuer data</li>
 * <li>{@code identity} is the encoded user identity data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var UserIdToken;
var UserIdToken$create;
var UserIdToken$parse;

(function() {
    /** Milliseconds per second.
     * @const
     * @type {number}
     */
    var MILLISECONDS_PER_SECOND = 1000;

    /**
     * JSON key token data.
     * @const
     * @type {string}
     */
    var KEY_TOKENDATA = "tokendata";
    /**
     * JSON key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    // tokendata
    /**
     * JSON key renewal window timestamp.
     * @const
     * @type {string}
     */
    var KEY_RENEWAL_WINDOW = "renewalwindow";
    /**
     * JSON key expiration timestamp.
     * @const
     * @type {string}
     */
    var KEY_EXPIRATION = "expiration";
    /**
     * JSON key master token serial number.
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /**
     * JSON key user ID token serial number.
     * @const
     * @type {string}
     */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /**
     * JSON key token user data.
     * @const
     * @type {string}
     */
    var KEY_USERDATA = "userdata";

    // userdata
    /**
     * JSON key issuer data.
     * @const
     * @type {string}
     */
    var KEY_ISSUER_DATA = "issuerdata";
    /**
     * JSON key identity.
     * @const
     * @type {string}
     */
    var KEY_IDENTITY = "identity";

    /**
     * Create a new token data container object.
     *
     * @param {Uint8Array} tokendata raw token data.
     * @param {Uint8Array} signature raw signature.
     * @param {boolean} verified true if verified.
     * @constructor
     */
    function CreationData(tokendata, signature, verified) {
        this.tokendata = tokendata;
        this.signature = signature;
        this.verified = verified;
    };

    UserIdToken = util.Class.create({
        /**
         * Create a new user ID token with the specified user.
         *
         * @param {MslContext} ctx MSL context.
         * @param {Date} renewalWindow the renewal window.
         * @param {Date} expiration the expiration.
         * @param {MasterToken} masterToken the master token.
         * @param {number} serialNumber the user ID token serial number.
         * @param {?Object} the issuer data. May be null.
         * @param {MslUser} user the MSL user.
         * @param {?CreationData} creationData optional creation data.
         * @param {{result: function(UserIdToken), error: function(Error)}}
         *        callback the callback functions that will receive the user ID token
         *        or any thrown exceptions.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         */
        init: function init(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, creationData, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // The expiration must appear after the renewal window.
                if (expiration.getTime() < renewalWindow.getTime())
                    throw new MslInternalException("Cannot construct a user ID token that expires before its renewal window opens.");
                // A master token must be provided.
                if (!masterToken)
                    throw new MslInternalException("Cannot construct a user ID token without a master token.");
                // The serial number must be within range.
                if (serialNumber < 0 || serialNumber > MslConstants$MAX_LONG_VALUE)
                    throw new MslInternalException("Serial number " + serialNumber + " is outside the valid range.");

                // Renewal window and expiration are in seconds, not milliseconds.
                var renewalWindowSeconds = Math.floor(renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
                var expirationSeconds = Math.floor(expiration.getTime() / MILLISECONDS_PER_SECOND);

                // Extract master token serial number.
                var mtSerialNumber = masterToken.serialNumber;

                // Construct the token data.
                if (!creationData) {
                    // Construct the user data.
                    var userData = {};
                    if (issuerData)
                        userData[KEY_ISSUER_DATA] = issuerData;
                    userData[KEY_IDENTITY] = user.getEncoded();
                    var userdata = textEncoding$getBytes(JSON.stringify(userData), MslConstants$DEFAULT_CHARSET);

                    // Encrypt the user data.
                    var cryptoContext = ctx.getMslCryptoContext();
                    cryptoContext.encrypt(userdata, {
                        result: function(ciphertext) {
                            AsyncExecutor(callback, function() {
                                // Construct the token data.
                                var tokenDataJO = {};
                                tokenDataJO[KEY_RENEWAL_WINDOW] = renewalWindowSeconds;
                                tokenDataJO[KEY_EXPIRATION] = expirationSeconds;
                                tokenDataJO[KEY_MASTER_TOKEN_SERIAL_NUMBER] = mtSerialNumber;
                                tokenDataJO[KEY_SERIAL_NUMBER] = serialNumber;
                                tokenDataJO[KEY_USERDATA] = base64$encode(ciphertext);
                                var tokendata = textEncoding$getBytes(JSON.stringify(tokenDataJO), MslConstants$DEFAULT_CHARSET);

                                // Sign the token data.
                                cryptoContext.sign(tokendata, {
                                    result: function(signature) {
                                        AsyncExecutor(callback, function() {
                                            var verified = true;

                                            // The properties.
                                            var mtSerialNumber = masterToken.serialNumber;
                                            var props = {
                                                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                                                renewalWindowSeconds: { value: renewalWindowSeconds, writable: false, enumerable: false, configurable: false },
                                                expirationSeconds: { value: expirationSeconds, writable: false, enumerable: false, configurable: false },
                                                mtSerialNumber: { value: mtSerialNumber, writable: false, configurable: false },
                                                serialNumber: { value: serialNumber, writable: false, configurable: false },
                                                issuerData: { value: issuerData, writable: false, configurable: false },
                                                user: { value: user, writable: false, configurable: false },
                                                verified: { value: verified, writable: false, enumerable: false, configurable: false },
                                                tokendata: { value: tokendata, writable: false, enumerable: false, configurable: false },
                                                signature: { value: signature, writable: false, enumerable: false, configurable: false }
                                            };
                                            Object.defineProperties(this, props);
                                            return this;
                                        }, self);
                                    },
                                    error: function(e) {
                                        AsyncExecutor(callback, function() {
                                            if (e instanceof MslException)
                                                e.setEntity(masterToken);
                                            throw e;
                                        }, self);
                                    },
                                });
                            }, self);
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException)
                                    e.setEntity(masterToken);
                                throw e;
                            }, self);
                        },
                    });
                } else {
                    var tokendata = creationData.tokendata;
                    var signature = creationData.signature;
                    var verified = creationData.verified;

                    // The properties.
                    var mtSerialNumber = masterToken.serialNumber;
                    var props = {
                        ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                        renewalWindowSeconds: { value: renewalWindowSeconds, writable: false, enumerable: false, configurable: false },
                        expirationSeconds: { value: expirationSeconds, writable: false, enumerable: false, configurable: false },
                        mtSerialNumber: { value: mtSerialNumber, writable: false, configurable: false },
                        serialNumber: { value: serialNumber, writable: false, configurable: false },
                        issuerData: { value: issuerData, writable: false, configurable: false },
                        user: { value: user, writable: false, configurable: false },
                        verified: { value: verified, writable: false, enumerable: false, configurable: false },
                        tokendata: { value: tokendata, writable: false, enumerable: false, configurable: false },
                        signature: { value: signature, writable: false, enumerable: false, configurable: false }
                    };
                    Object.defineProperties(this, props);
                    return this;
                }
            }, this);
        },

        /**
        * @return {Date} gets the renewal window.
        */
        get renewalWindow() {
            return new Date(this.renewalWindowSeconds * MILLISECONDS_PER_SECOND);
        },

        /**
        * @return {Date} gets the expiration.
        */
        get expiration() {
            return new Date(this.expirationSeconds * MILLISECONDS_PER_SECOND);
        },

        /**
         * @return {boolean} true if the token has been verified.
         */
        isVerified: function isVerified() {
            return this.verified;
        },

        /**
         * @return {boolean} true if the decrypted content is available. (Implies verified.)
         */
        isDecrypted: function isDecrypted() {
            return (this.user) ? true : false;
        },

        /**
         * Always returns true if this token was issued by a different entity
         * because we cannot know if the local entity time is correct.
         *
         * If this token was issued by the local entity then we assume its
         * clock at that time is in sync with the clock now.
         *
         * @return {boolean} true if the renewal window has been entered.
         */
        isRenewable: function isRenewable() {
            return this.renewalWindow.getTime() <= this.ctx.getTime();
        },

        /**
         * Always returns false if this token was issued by a different entity
         * because we cannot know if the local entity time is correct.
         *
         * If this token was issued by the local entity then we assume its
         * clock at that time is in sync with the clock now.
         *
         * @return {boolean} true if expired.
         */
        isExpired: function isExpired() {
            return this.expiration.getTime() <= this.ctx.getTime();
        },

        /**
         * @param {MasterToken} masterToken master token. May be null.
         * @return {boolean} true if this token is bound to the provided master token.
         */
        isBoundTo: function isBoundTo(masterToken) {
            return (masterToken && masterToken.serialNumber == this.mtSerialNumber);
        },

        /** @inheritDoc */
        toJSON: function toJSON() {
            var jsonObj = {};
            jsonObj[KEY_TOKENDATA] = base64$encode(this.tokendata);
            jsonObj[KEY_SIGNATURE] = base64$encode(this.signature);
            return jsonObj;
        },

        /**
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a user ID token with the same serial
         *         number bound to the same master token.
         * @see #uniqueKey()
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof UserIdToken)) return false;
            return this.serialNumber == that.serialNumber && this.mtSerialNumber == that.mtSerialNumber;
        },

        /**
         * @return {string} a string that uniquely identifies this master token.
         * @see #equals(that)
         */
        uniqueKey: function uniqueKey() {
            return this.serialNumber + ':' + this.mtSerialNumber;
        },
    });

    /**
     * Create a new user ID token with the specified user.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Date} renewalWindow the renewal window.
     * @param {Date} expiration the expiration.
     * @param {MasterToken} masterToken the master token.
     * @param {number} serialNumber the user ID token serial number.
     * @param {?Object} the issuer data. May be null.
     * @param {MslUser} user the MSL user.
     * @param {{result: function(UserIdToken), error: function(Error)}}
     *        callback the callback functions that will receive the user ID token
     *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    UserIdToken$create = function UserIdToken$create(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, callback) {
        new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, null, callback);
    };

    /**
     * Create a new user ID token from the provided JSON object. The associated
     * master token must be provided to verify the user ID token.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Object} userIdTokenJO user ID token JSON object.
     * @param {MasterToken} masterToken the master token.
     * @param {{result: function(UserIdToken), error: function(Error)}}
     *        callback the callback functions that will receive the user ID token
     *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error verifying the token
     *         data.
     * @throws MslException if the user ID token master token serial number
     *         does not match the master token serial number, or the expiration
     *         timestamp occurs before the renewal window, or the user data is
     *         missing.
     */
    UserIdToken$parse = function UserIdToken$parse(ctx, userIdTokenJO, masterToken, callback) {
        AsyncExecutor(callback, function() {
            // Grab the crypto context.
            var cryptoContext = ctx.getMslCryptoContext();

            // Verify the JSON representation.
            var tokendataB64 = userIdTokenJO[KEY_TOKENDATA];
            var signatureB64 = userIdTokenJO[KEY_SIGNATURE];
            if (typeof tokendataB64 !== 'string' || typeof signatureB64 !== 'string')
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "useridtoken " + JSON.stringify(userIdTokenJO)).setEntity(masterToken);
            var tokendata, signature;
            try {
                tokendata = base64$decode(tokendataB64);
            } catch (e) {
                throw new MslException(MslError.USERIDTOKEN_TOKENDATA_INVALID, "useridtoken " + JSON.stringify(userIdTokenJO), e).setEntity(masterToken);
            }
            if (!tokendata || tokendata.length == 0)
                throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_MISSING, "useridtoken " + JSON.stringify(userIdTokenJO)).setEntity(masterToken);
            try {
                signature = base64$decode(signatureB64);
            } catch (e) {
                throw new MslException(MslError.USERIDTOKEN_TOKENDATA_INVALID, "useridtoken " + JSON.stringify(userIdTokenJO), e).setEntity(masterToken);
            }
            cryptoContext.verify(tokendata, signature, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        // Pull the token data.
                        var renewalWindowSeconds, expirationSeconds, mtSerialNumber, serialNumber, ciphertextB64;
                        var tokenDataJson = textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET);
                        try {
                            var tokenDataJO = JSON.parse(tokenDataJson);
                            renewalWindowSeconds = parseInt(tokenDataJO[KEY_RENEWAL_WINDOW]);
                            expirationSeconds = parseInt(tokenDataJO[KEY_EXPIRATION]);
                            mtSerialNumber = parseInt(tokenDataJO[KEY_MASTER_TOKEN_SERIAL_NUMBER]);
                            serialNumber = parseInt(tokenDataJO[KEY_SERIAL_NUMBER]);
                            ciphertextB64 = tokenDataJO[KEY_USERDATA];
                        } catch (e) {
                            if (e instanceof SyntaxError)
                                throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR, "usertokendata " + tokenDataJson, e).setEntity(masterToken);
                            throw e;
                        }

                        // Verify token data.
                        if (!renewalWindowSeconds || renewalWindowSeconds != renewalWindowSeconds ||
                            !expirationSeconds || expirationSeconds != expirationSeconds ||
                            typeof mtSerialNumber !== 'number' || mtSerialNumber != mtSerialNumber ||
                            typeof serialNumber !== 'number' || serialNumber != serialNumber ||
                            typeof ciphertextB64 !== 'string')
                        {
                            throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR, "usertokendata " + tokenDataJson).setEntity(masterToken);
                        }
                        if (expirationSeconds < renewalWindowSeconds)
                            throw new MslException(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL, "mastertokendata " + tokenDataJson).setEntity(masterToken);

                        // Verify serial number values.
                        if (mtSerialNumber < 0 || mtSerialNumber > MslConstants$MAX_LONG_VALUE)
                            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokenDataJson).setEntity(masterToken);
                        if (serialNumber < 0 || serialNumber > MslConstants$MAX_LONG_VALUE)
                            throw new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokenDataJson).setEntity(masterToken);

                        // Convert dates.
                        var renewalWindow = new Date(renewalWindowSeconds * MILLISECONDS_PER_SECOND);
                        var expiration = new Date(expirationSeconds * MILLISECONDS_PER_SECOND);

                        // Verify serial numbers.
                        if (!masterToken || mtSerialNumber != masterToken.serialNumber)
                            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + mtSerialNumber + "; mt " + JSON.stringify(masterToken)).setEntity(masterToken);

                        // Construct user data.
                        var ciphertext;
                        try {
                            ciphertext = base64$decode(ciphertextB64);
                        } catch (e) {
                            throw new MslException(MslError.USERIDTOKEN_USERDATA_INVALID, ciphertextB64, e).setEntity(masterToken);
                        }
                        if (!ciphertext || ciphertext.length == 0)
                            throw new MslException(MslError.USERIDTOKEN_USERDATA_MISSING, ciphertextB64).setEntity(masterToken);
                        if (verified) {
                            cryptoContext.decrypt(ciphertext, {
                                result: function(userdata) {
                                    AsyncExecutor(callback, function() {
                                        // Pull the user data.
                                        var issuerData, identity;
                                        var userdataJson = textEncoding$getString(userdata, MslConstants$DEFAULT_CHARSET);
                                        try {
                                            var userdataJO = JSON.parse(userdataJson);
                                            issuerData = userdataJO[KEY_ISSUER_DATA];
                                            identity = userdataJO[KEY_IDENTITY];
                                        } catch (e) {
                                            if (e instanceof SyntaxError)
                                                throw new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR, "userdata " + userdataJson).setEntity(masterToken);
                                            throw e;
                                        }

                                        // Verify user data.
                                        if (issuerData && typeof issuerData !== 'object' ||
                                            typeof identity !== 'string')
                                        {
                                            throw new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR, "userdata " + userdataJson).setEntity(masterToken);
                                        }
                                        if (!identity || identity.length == 0)
                                            throw new MslException(MslError.USERIDTOKEN_IDENTITY_INVALID, "userdata " + userdataJson).setEntity(masterToken);
                                        
                                        // Reconstruct the user.
                                        var factory = ctx.getTokenFactory();
                                        factory.createUser(ctx, identity, {
                                            result: function(user) {
                                                AsyncExecutor(callback, function() {
                                                    if (!user)
                                                        throw new MslInternalException("TokenFactory.createUser() returned null in violation of the interface contract.");
                                                    
                                                    // Return the new user ID token.
                                                    var creationData = new CreationData(tokendata, signature, verified);
                                                    new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, creationData, callback);
                                                });
                                            },
                                            error: function(e) {
                                                AsyncExecutor(callback, function() {
                                                    if (e instanceof MslException)
                                                        e.setEntity(masterToken);
                                                    throw e;
                                                });
                                            },
                                        });
                                    });
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (e instanceof MslException)
                                            e.setEntity(masterToken);
                                        throw e;
                                    });
                                },
                            });
                        } else {
                            var issuerData = null;
                            var user = null;

                            // Return the new user ID token.
                            var creationData = new CreationData(tokendata, signature, verified);
                            new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, creationData, callback);
                        }
                    });
                },
                error: function(e) {
                    AsyncExecutor(callback, function() {
                        if (e instanceof MslException)
                            e.setEntity(masterToken);
                        throw e;
                    });
                },
            });
        });
    };
})();


/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the user ID token data (usertokendata)</li>
 * <li>{@code signature} is the verification data of the user ID token data</li>
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
 *   "userdata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code mtserialnumber} is the master token serial number</li>
 * <li>{@code serialnumber} is the user ID token serial number</li>
 * <li>{@code userdata} is the encrypted user data (userdata)</li>
 * </ul></p>
 *
 * <p>The decrypted user data is represented as
 * {@code
 * userdata = {
 *   "#mandatory" : [ "identity" ],
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
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslConstants = require('../MslConstants.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslException = require('../MslException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	var Base64 = require('../util/Base64.js');
	
    /** Milliseconds per second.
     * @const
     * @type {number}
     */
    var MILLISECONDS_PER_SECOND = 1000;

    /**
     * Key token data.
     * @const
     * @type {string}
     */
    var KEY_TOKENDATA = "tokendata";
    /**
     * Key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    // tokendata
    /**
     * Key renewal window timestamp.
     * @const
     * @type {string}
     */
    var KEY_RENEWAL_WINDOW = "renewalwindow";
    /**
     * Key expiration timestamp.
     * @const
     * @type {string}
     */
    var KEY_EXPIRATION = "expiration";
    /**
     * Key master token serial number.
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /**
     * Key user ID token serial number.
     * @const
     * @type {string}
     */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /**
     * Key token user data.
     * @const
     * @type {string}
     */
    var KEY_USERDATA = "userdata";

    // userdata
    /**
     * Key issuer data.
     * @const
     * @type {string}
     */
    var KEY_ISSUER_DATA = "issuerdata";
    /**
     * Key identity.
     * @const
     * @type {string}
     */
    var KEY_IDENTITY = "identity";

    /**
     * Create a new token data container object.
     *
     * @param {MslObject} userdata user data.
     * @param {Uint8Array} tokendataBytes raw token data.
     * @param {Uint8Array} signatureBytes raw signature.
     * @param {boolean} verified true if verified.
     * @constructor
     */
    function CreationData(userdata, tokendataBytes, signatureBytes, verified) {
        this.userdata = userdata;
        this.tokendataBytes = tokendataBytes;
        this.signatureBytes = signatureBytes;
        this.verified = verified;
    }

    var UserIdToken = module.exports = MslEncodable.extend({
        /**
         * Create a new user ID token with the specified user.
         *
         * @param {MslContext} ctx MSL context.
         * @param {Date} renewalWindow the renewal window.
         * @param {Date} expiration the expiration.
         * @param {MasterToken} masterToken the master token.
         * @param {number} serialNumber the user ID token serial number.
         * @param {?MslObject} the issuer data. May be null.
         * @param {MslUser} user the MSL user.
         * @param {?CreationData} creationData optional creation data.
         * @throws MslEncodingException if there is an error encoding the data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         */
        init: function init(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, creationData) {
            // The expiration must appear after the renewal window.
            if (expiration.getTime() < renewalWindow.getTime())
                throw new MslInternalException("Cannot construct a user ID token that expires before its renewal window opens.");
            // A master token must be provided.
            if (!masterToken)
                throw new MslInternalException("Cannot construct a user ID token without a master token.");
            // The serial number must be within range.
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslInternalException("Serial number " + serialNumber + " is outside the valid range.");

            // Renewal window and expiration are in seconds, not milliseconds.
            var renewalWindowSeconds = Math.floor(renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
            var expirationSeconds = Math.floor(expiration.getTime() / MILLISECONDS_PER_SECOND);

            // Extract master token serial number.
            var mtSerialNumber = masterToken.serialNumber;

            // Construct the token data.
            var userdata, tokendataBytes, signatureBytes, verified;
            if (!creationData) {
                // Construct the user data.
                var encoder = ctx.getMslEncoderFactory();
                userdata = encoder.createObject();
                if (issuerData)
                    userdata.put(KEY_ISSUER_DATA, issuerData);
                userdata.put(KEY_IDENTITY, user.getEncoded());
                
                tokendataBytes = null;
                signatureBytes = null;
                verified = true;
            } else {
                userdata = creationData.userdata;
                tokendataBytes = creationData.tokendataBytes;
                signatureBytes = creationData.signatureBytes;
                verified = creationData.verified;
            }

            // The properties.
            var props = {
                /**
                 * MSL context.
                 * @type {MslContext}
                 */
                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                /**
                 * User ID token renewal window in seconds since the epoch.
                 * @type {number}
                 */
                renewalWindowSeconds: { value: renewalWindowSeconds, writable: false, enumerable: false, configurable: false },
                /**
                 * User ID token expiration in seconds since the epoch.
                 * @type {number}
                 */
                expirationSeconds: { value: expirationSeconds, writable: false, enumerable: false, configurable: false },
                /**
                 * Master token serial number.
                 * @type {number}
                 */
                mtSerialNumber: { value: mtSerialNumber, writable: false, configurable: false },
                /**
                 * Serial number.
                 * @type {number}
                 */
                serialNumber: { value: serialNumber, writable: false, configurable: false },
                /**
                 * User data.
                 * @type {MslObject}
                 */
                userdata: { value: userdata, writable: false, enumerable: false, configurable: false },
                /**
                 * Issuer data.
                 * @type {MslObject}
                 */
                issuerData: { value: issuerData, writable: false, configurable: false },
                /**
                 * MSL user.
                 * @type {MslUser}
                 */
                user: { value: user, writable: false, configurable: false },
                /**
                 * Token data bytes.
                 * @type {Uint8Array}
                 */
                tokendataBytes: { value: tokendataBytes, writable: false, enumerable: false, configurable: false },
                /**
                 * Signature bytes.
                 * @type {Uint8Array}
                 */
                signatureBytes: { value: signatureBytes, writable: false, enumerable: false, configurable: false },
                /**
                 * Token is verified.
                 * @type {boolean}
                 */
                verified: { value: verified, writable: false, enumerable: false, configurable: false },
                /**
                 * Cached encodings.
                 * @type {Object<MslEncoderFormat,Uint8Array>}
                 */
                encodings: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {boolean} true if the decrypted content is available. (Implies verified.)
         */
        isDecrypted: function isDecrypted() {
            return (this.user) ? true : false;
        },

        /**
         * @return {boolean} true if the token has been verified.
         */
        isVerified: function isVerified() {
            return this.verified;
        },

        /**
        * @return {Date} gets the renewal window.
        */
        get renewalWindow() {
            return new Date(this.renewalWindowSeconds * MILLISECONDS_PER_SECOND);
        },

        /**
         * <p>Returns true if the user ID token renewal window has been entered.</p>
         *
         * <ul>
         * <li>If a time is provided the renewal window value will be compared
         * against the provided time.</li>
         * <li>If the user ID token was issued by the local entity the renewal
         * window value will be compared against the local entity time. We assume
         * its clock at the time of issuance is in sync with the clock now.</li>
         * <li>Otherwise the user ID token is considered renewable under the
         * assumption that the local time is not synchronized with the master token
         * issuing entity time.</li>
         * </ul>
         *
         * @param {?Date} now the time to compare against.
         * @return {boolean} true if the renewal window has been entered.
         */
        isRenewable: function isRenewable(now) {
            if (now)
                return this.renewalWindow.getTime() <= now.getTime();
            if (this.isVerified())
                return this.renewalWindow.getTime() <= this.ctx.getTime();
            return true;
        },

        /**
        * @return {Date} gets the expiration.
        */
        get expiration() {
            return new Date(this.expirationSeconds * MILLISECONDS_PER_SECOND);
        },

        /**
         * <p>Returns true if the user ID token is expired.</p>
         *
         * <ul>
         * <li>If a time is provided the expiration value will be compared against
         * the provided time.</li>
         * <li>If the user ID token was issued by the local entity the expiration
         * value will be compared against the local entity time. We assume
         * its clock at the time of issuance is in sync with the clock now.</li>
         * <li>Otherwise the user ID token is considered not expired under the
         * assumption that the local time is not synchronized with the token-
         * issuing entity time.</li>
         * </ul>
         *
         * @param {?Date} now the time to compare against.
         * @return {boolean} true if expired.
         */
        isExpired: function isExpired(now) {
            if (now)
                return this.expiration.getTime() <= now.getTime();
            if (this.isVerified())
                return this.expiration.getTime() <= this.ctx.getTime();
            return false;
        },

        /**
         * @param {MasterToken} masterToken master token. May be null.
         * @return {boolean} true if this token is bound to the provided master token.
         */
        isBoundTo: function isBoundTo(masterToken) {
            return (masterToken && masterToken.serialNumber == this.mtSerialNumber);
        },

        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Return any cached encoding.
                if (this.encodings[format])
                    return this.encodings[format];
                
                // If we parsed this token (i.e. did not create it from scratch) then
                // we should not re-encrypt or re-sign as there is no guarantee out MSL
                // crypto context is capable of encrypting and signing with the same
                // keys, even if it is capable of decrypting and verifying.
                if (this.tokendataBytes != null || this.signatureBytes != null) {
                    encodeToken(this.tokendataBytes, this.signatureBytes);
                }
                // 
                // Otherwise create the token data and signature.
                else {
                    // Grab the MSL token crypto context.
                    var cryptoContext;
                    try {
                        cryptoContext = this.ctx.getMslCryptoContext();
                    } catch (e) {
                        if (e instanceof MslCryptoException)
                            throw new MslEncoderException("Error creating the MSL crypto context.", e);
                        throw e;
                    }
                    
                    // Encrypt the user data.
                    encoder.encodeObject(this.userdata, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(ciphertext) {
		                            AsyncExecutor(callback, function() {
		                                // Construct the token data.
		                                var tokendata = encoder.createObject();
		                                tokendata.put(KEY_RENEWAL_WINDOW, this.renewalWindowSeconds);
		                                tokendata.put(KEY_EXPIRATION, this.expirationSeconds);
		                                tokendata.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.mtSerialNumber);
		                                tokendata.put(KEY_SERIAL_NUMBER, this.serialNumber);
		                                tokendata.put(KEY_USERDATA, ciphertext);
		                                
		                                // Sign the token data.
		                                encoder.encodeObject(tokendata, format, {
		                                	result: function(data) {
				                                cryptoContext.sign(data, encoder, format, {
				                                    result: function(signature) {
				                                        encodeToken(data, signature);
				                                    },
				                                    error: function(e) {
				                                        AsyncExecutor(callback, function() {
				                                            if (e instanceof MslCryptoException)
				                                                throw new MslEncoderException("Error signing the token data.", e);
				                                            throw e;
				                                        }, self);
				                                    }
				                                });
		                                	},
		                                	error: callback.error,
		                                });
		                            }, self);
		                        },
		                        error: function(e) {
		                            AsyncExecutor(callback, function() {
		                                if (e instanceof MslCryptoException)
		                                    throw new MslEncoderException("Error encrypting the user data.", e);
		                                throw e;
		                            }, self);
		                        }
		                    });
                    	},
                    	error: callback.error,
                    });
                }
            }, self);
            
            function encodeToken(data, signature) {
                AsyncExecutor(callback, function() {
                    // Encode the token.
                    var token = encoder.createObject();
                    token.put(KEY_TOKENDATA, data);
                    token.put(KEY_SIGNATURE, signature);
                    encoder.encodeObject(token, format, {
                    	result: function(encoding) {
                    		AsyncExecutor(callback, function() {
	                    		// Cache and return the encoding.
	                    		this.encodings[format] = encoding;
	                    		return encoding;
                    		}, self);
                    	},
                    	error: callback.error,
                    });
                }, self);
            }
        },
        
        /** @inheritDoc */
        toString: function toString() {
            var encoder = this.ctx.getMslEncoderFactory();
            
            var tokendataMo = encoder.createObject();
            tokendataMo.put(KEY_RENEWAL_WINDOW, this.renewalWindowSeconds);
            tokendataMo.put(KEY_EXPIRATION, this.expirationSeconds);
            tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.mtSerialNumber);
            tokendataMo.put(KEY_SERIAL_NUMBER, this.serialNumber);
            tokendataMo.put(KEY_USERDATA, "(redacted)");

            var mslObj = encoder.createObject();
            mslObj.put(KEY_TOKENDATA, tokendataMo);
            mslObj.put(KEY_SIGNATURE, (this.signatureBytes) ? this.signatureBytes : "(null)");
            return mslObj.toString();
        },

        /**
         * <p>Returns true if the other object is a user ID token with the same
         * serial number bound to the same master token.</p>
         * 
         * <p>This function is designed for use with sets and maps to guarantee
         * uniqueness of individual user ID tokens.</p>
         * 
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
    var UserIdToken$create = function UserIdToken$create(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, callback) {
    	AsyncExecutor(callback, function() {
    		return new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user, null);
    	});
    };

    /**
     * Create a new user ID token from the provided MSL object. The associated
     * master token must be provided to verify the user ID token.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} userIdTokenMo user ID token MSL object.
     * @param {MasterToken} masterToken the master token.
     * @param {{result: function(UserIdToken), error: function(Error)}}
     *        callback the callback functions that will receive the user ID token
     *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error verifying the token
     *         data.
     * @throws MslException if the user ID token master token serial number
     *         does not match the master token serial number, or the expiration
     *         timestamp occurs before the renewal window, or the user data is
     *         missing.
     */
    var UserIdToken$parse = function UserIdToken$parse(ctx, userIdTokenMo, masterToken, callback) {
        AsyncExecutor(callback, function() {
            // Grab the crypto context and encoder.
            var cryptoContext = ctx.getMslCryptoContext();
            var encoder = ctx.getMslEncoderFactory();

            // Verify the encoding.
            var tokendataBytes, signatureBytes, verified;
            try {
                tokendataBytes = userIdTokenMo.getBytes(KEY_TOKENDATA);
                if (tokendataBytes.length == 0)
                    throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_MISSING, "useridtoken " + userIdTokenMo).setMasterToken(masterToken);
                signatureBytes = userIdTokenMo.getBytes(KEY_SIGNATURE);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "useridtoken " + userIdTokenMo, e).setMasterToken(masterToken);
                throw e;
            }
            cryptoContext.verify(tokendataBytes, signatureBytes, encoder, {
                result: function(verified) {
                    parseToken(encoder, cryptoContext, tokendataBytes, signatureBytes, verified);
                },
                error: callback.error,
            });
        });
        
        function parseToken(encoder, cryptoContext, tokendataBytes, signatureBytes, verified) {
            AsyncExecutor(callback, function() {
                // Pull the token data.
                var renewalWindowSeconds, expirationSeconds, mtSerialNumber, serialNumber, ciphertext;
                try {
                    var tokendata = encoder.parseObject(tokendataBytes);
                    renewalWindowSeconds = tokendata.getLong(KEY_RENEWAL_WINDOW);
                    expirationSeconds = tokendata.getLong(KEY_EXPIRATION);
                    if (expirationSeconds < renewalWindowSeconds)
                        throw new MslException(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL, "usertokendata " + tokendata).setMasterToken(masterToken);
                    mtSerialNumber = tokendata.getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
                    if (mtSerialNumber < 0 || mtSerialNumber > MslConstants.MAX_LONG_VALUE)
                        throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokendata).setMasterToken(masterToken);
                    serialNumber = tokendata.getLong(KEY_SERIAL_NUMBER);
                    if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                        throw new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokendata).setMasterToken(masterToken);
                    ciphertext = tokendata.getBytes(KEY_USERDATA);
                    if (ciphertext.length == 0)
                        throw new MslException(MslError.USERIDTOKEN_USERDATA_MISSING).setMasterToken(masterToken);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR, "usertokendata " + Base64.encode(tokendataBytes), e).setMasterToken(masterToken);
                    throw e;
                }
                if (verified) {
                    cryptoContext.decrypt(ciphertext, encoder, {
                        result: function(plaintext) {
                            parseUserdata(encoder, tokendataBytes, signatureBytes, verified,
                                renewalWindowSeconds, expirationSeconds, mtSerialNumber, serialNumber,
                                plaintext);
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslCryptoException)
                                    e.setMasterToken(masterToken);
                                throw e;
                            });
                        }
                    });
                } else {
                    createToken(tokendataBytes, signatureBytes, verified,
                       renewalWindowSeconds, expirationSeconds, mtSerialNumber, serialNumber,
                       null, null, null);
                }
            });
        }
        
        function parseUserdata(encoder, tokendataBytes, signatureBytes, verified,
                               renewalWindowSeconds, expirationSeconds, mtSerialNumber, serialNumber,
                               plaintext)
        {
            AsyncExecutor(callback, function() {
                // Pull the user data.
                var userdata, issuerdata, identity;
                try {
                    userdata = encoder.parseObject(plaintext);
                    issuerdata = (userdata.has(KEY_ISSUER_DATA)) ? userdata.getMslObject(KEY_ISSUER_DATA, encoder) : null;
                    identity = userdata.getString(KEY_IDENTITY);
                    if (!identity || identity.length == 0)
                        throw new MslException(MslError.USERIDTOKEN_IDENTITY_INVALID, "userdata " + userdata).setMasterToken(masterToken);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR, "userdata " + Base64.encode(plaintext), e).setMasterToken(masterToken);
                    throw e;
                }
                var factory = ctx.getTokenFactory();
                factory.createUser(ctx, identity, {
                    result: function(user) {
                        AsyncExecutor(callback, function() {
                            if (!user)
                                throw new MslInternalException("TokenFactory.createUser() returned null in violation of the interface contract.");
                            createToken(tokendataBytes, signatureBytes, verified,
                                renewalWindowSeconds, expirationSeconds, mtSerialNumber, serialNumber,
                                userdata, issuerdata, user);
                        });
                    },
                    error: callback.error,
                });
            });
        }
        
        function createToken(tokendataBytes, signatureBytes, verified,
                             renewalWindowSeconds, expirationSeconds, mtSerialNumber, serialNumber,
                             userdata, issuerdata, user)
        {
            AsyncExecutor(callback, function() {
                // Convert dates.
                var renewalWindow = new Date(renewalWindowSeconds * MILLISECONDS_PER_SECOND);
                var expiration = new Date(expirationSeconds * MILLISECONDS_PER_SECOND);
                
                // Verify serial numbers.
                if (!masterToken || mtSerialNumber != masterToken.serialNumber)
                    throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + mtSerialNumber + "; mt " + masterToken).setMasterToken(masterToken);

                // Return the new user ID token.
                var creationData = new CreationData(userdata, tokendataBytes, signatureBytes, verified);
                return new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerdata, user, creationData);
            });
        }
    };
    
    // Exports.
    module.exports.create = UserIdToken$create;
    module.exports.parse = UserIdToken$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('UserIdToken'));
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
 * <p>The master token provides proof of remote entity identity. A MSL-specific
 * crypto context is used to encrypt the master token data and generate the
 * master token verification data. The remote entity cannot decrypt the master
 * token data or generate the master token verification data.</p>
 *
 * <p>The master token session keys will be used for MSL message encryption and
 * integrity protection. The use of these session keys implies the MSL message
 * identity as specified in the master token.</p>
 *
 * <p>Master tokens also contain a sequence number identifying the issue number
 * of the token. This is a monotonically increasing number that is incremented
 * by one each time a master token is renewed.</p>
 *
 * <p>When in possession of multiple master tokens, the token with the highest
 * sequence number should be considered the newest token. Since the sequence
 * number space is signed 53-bit numbers, if a sequence number is smaller by
 * more than 45-bits (e.g. the new sequence number is <= 128 and the old
 * sequence number is 2^53), it is considered the newest token.</p>
 *
 * <p>The renewal window indicates the time after which the master token will
 * be renewed if requested by the entity. The expiration is the time after
 * which the master token will be renewed no matter what.</p>
 *
 * <p>Master tokens also contain a serial number against which all other tokens
 * are bound. Changing the serial number when the master token is renewed
 * invalidates all of those tokens.</p>
 *
 * <p>The issuer identity identifies the issuer of this master token, which may
 * be useful to services that accept the master token.</p>
 *
 * <p>While there can be multiple versions of a master token, this class should
 * encapsulate support for all of those versions.</p>
 *
 * <p>Master tokens are represented as
 * {@code
 * mastertoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the master token data (mastertokendata)</li>
 * <li>{@code signature} is the verification data of the master token data</li>
 * </ul></p>
 *
 * <p>The token data is represented as
 * {@code
 * mastertokendata = {
 *   "#mandatory" : [ "renewalwindow", "expiration", "sequencenumber", "serialnumber", "sessiondata" ],
 *   "renewalwindow" : "int64(0,-)",
 *   "expiration" : "int64(0,-)",
 *   "sequencenumber" : "int64(0,-)",
 *   "serialnumber" : "int64(0,-)",
 *   "sessiondata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code sequencenumber} is the master token sequence number</li>
 * <li>{@code serialnumber} is the master token serial number</li>
 * <li>{@code sessiondata} is the encrypted session data (sessiondata)</li>
 * </ul></p>
 *
 * <p>The decrypted session data is represented as
 * {@code
 * sessiondata = {
 *   "#mandatory" : [ "identity", "encryptionkey"],
 *   "#conditions" : [ "hmackey" or "signaturekey" ],
 *   "issuerdata" : object,
 *   "identity" : "string",
 *   "encryptionkey" : "binary",
 *   "encryptionkeyalgorithm" : "string",
 *   "hmackey" : "binary",
 *   "signaturekey" : "binary",
 *   "signaturekeyalgorithm" : "string",
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the master token issuer data</li>
 * <li>{@code identity} is the identifier of the remote entity</li>
 * <li>{@code encryptionkey} is the encryption session key</li>
 * <li>{@code encryptionkeyalgorithm} is the JCA encryption algorithm name (default: AES/CBC/PKCS5Padding)</li>
 * <li>{@code hmackey} is the HMAC session key</li>
 * <li>{@code signaturekey} is the signature session key</li>
 * <li>{@code signaturekeyalgorithm} is the JCA signature algorithm name (default: HmacSHA256)</li> 
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslConstants = require('../MslConstants.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslError = require('../MslError.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslException = require('../MslException.js');
	var Base64 = require('../util/Base64.js');
	var SecretKey = require('../crypto/SecretKey.js');
	var WebCryptoUsage = require('../crypto/WebCryptoUsage.js');
	
    /**
     * Milliseconds per second.
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
     * Key sequence number.
     * @const
     * @type {string}
     */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /**
     * Key serial number.
     * @const
     * @type {string}
     */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /**
     * Key session data.
     * @const
     * @type {string}
     */
    var KEY_SESSIONDATA = "sessiondata";

    // sessiondata
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
     * Key symmetric encryption key.
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /**
     * Key encryption algorithm.
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
    /**
     * Key symmetric HMAC key.
     * @const
     * @type {string}
     */
    var KEY_HMAC_KEY = "hmackey";
    /**
     * Key signature key.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE_KEY = "signaturekey";
    /**
     * Key signature algorithm.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";

    /**
     * Create a new session and token data container object.
     *
     * @param {MslObject} sessiondata raw session data. May be null.
     * @param {Uint8Array} tokendataBytes raw token data.
     * @param {Uint8Array} signatureBytes raw signature.
     * @param {boolean} verified true if verified.
     * @constructor
     */
    function CreationData(sessiondata, tokendataBytes, signatureBytes, verified) {
        this.sessiondata = sessiondata;
        this.tokendataBytes = tokendataBytes;
        this.signatureBytes = signatureBytes;
        this.verified = verified;
    }

    var MasterToken = module.exports = MslEncodable.extend({
        /**
         * Create a new master token with the specified expiration, identity,
         * serial number, and encryption and signature keys.
         *
         * @param {MslContext} ctx MSL context.
         * @param {Date} renewalWindow the renewal window.
         * @param {Date} expiration the expiration.
         * @param {number} sequenceNumber the master token sequence number.
         * @param {number} serialNumber the master token serial number.
         * @param {Object} issuerData the issuer data. May be null.
         * @param {string} identity the singular identity this master token represents.
         * @param {SecretKey} encryptionKey the session encryption key.
         * @param {SecretKey} signatureKey the session signature key.
         * @param {?CreationData} creationData optional creation data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @constructor
         */
        init: function init(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, signatureKey, creationData) {
            // The expiration must appear after the renewal window.
            if (expiration.getTime() < renewalWindow.getTime())
                throw new MslInternalException("Cannot construct a master token that expires before its renewal window opens.");
            // The sequence number and serial number must be within range.
            if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslInternalException("Serial number " + serialNumber + " is outside the valid range.");

            // Renewal window and expiration are in seconds, not milliseconds.
            var renewalWindowSeconds = Math.floor(renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
            var expirationSeconds = Math.floor(expiration.getTime() / MILLISECONDS_PER_SECOND);

            // Construct the session data.
            var sessiondata, tokendataBytes, signatureBytes, verified;
            if (!creationData) {
                // Encode session keys and algorithm names.
                var encryptionKeyBytes = encryptionKey.toByteArray();
                var encryptionAlgo = MslConstants.EncryptionAlgo.fromString(encryptionKey.algorithm);
                var signatureKeyBytes = signatureKey.toByteArray();
                var signatureAlgo = MslConstants.SignatureAlgo.fromString(signatureKey.algorithm);
                if (!encryptionAlgo || !signatureAlgo)
                    throw new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM, "encryption algorithm: " + encryptionKey.algorithm + "; signature algorithm: " + signatureKey.algorithm);

                // Create session data.
                var encoder = ctx.getMslEncoderFactory();
                sessiondata = encoder.createObject();
                if (issuerData)
                    sessiondata.put(KEY_ISSUER_DATA, issuerData);
                sessiondata.put(KEY_IDENTITY, identity);
                sessiondata.put(KEY_ENCRYPTION_KEY, encryptionKeyBytes);
                sessiondata.put(KEY_ENCRYPTION_ALGORITHM, encryptionAlgo);
                sessiondata.put(KEY_HMAC_KEY, signatureKeyBytes);
                sessiondata.put(KEY_SIGNATURE_KEY, signatureKeyBytes);
                sessiondata.put(KEY_SIGNATURE_ALGORITHM, signatureAlgo);
                
                tokendataBytes = null;
                signatureBytes = null;
                verified = true;
            } else {
                sessiondata = creationData.sessiondata;
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
                 * Master token renewal window in seconds since the epoch.
                 * @type {number}
                 */
                renewalWindowSeconds: { value: renewalWindowSeconds, writable: false, enumerable: false, configurable: false },
                /**
                 * Master token expiration in seconds since the epoch.
                 * @type {number}
                 */
                expirationSeconds: { value: expirationSeconds, writable: false, enumerable: false, configurable: false },
                /**
                 * Sequence number.
                 * @type {number}
                 */
                sequenceNumber: { value: sequenceNumber, writable: false, enumerable: false, configurable: false },
                /**
                 * Serial number.
                 * @type {number}
                 */
                serialNumber: { value: serialNumber, writable: false, enumerable: false, configurable: false },
                /**
                 * Session data.
                 * @type {MslObject}
                 */
                sessiondata: { value: sessiondata, writable: false, enumerable: false, configurable: false },
                /**
                 * Issuer data.
                 * @type {MslObject}
                 */
                issuerData: { value: issuerData, writable: false, configurable: false },
                /**
                 * Entity identity.
                 * @type {string}
                 */
                identity: { value: identity, writable: false, configurable: false },
                /**
                 * Encryption key.
                 * @type {SecretKey}
                 */
                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                /**
                 * Signature key.
                 * @type {SecretKey}
                 */
                signatureKey: { value: signatureKey, writable: false, configurable: false },
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
         * @return {boolean} true if the decrypted content is available. (Implies verified.)
         */
        isDecrypted: function isDecrypted() {
            return (this.sessiondata) ? true : false;
        },

        /**
         * @return {boolean} true if the token has been verified.
         */
        isVerified: function isVerified() {
            return this.verified;
        },

        /**
         * <p>Returns true if the master token renewal window has been entered.</p>
         *
         * <ul>
         * <li>If a time is provided the renewal window value will be compared
         * against the provided time.</li>
         * <li>If the master token was issued by the local entity the renewal
         * window value will be compared against the local entity time. We assume
         * its clock at the time of issuance is in sync with the clock now.</li>
         * <li>Otherwise the master token is considered renewable under the
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
         * <p>Returns true if the master token is expired.</p>
         *
         * <ul>
         * <li>If a time is provided the expiration value will be compared against
         * the provided time.</li>
         * <li>If the master token was issued by the local entity the expiration
         * value will be compared against the local entity time. We assume
         * its clock at the time of issuance is in sync with the clock now.</li>
         * <li>Otherwise the master token is considered not expired under the
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
         * <p>A master token is considered newer if its sequence number is greater
         * than another master token. If both the sequence numbers are equal, then
         * the master token with the later expiration date is considered newer.</p>
         * 
         * <p>Serial numbers are not taken into consideration when comparing which
         * master token is newer because serial numbers will change when new master
         * tokens are created as opposed to renewed. The caller of this function
         * should already be comparing master tokens that can be used
         * interchangeably (i.e. for the same MSL network).</p>
         *
         * @param {MasterToken} that the master token to compare with.
         * @return {boolean} true if this master token is newer than the provided one.
         */
        isNewerThan: function isNewerThan(that) {
            var cutoff;
            
            // If the sequence numbers are equal then compare the expiration dates.
            if (this.sequenceNumber == that.sequenceNumber)
                return this.expiration > that.expiration;

            // If this sequence number is bigger than that sequence number, make
            // sure that sequence number is not less than the cutoff.
            if (this.sequenceNumber > that.sequenceNumber) {
                cutoff = this.sequenceNumber - MslConstants.MAX_LONG_VALUE + 127;
                return that.sequenceNumber >= cutoff;
            }

            // If this sequence number is smaller than that sequence number, make
            // sure this sequence number is less than the cutoff.
            cutoff = that.sequenceNumber - MslConstants.MAX_LONG_VALUE + 127;
            return this.sequenceNumber < cutoff;
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
                    
                    // Encrypt the session data.
                    encoder.encodeObject(this.sessiondata, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(ciphertext) {
		                            AsyncExecutor(callback, function() {
		                                // Construct the token data.
		                                var tokendata = encoder.createObject();
		                                tokendata.put(KEY_RENEWAL_WINDOW, this.renewalWindowSeconds);
		                                tokendata.put(KEY_EXPIRATION, this.expirationSeconds);
		                                tokendata.put(KEY_SEQUENCE_NUMBER, this.sequenceNumber);
		                                tokendata.put(KEY_SERIAL_NUMBER, this.serialNumber);
		                                tokendata.put(KEY_SESSIONDATA, ciphertext);
		                                
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
		                                    throw new MslEncoderException("Error encrypting the session data.", e);
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
            
            var tokendata = encoder.createObject();
            tokendata.put(KEY_RENEWAL_WINDOW, this.renewalWindowSeconds);
            tokendata.put(KEY_EXPIRATION, this.expirationSeconds);
            tokendata.put(KEY_SEQUENCE_NUMBER, this.sequenceNumber);
            tokendata.put(KEY_SERIAL_NUMBER, this.serialNumber);
            tokendata.put(KEY_SESSIONDATA, "(redacted)");

            var token = encoder.createObject();
            token.put(KEY_TOKENDATA, tokendata);
            token.put(KEY_SIGNATURE, (this.signatureBytes) ? this.signatureBytes : "(null)");
            return token.toString();
        },

        /**
         * <p>Returns true if the other object is a master token with the same
         * serial number, sequence number, and expiration. The expiration is
         * considered in the event the issuer renews a master token but is unable
         * or unwilling to increment the sequence number.</p>
         * 
         * <p>This function is designed for use with sets and maps to guarantee
         * uniqueness of individual master tokens.</p>
         * 
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a master token with the same
         *         serial number, sequence number, and expiration.
         * @see #uniqueKey()
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof MasterToken)) return false;
            return this.serialNumber == that.serialNumber &&
                this.sequenceNumber == that.sequenceNumber &&
                this.expiration.getTime() == that.expiration.getTime();
        },

        /**
         * @return {string} a string that uniquely identifies this master token.
         * @see #equals(that)
         */
        uniqueKey: function uniqueKey() {
            return this.serialNumber + ':' + this.sequenceNumber + ':' + this.expiration.getTime();
        },
    });

    /**
     * Create a new master token with the specified expiration, identity,
     * serial number, and encryption and signature keys.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Date} renewalWindow the renewal window.
     * @param {Date} expiration the expiration.
     * @param {number} sequenceNumber the master token sequence number.
     * @param {number} serialNumber the master token serial number.
     * @param {Object} issuerData the issuer data. May be null.
     * @param {string} identity the singular identity this master token represents.
     * @param {SecretKey} encryptionKey the session encryption key.
     * @param {SecretKey} signatureKey the session signature key.
     * @param {CreationData} creationData optional creation data.
     * @param {{result: function(MasterToken), error: function(Error)}}
     *        callback the callback functions that will receive the master token
     *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    var MasterToken$create = function MasterToken$create(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, signatureKey, callback) {
        AsyncExecutor(callback, function() {
            return new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, signatureKey, null);
        });
    };

    /**
     * Create a new master token from the provided JSON.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Object} masterTokenMo master token JSON object.
     * @param {{result: function(MasterToken), error: function(Error)}}
     *        callback the callback functions that will receive the master token
     *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error verifying the token data
     *         or extracting the session keys.
     * @throws MslException if the expiration timestamp occurs before the
     *         renewal window, or the sequence number is out of range, or the
     *         serial number is out of range, or the token data or signature is
     *         invalid.
     */
    var MasterToken$parse = function MasterToken$parse(ctx, masterTokenMo, callback) {
        AsyncExecutor(callback, function() {
            // Grab the crypto context.
            var cryptoContext = ctx.getMslCryptoContext();
            
            // Verify the encoding.
            var encoder = ctx.getMslEncoderFactory();
            var tokendataBytes, signatureBytes;
            try {
                tokendataBytes = masterTokenMo.getBytes(KEY_TOKENDATA);
                if (tokendataBytes.length == 0)
                    throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_MISSING, "mastertoken " + masterTokenMo);
                signatureBytes = masterTokenMo.getBytes(KEY_SIGNATURE);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "mastertoken " + masterTokenMo, e);
                throw e;
            }
            cryptoContext.verify(tokendataBytes, signatureBytes, encoder, {
                result: function(verified) {
                    parseTokendata(cryptoContext, encoder, tokendataBytes, signatureBytes, verified);
                },
                error: callback.error,
            });
        });
        
        function parseTokendata(cryptoContext, encoder, tokendataBytes, signatureBytes, verified) {
            AsyncExecutor(callback, function() {
                // Pull the token data.
                try {
                    var tokendata = encoder.parseObject(tokendataBytes);
                    var renewalWindowSeconds = tokendata.getLong(KEY_RENEWAL_WINDOW);
                    var expirationSeconds = tokendata.getLong(KEY_EXPIRATION);
                    if (expirationSeconds < renewalWindowSeconds)
                        throw new MslException(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL, "mastertokendata " + tokendata);
                    var sequenceNumber = tokendata.getLong(KEY_SEQUENCE_NUMBER);
                    if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                        throw new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokendata);
                    var serialNumber = tokendata.getLong(KEY_SERIAL_NUMBER);
                    if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                        throw new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokendata);
                    var ciphertext = tokendata.getBytes(KEY_SESSIONDATA);
                    if (ciphertext.length == 0)
                        throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_MISSING, "mastertokendata " + tokendata);
                    
                    // Convert dates.
                    var renewalWindow = new Date(renewalWindowSeconds * MILLISECONDS_PER_SECOND);
                    var expiration = new Date(expirationSeconds * MILLISECONDS_PER_SECOND);
                    
                    if (verified) {
                        cryptoContext.decrypt(ciphertext, encoder, {
                            result: function(plaintext) {
                                parseSessiondata(cryptoContext, encoder, tokendataBytes, signatureBytes, verified,
                                    renewalWindow, expiration, sequenceNumber, serialNumber,
                                    plaintext);
                            },
                            error: callback.error,
                        });
                    } else {
                        constructToken(cryptoContext, encoder, tokendataBytes, signatureBytes, verified,
                            renewalWindow, expiration, sequenceNumber, serialNumber,
                            null, null, null, null, null);
                    }
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR, "mastertokendata " + Base64.encode(tokendataBytes), e);
                    throw e;
                }
            });
        }
        
        function parseSessiondata(cryptoContext, encoder, tokendataBytes, signatureBytes, verified,
                                  renewalWindow, expiration, sequenceNumber, serialNumber,
                                  plaintext)
        {
            AsyncExecutor(callback, function() {
                // Pull the session data.
                var sessiondata, issuerdata, identity;
                var rawEncryptionKey, rawSignatureKey;
                var encryptionAlgo, signatureAlgo;
                try {
                    sessiondata = encoder.parseObject(plaintext);
                    issuerdata = (sessiondata.has(KEY_ISSUER_DATA)) ? sessiondata.getMslObject(KEY_ISSUER_DATA, encoder) : null;
                    identity = sessiondata.getString(KEY_IDENTITY);
                    rawEncryptionKey = sessiondata.getBytes(KEY_ENCRYPTION_KEY);
                    encryptionAlgo = sessiondata.optString(KEY_ENCRYPTION_ALGORITHM, MslConstants.EncryptionAlgo.AES);
                    rawSignatureKey = (sessiondata.has(KEY_SIGNATURE_KEY))
                        ? sessiondata.getBytes(KEY_SIGNATURE_KEY)
                        : sessiondata.getBytes(KEY_HMAC_KEY);
                    signatureAlgo = sessiondata.optString(KEY_SIGNATURE_ALGORITHM, MslConstants.SignatureAlgo.HmacSHA256);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR, "sessiondata " + Base64.encode(plaintext), e);
                    throw e;
                }
                
                // Decode algorithm names.
                var wcEncryptionAlgo = MslConstants.EncryptionAlgo.toWebCryptoAlgorithm(encryptionAlgo);
                var wcSignatureAlgo = MslConstants.SignatureAlgo.toWebCryptoAlgorithm(signatureAlgo);
                if (!wcEncryptionAlgo || !wcSignatureAlgo)
                    throw new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM, "encryption algorithm: " + encryptionAlgo + "; signature algorithm: " + signatureAlgo);
                
                // Reconstruct keys.
                SecretKey.import(rawEncryptionKey, wcEncryptionAlgo, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(encryptionKey) {
                        SecretKey.import(rawSignatureKey, wcSignatureAlgo, WebCryptoUsage.SIGN_VERIFY, {
                            result: function(signatureKey) {
                                constructToken(cryptoContext, encoder, tokendataBytes, signatureBytes, verified,
                                    renewalWindow, expiration, sequenceNumber, serialNumber,
                                    sessiondata, issuerdata, identity, encryptionKey, signatureKey);
                            },
                            error: function(e) {
                                callback.error(new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR, e));
                            }
                        });
                    },
                    error: function(e) {
                        callback.error(new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR, e));
                    }
                });
            });
        }
        
        function constructToken(cryptoContext, encoder, tokendataBytes, signatureBytes, verified,
                                renewalWindow, expiration, sequenceNumber, serialNumber,
                                sessiondata, issuerdata, identity, encryptionKey, signatureKey)
        {
            AsyncExecutor(callback, function() {
                // Return the new master token.
                var creationData = new CreationData(sessiondata, tokendataBytes, signatureBytes, verified);
                return new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerdata, identity, encryptionKey, signatureKey, creationData);
            });
        }
    };
    
    // Exports.
    module.exports.create = MasterToken$create;
    module.exports.parse = MasterToken$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MasterToken'));

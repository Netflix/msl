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
 * <p>MSL encryption envelopes contain all of the information necessary for
 * decrypting and verifying the integrity of its data payload.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var MslConstants = require('../MslConstants.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var Base64 = require('../util/Base64.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	var MslInternalException = require('../MslInternalException.js');
	
    /**
     * Key version.
     * @const
     * @type {string}
     */
    var KEY_VERSION = "version";
    /**
     * Key key ID.
     * @const
     * @type {string}
     */
    var KEY_KEY_ID = "keyid";
    /**
     * Key cipherspec.
     * @const
     * @type {string}
     */
    var KEY_CIPHERSPEC = "cipherspec";
    /**
     * Key initialization vector.
     * @const
     * @type {string}
     */
    var KEY_IV = "iv";
    /**
     * Key ciphertext.
     * @const
     * @type {string}
     */
    var KEY_CIPHERTEXT = "ciphertext";
    /**
     * Key SHA-256.
     * @const
     * @type {string} 
     */
    var KEY_SHA256 = "sha256";

    /** Versions. */
    var Version = {
        /**
         * <p>Version 1.</p>
         * 
         * {@code {
         *   "#mandatory" : [ "keyid", "iv", "ciphertext", "sha256" ],
         *   "keyid" : "string",
         *   "iv" : "binary",
         *   "ciphertext" : "binary",
         *   "sha256" : "binary",
         * }} where:
         * <ul>
         * <li>{@code keyid} is the encryption key ID</li>
         * <li>{@code iv} is the initialization vector</li>
         * <li>{@code ciphertext} is the ciphertext</li>
         * <li>{@code sha256} is the SHA-256 of the encryption envelope</li>
         * </ul>
         * 
         * <p>The SHA-256 is computed over the concatenation of {@code key ID ||
         * IV || ciphertext}.</p>
         */
        V1 : 1,
        /**
         * <p>Version 2.</p>
         * 
         * {@code {
         *   "#mandatory" : [ "version", "cipherspec", "ciphertext" ],
         *   "version" : "number",
         *   "cipherspec" : "string",
         *   "iv" : "binary",
         *   "ciphertext" : "binary",
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code cipherspec} is one of the recognized cipher specifications</li>
         * <li>{@code iv} is the optional initialization vector</li>
         * <li>{@code ciphertext} is the ciphertext</li>
         * </ul>
         * 
         * <p>Supported cipher specifications:
         * <table>
         * <tr><th>Cipher Spec</th><th>Description</th></tr>
         * <tr><td>AES/CBC/PKCS5Padding</td><td>AES CBC w/PKCS#5 Padding</td></tr>
         * </table></p>
         */
        V2 : 2
    };
    
    var MslCiphertextEnvelope = module.exports = MslEncodable.extend({
        /**
         * <p>Create a new encryption envelope with the provided details.</p>
         *
         * @param {string|MslConstants.CipherSpec} keyIdOrSpec the key
         *        identifier or cipher specification.
         * @param {?Uint8Array} iv the initialization vector. May be null.
         * @param {Uint8Array} ciphertext the ciphertext.
         * @constructor
         */
        init: function init(keyIdOrSpec, iv, ciphertext) {
        	// Determine envelope version from first parameter.
        	var version    = Version.V1,
        		keyId      = keyIdOrSpec,
        		cipherSpec = null;
        	for (var key in MslConstants.CipherSpec) {
        		if (MslConstants.CipherSpec[key] == keyIdOrSpec) {
        			version = Version.V2;
        			keyId = null;
        			cipherSpec = keyIdOrSpec;
        			break;
        		}
        	}

        	// The properties.
        	var props = {
        		version: { value: version, writable: false, enumerable: false, configurable: false },
        		keyId: { value: keyId, writable: false, configurable: false },
        		cipherSpec: { value: cipherSpec, writable: false, configurable: false },
        		iv: { value: iv, writable: false, configurable: false },
        		ciphertext: { value: ciphertext, writable: false, configurable: false },
        	};
        	Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                switch (this.version) {
                    case Version.V1:
                        mo.put(KEY_KEY_ID, this.keyId);
                        if (this.iv) mo.put(KEY_IV, this.iv);
                        mo.put(KEY_CIPHERTEXT, this.ciphertext);
                        mo.put(KEY_SHA256, Base64.decode("AA=="));
                        break;
                    case Version.V2:
                        mo.put(KEY_VERSION, this.version);
                        mo.put(KEY_CIPHERSPEC, this.cipherSpec);
                        if (this.iv) mo.put(KEY_IV, this.iv);
                        mo.put(KEY_CIPHERTEXT, this.ciphertext);
                        break;
                    default:
                        throw new MslInternalException("Ciphertext envelope version " + this.version + " encoding unsupported.");
                }
                encoder.encodeObject(mo, format, callback);
            }, this);
        }
    });

    /**
     * <p>Create a new encryption envelope with the provided details.</p>
     *
     * @param {string|CipherSpec} keyIdOrSpec the key identifier or cipher
     *        specification.
     * @param {Uint8Array} iv the initialization vector. May be null.
     * @param {Uint8Array} ciphertext the ciphertext.
     * @param {{result: function(MslCiphertextEnvelope), error: function(Error)}}
     *        callback the callback functions that will receive the envelope
     *        or any thrown exceptions.
     */
    var MslCiphertextEnvelope$create = function MslCiphertextEnvelope$create(keyIdOrCipherSpec, iv, ciphertext, callback) {
    	AsyncExecutor(callback, function() {
    		return new MslCiphertextEnvelope(keyIdOrCipherSpec, iv, ciphertext);
    	});
    };

    /**
     * Create a new encryption envelope from the provided MSL object. If an
     * envelope version is provided then the MSL object is parsed accordingly.
     *
     * @param {MslObject} mo the MSL object.
     * @param {?Version} version the envelope version.
     *        May be null.
     * @param {{result: function(MslCiphertextEnvelope), error: function(Error)}}
     *        callback the callback functions that will receive the envelope
     *        or any thrown exceptions.
     * @throws MslCryptoException if there is an error processing the
     *         encryption envelope.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    var MslCiphertextEnvelope$parse = function MslCiphertextEnvelope$parse(mo, version, callback) {
        AsyncExecutor(callback, function() {
            // If a version was not specified, determine the envelope version.
            if (!version) {
                try {
                    version = mo.getInt(KEY_VERSION);
                    var identified = false;
                    for (var ver in Version) {
                        if (Version[ver] == version) {
                            identified = true;
                            break;
                        }
                    }
                    if (!identified)
                        throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE, "ciphertext envelope " + mo);
                } catch (e) {
                    if (e instanceof MslEncoderException) {
                        // If anything fails to parse, treat this as a version 1 envelope.
                        version = Version.V1;
                    } else {
                        throw e;
                    }
                }
            }
            
            // Parse envelope.
            var keyIdOrSpec, iv, ciphertext;
            switch (version) {
                case Version.V1:
                    try {
                        // Version 1 envelopes use the key ID.
                        keyIdOrSpec = mo.getString(KEY_KEY_ID);
                        iv = (mo.has(KEY_IV)) ? mo.getBytes(KEY_IV) : null;
                        ciphertext = mo.getBytes(KEY_CIPHERTEXT);
                        mo.getBytes(KEY_SHA256);
                    } catch (e) {
                        if (e instanceof MslEncoderException)
                            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "ciphertext envelope " + mo, e);
                        throw e;
                    }
                    break;
                case Version.V2:
                    try {
                        // Version 2 envelopes use the cipher specification.
                        var v = mo.getInt(KEY_VERSION);
                        if (v != Version.V2)
                            throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE, "ciphertext envelope " + mo);
                        keyIdOrSpec = MslConstants.CipherSpec.fromString(mo.getString(KEY_CIPHERSPEC));
                        if (!keyIdOrSpec)
                            throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERSPEC, "ciphertext envelope " + mo);
                        iv = (mo.has(KEY_IV)) ? mo.getBytes(KEY_IV) : null;
                        ciphertext = mo.getBytes(KEY_CIPHERTEXT);
                    } catch (e) {
                        if (e instanceof MslEncoderException)
                            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "ciphertext envelope " + mo, e);
                        throw e;
                    }
                    break;
                default:
                    throw new MslCryptoException(MslError.UNSUPPORTED_CIPHERTEXT_ENVELOPE, "ciphertext envelope " + mo);
            }
            
            // Return envelope.
            return new MslCiphertextEnvelope(keyIdOrSpec, iv, ciphertext);
        });
    };
    
    // Exports.
    module.exports.create = MslCiphertextEnvelope$create;
    module.exports.parse = MslCiphertextEnvelope$parse;
    module.exports.Version = Version;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslCiphertextEnvelope'));

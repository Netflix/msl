/**
 * Copyright (c) 2013-2018 Netflix, Inc.  All rights reserved.
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
 * <p>MSL signature envelopes contain all of the information necessary for
 * verifying data using a known key.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require("../util/Class.js");
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslConstants = require('../MslConstants.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	var Base64 = require('../util/Base64.js');
	
    /**
     * Key version.
     * @const
     * @type {string}
     */
    var KEY_VERSION = "version";
    /**
     * Key algorithm.
     * @const
     * @type {string}
     */
    var KEY_ALGORITHM = "algorithm";
    /**
     * Key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    /** Versions. */
    var Version = {
        /**
         * <p>Version 1.</p>
         *
         * {@code signature}
         *
         * <p>The signature is represented as raw bytes.</p>
         */
        V1 : 1,
        /**
         * <p>Version 2.</p>
         *
         * {@code {
         *   "#mandatory" : [ "version", "algorithm", "signature" ],
         *   "version" : "number",
         *   "algorithm" : "string",
         *   "signature" : "binary"
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code algorithm} is one of the recognized signature algorithms</li>
         * <li>{@code signature} is the signature</li>
         * </ul>
         *
         * <p>Supported algorithms:
         * <table>
         * <tr><th>Algorithm</th><th>Description</th>
         * <tr><td>HmacSHA256</td><td>HMAC w/SHA-256</td></tr>
         * <tr><td>SHA256withRSA</td><td>RSA signature w/SHA-256</td></tr>
         * <tr><td>AESCmac</td><td>AES CMAC</td></tr>
         * </table></p>
         */
        V2 : 2,
    };

    var MslSignatureEnvelope = module.exports = Class.create({
        /**
         * Create a new signature envelope with the provided data.
         *
         * @param {Version} version the envelope version.
         * @param {?MslConstants$SignatureAlgo} algorithm the signature algorithm. May be null.
         * @param {Uint8Array} signature the signature.
         */
        init: function init(version, algorithm, signature) {
            // The properties.
            var props = {
                version: { value: version, writable: false, enumerable: false, configurable: false },
                algorithm: { value: algorithm, writable: false, configurable: false },
                signature: { value: signature, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /**
         * Returns the signature envelope in byte form.
         * 
         * @param {MslEncoderFactory} encoder MSL encoder factory.
         * @param {MslEncoderFormat} format MSL encoder format.
         * @param {{result: function(Uint8Array), error: function(Error)}}
         *        callback the callback functions that will receive the byte
         *        representation of the signature envelope or any thrown
         *        exceptions.
         * @throws MslEncoderException if there is an error encoding the envelope.
         * @throws MslInternalException if the envelope version is not supported.
         */
        getBytes: function getBytes(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                switch (this.version) {
                    case Version.V1:
                        return this.signature;
                    case Version.V2:
                        var mo = encoder.createObject();
                        mo.put(KEY_VERSION, this.version);
                        mo.put(KEY_ALGORITHM, this.algorithm);
                        mo.put(KEY_SIGNATURE, this.signature);
                        encoder.encodeObject(mo, format, callback);
                        break;
                    default:
                        throw new MslInternalException("Signature envelope version " + this.version + " encoding unsupported.");
                }
            }, this);
        },
    });

    /**
     * <p>This method has two acceptable parameter lists.</p>
     *
     * <p>The first form creates a version 1 signature envelope.</p>
     *
     * @param {Uint8Array} signature the signature.
     * @param {{result: function(MslSignatureEnvelope), error: function(Error)}}
     *        callback the callback functions that will receive the envelope
     *        or any thrown exceptions.
     *
     * <p>The second form creates a version 2 signature envelope.</p>
     *
     * @param {MslConstants$SignatureAlgo} algorithm the signature algorithm.
     * @param {Uint8Array} signature the signature.
     * @param {{result: function(MslSignatureEnvelope), error: function(Error)}}
     *        callback the callback functions that will receive the envelope
     *        or any thrown exceptions.
     */
    var MslSignatureEnvelope$create = function MslSignatureEnvelope$create(/* variable arguments */) {
        var version,
            signature,
            algorithm,
            callback;

        // Handle the first form.
        if (arguments.length == 2) {
            version = Version.V1;
            signature = arguments[0];
            algorithm = null;
            callback = arguments[1];
        }

        // Handle the second form.
        else if (arguments.length == 3) {
            version = Version.V2;
            algorithm = arguments[0];
            signature = arguments[1];
            callback = arguments[2];
        }

        // Malformed arguments are not explicitly handled, just as with any
        // other function.

        AsyncExecutor(callback, function() {
            return new MslSignatureEnvelope(version, algorithm, signature);
        });
    };

    /**
     * Create a new signature envelope from the provided envelope bytes. If a
     * signature version is provided then the MSL object is parsed accordingly.
     *
     * @param {Uint8Array} envelope the raw envelope bytes.
     * @param {?Version} version the envelope version.
     *        May be null.
     * @param {MslEncoderFactory} MSL encoder factory.
     * @param {{result: function(MslSignatureEnvelope), error: function(Error)}}
     *        callback the callback functions that will receive the envelope
     *        or any thrown exceptions.
     * @throws MslCryptoException if there is an error processing the signature
     *         envelope.
     * @throws MslEncodingException if there is an error parsing the envelope.
     * @see #getBytes(MslEncoderFactory, MslEncoderFormat)
     */
    var MslSignatureEnvelope$parse = function MslSignatureEnvelope$parse(envelope, version, encoder, callback) {
        AsyncExecutor(callback, function() {
            var algorithm, signature;
            var envelopeMo;
            
            if (version) {
                switch (version) {
                    case Version.V1:
                        return new MslSignatureEnvelope(Version.V1, null, envelope);
                    case Version.V2:
                        try {
                            // We expect the byte representation to be a MSL object.
                            envelopeMo = encoder.parseObject(envelope);

                            // Verify version.
                            var v = envelopeMo.getInt(KEY_VERSION);
                            if (Version.V2 != v)
                                throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + envelope);

                            // Grab algorithm.
                            algorithm = MslConstants.SignatureAlgo.fromString(envelopeMo.getString(KEY_ALGORITHM));
                            if (!algorithm)
                                throw new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM, "signature envelope " + envelope);

                            // Grab signature.
                            signature = envelopeMo.getBytes(KEY_SIGNATURE);

                            // Return the envelope.
                            return new MslSignatureEnvelope(Version.V2, algorithm, signature);
                        } catch (e) {
                            if (e instanceof MslEncoderException)
                                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "signature envelope " + envelope, e);
                            throw e;
                        }
                    default:
                        throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + Base64.encode(envelope));
                }
            }

            // Attempt to convert this to a MSL object.
            try {
                // If this is a MSL object, we expect the byte representation to be
                // decodable.
                envelopeMo = encoder.parseObject(envelope);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    envelopeMo = null;
                else
                    throw e;
            }

            // Determine the envelope version.
            //
            // If there is no MSL object, or there is no version field (as the
            // binary signature may coincidentally parse into a MSL object), then
            // this is a version 1 envelope.
            var envelopeVersion;
            if (!envelopeMo || !envelopeMo.has(KEY_VERSION)) {
                envelopeVersion = Version.V1;
            } else {
                try {
                    envelopeVersion = envelopeMo.getInt(KEY_VERSION);
                    if (envelopeVersion !== envelopeVersion) {
                        // There is a possibility that this is a version 1 envelope.
                        envelopeVersion = Version.V1;
                    }
                    var recognized = false;
                    for (var ver in Version) {
                        if (Version[ver] == envelopeVersion) {
                            recognized = true;
                            break;
                        }
                    }
                    if (!recognized) {
                        // There is a possibility that this is a version 1 envelope.
                        envelopeVersion = Version.V1;
                    }
                } catch (e) {
                    if (e instanceof MslEncoderException) {
                        // There is a possibility that this is a version 1 envelope.
                        envelopeVersion = Version.V1;
                    }
                }
            }

            // Parse envelope.
            switch (envelopeVersion) {
                case Version.V1:
                    return new MslSignatureEnvelope(envelopeVersion, null, envelope);
                case Version.V2:
                    try {
                        algorithm = MslConstants.SignatureAlgo.fromString(envelopeMo.getString(KEY_ALGORITHM));
                        signature = envelopeMo.getBytes(KEY_SIGNATURE);

                        // Verify algorithm.
                        if (!algorithm) {
                            // It is extremely unlikely but possible that this is a
                            // version 1 envelope.
                            return new MslSignatureEnvelope(Version.V1, null, envelope);
                        }
                        return new MslSignatureEnvelope(envelopeVersion, algorithm, signature);
                    } catch (e) {
                        if (e instanceof MslEncoderException) {
                            // It is extremely unlikely but possible that this is a
                            // version 1 envelope.
                            return new MslSignatureEnvelope(Version.V1, null, envelope);
                        }
                        throw e;
                    }
                default:
                    throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + envelope);
            }
        });
    };
    
    // Exports.
    module.exports.create = MslSignatureEnvelope$create;
    module.exports.parse = MslSignatureEnvelope$parse;
    module.exports.Version = Version;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslSignatureEnvelope'));
/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
var MslSignatureEnvelope;
var MslSignatureEnvelope$create;
var MslSignatureEnvelope$parse;
var MslSignatureEnvelope$Version;

(function() {
    /**
     * JSON key version.
     * @const
     * @type {string}
     */
    var KEY_VERSION = "version";
    /**
     * JSON key algorithm.
     * @const
     * @type {string}
     */
    var KEY_ALGORITHM = "algorithm";
    /**
     * JSON key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    /** Versions. */
    var Version = MslSignatureEnvelope$Version = {
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
         *   "signature" : "base64"
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code algorithm} is one of the recognized signature algorithms</li>
         * <li>{@code signature} is the Base64-encoded signature</li>
         * </ul>
         *
         * <p>Supported algorithms:
         * <table>
         * <tr><th>Algorithm</th><th>Description</th>
         * <tr><td>HmacSHA256</td><td>HMAC w/SHA-256</td></tr>
         * <tr><td>SHA256withRSA</td><td>RSA signature w/SHA-256</td></tr>
         * </table></p>
         */
        V2 : 2,
    };

    MslSignatureEnvelope = util.Class.create({
        /**
         * Create a new signature envelope with the provided data.
         *
         * @param {Version} version the envelope version.
         * @param {?MslConstants$SignatureAlgo} algorithm the signature algorithm. May be null.
         * @param {Uint8Array} signature the signature.
         */
        init: function init(version, algorithm, signature) {
            // Create the byte representation.
            var bytes;
            switch (version) {
                case Version.V1:
                    bytes = signature;
                    break;
                case Version.V2:
                    var jsonObj = {};
                    jsonObj[KEY_VERSION] = version;
                    jsonObj[KEY_ALGORITHM] = algorithm;
                    jsonObj[KEY_SIGNATURE] = base64$encode(signature);
                    bytes = textEncoding$getBytes(JSON.stringify(jsonObj), MslConstants$DEFAULT_CHARSET);
                    break;
                default:
                    throw new MslInternalException("Signature envelope version " + version + " encoding unsupported.");
            }

            // The properties.
            var props = {
                version: { value: version, writable: false, enumerable: false, configurable: false },
                algorithm: { value: algorithm, writable: false, configurable: false },
                signature: { value: signature, writable: false, configurable: false },
                bytes: { value: bytes, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        }
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
    MslSignatureEnvelope$create = function MslSignatureEnvelope$create(/* variable arguments */) {
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
     * signature version is provided then the JSON object is parsed accordingly.
     *
     * @param {Uint8Array} envelope the raw envelope bytes.
     * @param {?MslSignatureEnvelope$Version} version the envelope version.
     *        May be null.
     * @param {{result: function(MslSignatureEnvelope), error: function(Error)}}
     *        callback the callback functions that will receive the envelope
     *        or any thrown exceptions.
     * @throws MslCryptoException if there is an error processing the signature
     *         envelope.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @see #getBytes()
     */
    MslSignatureEnvelope$parse = function MslSignatureEnvelope$parse(envelope, version, callback) {
        AsyncExecutor(callback, function() {
            if (version) {
                switch (version) {
                    case Version.V1:
                        return new MslSignatureEnvelope(Version.V1, null, envelope);
                    case Version.V2:
                        try {
                            // We expect the byte representation to be a JSON string.
                            var json = textEncoding$getString(envelope, MslConstants$DEFAULT_CHARSET);
                            var envelopeJo = JSON.parse(json);

                            // Extract values.
                            var v             = parseInt(envelopeJo[KEY_VERSION]),
                                algorithmName = envelopeJo[KEY_ALGORITHM],
                                signatureB64  = envelopeJo[KEY_SIGNATURE];
                            if (!v || typeof v !== 'number' || v != v ||
                                typeof algorithmName !== 'string' ||
                                typeof signatureB64 !== 'string')
                            {
                                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "signature envelope " + base64$encode(envelope));
                            }

                            // Verify version.
                            if (Version.V2 != v)
                                throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + base64$encode(envelope));

                            // Grab algorithm.
                            var algorithm = MslConstants$SignatureAlgo$fromString(algorithmName);
                            if (!algorithm)
                                throw new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM, "signature envelope " + base64$encode(envelope));

                            // Grab signature.
                            var signature = base64$decode(signatureB64);
                            if (!signature)
                                throw new MslCryptoException(MslError.INVALID_SIGNATURE, "signature envelope " + Base64Util.encode(envelope));

                            // Return the envelope.
                            return new MslSignatureEnvelope(Version.V2, algorithm, signature);
                        } catch (e) {
                            if (e instanceof SyntaxError)
                                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "signature envelope " + base64$encode(envelope), e);
                            throw e;
                        }
                    default:
                        throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + base64$encode(envelope));
                }
            }

            // Attempt to convert this to a JSON object.
            var envelopeJo;
            try {
                // If this is a JSON object, we expect the byte representation to
                // be a Base64-encoding of the JSON string.
                var json = textEncoding$getString(envelope, MslConstants$DEFAULT_CHARSET);
                envelopeJo = JSON.parse(json);
            } catch (e) {
                envelopeJo = null;
            }

            // Determine the envelope version.
            //
            // If there is no JSON object, or there is no version field (as the
            // binary signature may coincidentally parse into JSON), then this is a
            // version 1 envelope.
            var envelopeVersion;
            if (!envelopeJo || !envelopeJo[KEY_VERSION]) {
                envelopeVersion = Version.V1;
            } else {
                envelopeVersion = envelopeJo[KEY_VERSION];
                if (typeof envelopeVersion !== 'number' || envelopeVersion !== envelopeVersion) {
                    // There is a possibility that this is a version 1 envelope.
                    envelopeVersion = Version.V1;
                }
            }

            // Parse envelope.
            switch (envelopeVersion) {
                case Version.V1:
                    return new MslSignatureEnvelope(envelopeVersion, null, envelope);
                case Version.V2:
                    // Extract envelope data.
                    var algorithm = envelopeJo[KEY_ALGORITHM];
                    var signatureB64 = envelopeJo[KEY_SIGNATURE];

                    // Verify data.
                    if (typeof algorithm !== 'string' ||
                            typeof signatureB64 !== 'string')
                    {
                        // It is extremely unlikely but possible that this is a
                        // version 1 envelope.
                        return new MslSignatureEnvelope(Version.V1, null, envelope);
                    }

                    // Verify algorithm.
                    algorithm = MslConstants$SignatureAlgo$fromString(algorithm);
                    if (!algorithm) {
                        // It is extremely unlikely but possible that this is a
                        // version 1 envelope.
                        return new MslSignatureEnvelope(Version.V1, null, envelope);
                    }

                    // If the signature fails to decode then it is extremely
                    // unlikely but possible that this is a version 1 envelope.
                    //
                    // A zero-length signature is OK and does not indicate an
                    // error.
                    try {
                        signature = base64$decode(signatureB64);
                    } catch (e) {
                        return new MslSignatureEnvelope(Version.V1, null, envelope);
                    }

                    // Return the version 2 envelope.
                    return new MslSignatureEnvelope(envelopeVersion, algorithm, signature);
                default:
                    throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + envelope);
            }
        });
    };
})();
/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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
 * <p>The MSL crypto abstraction provides support for multiple versions of the
 * Web Crypto specification.</p>
 *
 * @author Kevin Gallagher <keving@netflix.com>
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var MslInternalException = require('../MslInternalException.js');
    var KeyFormat = require('../crypto/KeyFormat.js');
    var PromiseFactory = require('../util/PromiseFactory.js');
    var TextEncoding = require('../util/TextEncoding.js');
    
    var ASN1 = require('../lib/asnjwk.js');

    /**
     * Web Crypto API version.
     * @enum {number}
     */
    var WebCryptoVersion = {
        /** Legacy version with JWE+JWK wrap/unwrap. */
        LEGACY: 1,
        /** 2014.01 version with JWK decrypt+import wrap/unwrap. */
        V2014_01: 2,
        /**
         * 2014.02 version for Chromecast; same as 2014.01 except contains a
         * workaround for errors in Chromecast's definition of keyusage
         * identifiers.
         */
        V2014_02: 3,
        /**
         * 2014.02 version for Safari; same as 2014.02 except SPKI must be
         * converted to JWK for key import and vice versa for key export.
         */
        V2014_02_SAFARI: 4,
        /** Netflix JavaScript Web Crypto API. */
        NRDJS: 5,
        /** Latest (most compatible) version. */
        LATEST: 3,
    };
    Object.freeze(WebCryptoVersion);

    // Default to the latest Web Crypto version.
    var mslCrypto$version = WebCryptoVersion.LATEST;

    /**
     * <p>Set the Web Crypto version that should be used by MSL. This will
     * override the default version detected.</p>
     *
     * @param {WebCryptoVersion} version Web Crypto version to use.
     */
    var MslCrypto$setWebCryptoVersion = function MslCrypto$setWebCryptoVersion(version) {
        mslCrypto$version = version;
    };

    /**
     * <p>Return the Web Crypto version that is being used.</p>
     *
     * @return {WebCryptoVersion} the Web Crypto version in use.
     */
    var MslCrypto$getWebCryptoVersion = function MslCrypto$getWebCryptoVersion() {
        return mslCrypto$version;
    };

    // Determine crypto subtle.
    var nfCryptoSubtle;
    if (typeof window !== "undefined") {
        if (window.msCrypto) {
            nfCryptoSubtle = window.msCrypto.subtle;
            MslCrypto$setWebCryptoVersion(WebCryptoVersion.LEGACY);
        } else if (window.crypto) {
            if (window.crypto.webkitSubtle) {
                nfCryptoSubtle = window.crypto.webkitSubtle;
                MslCrypto$setWebCryptoVersion(WebCryptoVersion.V2014_02_SAFARI);
            } else if (window.crypto.subtle) {
                nfCryptoSubtle = window.crypto.subtle;
            } else {
                // The Web Cryptography API defines window.crypto as well as
                // window.crypto.subtle but restricts the existence of the
                // subtle attribute to secure contexts.
                throw new ReferenceError("Expected window.crypto.subtle but it was undefined. It may be unavailable if running in an insecure context.");
            }
        }
    }

    /**
     * Override the crypto subtle interface providing the Web Crypto API.
     *
     * @param {object} cryptoSubtle the new crypto subtle interface.
     */
    var MslCrypto$setCryptoSubtle = function MslCrypto$setCryptoSubtle(cryptoSubtle) {
        nfCryptoSubtle = cryptoSubtle;
    };

    // If extractable is not specified, default to false
    function normalizeExtractable(extractable) {
        return typeof(extractable) === "undefined" ? false : extractable;
    }

    // If key usage is not specified, default to all
    function normalizeKeyUsage(keyUsage) {
        if (keyUsage && keyUsage.length) {
            if (mslCrypto$version === WebCryptoVersion.V2014_02 ||
               mslCrypto$version === WebCryptoVersion.V2014_02_SAFARI)
            {
                // workaround for Chromecast's non-spec key usage definitions
                keyUsage = keyUsage.map(function(x) {
                    if (x == 'wrap')
                        return 'wrapKey';
                    if (x == 'unwrap')
                        return 'unwrapKey';
                    return x;
                });
            }
            return keyUsage;
        } else {
            // Note: 'deriveBits' is not currently handled by some implementations.
            // We don't use it, but it should be entered here eventually.
            if (mslCrypto$version === WebCryptoVersion.V2014_02 ||
                mslCrypto$version === WebCryptoVersion.V2014_02_SAFARI)
            {
                return ["encrypt", "decrypt", "sign", "verify",
                    "deriveKey", "wrapKey", "unwrapKey"];
            } else {
                return ["encrypt", "decrypt", "sign", "verify",
                        "deriveKey", "wrap", "unwrap"];
            }
        }
    }

    // If the native operation type is not a Promise, wrap it inside one.
    function promisedOperation(op) {
        if (!op.then) {
            return PromiseFactory.create(function(resolve, reject) {
                op.oncomplete = function(e) {
                    resolve(e.target.result);
                };
                op.onerror = function(e) {
                    reject(e);
                };
            });
        }
        return op;
    }

    var MslCrypto = module.exports = {
        'encrypt': function(algorithm, key, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.encrypt(algorithm, key, buffer);
                    return promisedOperation(op);
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'decrypt': function(algorithm, key, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.decrypt(algorithm, key, buffer);
                    return promisedOperation(op);
               default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'sign': function(algorithm, key, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.sign(algorithm, key, buffer);
                    return promisedOperation(op);
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'verify': function(algorithm, key, signature, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.verify(algorithm, key, signature, buffer);
                    return promisedOperation(op);
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'digest': function(algorithm, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.digest(algorithm, buffer);
                    return promisedOperation(op);
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'generateKey': function(algorithm, extractable, keyUsage) {
            var ext = normalizeExtractable(extractable);
            var ku = normalizeKeyUsage(keyUsage);
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.generateKey(algorithm, ext, ku);
                    return promisedOperation(op);
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'deriveKey': function(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsage) {
            var ext = normalizeExtractable(extractable);
            var ku = normalizeKeyUsage(keyUsage);
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, ext, ku);
                    return promisedOperation(op);
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },
        
        'deriveBits': function(algorithm, baseKey, length) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var op = nfCryptoSubtle.deriveBits(algorithm, baseKey, length);
                    return promisedOperation(op);
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'importKey': function(format, keyData, algorithm, extractable, keyUsage) {
            var ext = normalizeExtractable(extractable);
            var ku = normalizeKeyUsage(keyUsage);
            var op;
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.NRDJS:
                    op = nfCryptoSubtle.importKey(format, keyData, algorithm, ext, ku);
                    return promisedOperation(op);
                case WebCryptoVersion.V2014_02_SAFARI:
                    if (format == KeyFormat.SPKI || format == KeyFormat.PKCS8) {
                        var alg = ASN1.webCryptoAlgorithmToJwkAlg(algorithm);
                        var keyOps = ASN1.webCryptoUsageToJwkKeyOps(ku);
                        var jwkObj = ASN1.rsaDerToJwk(keyData, alg, keyOps, ext);
                        if (!jwkObj) {
                            throw new Error("Could not make valid JWK from DER input");
                        }
                        var jwk = JSON.stringify(jwkObj);
                        op = nfCryptoSubtle.importKey(KeyFormat.JWK, TextEncoding.getBytes(jwk), algorithm, ext, ku);
                        return promisedOperation(op);
                    } else {
                        op = nfCryptoSubtle.importKey(format, keyData, algorithm, ext, ku);
                        return promisedOperation(op);
                    }
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'exportKey': function(format, key) {
            var op;
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.NRDJS:
                    op = nfCryptoSubtle.exportKey(format, key);
                    return promisedOperation(op);
                case WebCryptoVersion.V2014_02_SAFARI:
                    if (format == KeyFormat.SPKI || format == KeyFormat.PKCS8) {
                        op = nfCryptoSubtle.exportKey(KeyFormat.JWK, key);
                        return promisedOperation(op).then(function (result) {
                            var jwkObj = JSON.parse(TextEncoding.getString(new Uint8Array(result)));
                            var rsaKey = ASN1.jwkToRsaDer(jwkObj);
                            if (!rsaKey) {
                                throw new Error("Could not make valid DER from JWK input");
                            }
                            return rsaKey.getDer().buffer;
                        });
                    } else {
                        op = nfCryptoSubtle.exportKey(format, key);
                        return promisedOperation(op);
                    }
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
        },

        'wrapKey': function(format, keyToWrap, wrappingKey, wrappingAlgorithm) {
            var op;
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                case WebCryptoVersion.NRDJS:
                    op = nfCryptoSubtle.wrapKey(keyToWrap, wrappingKey, wrappingAlgorithm);
                    break;
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    op = nfCryptoSubtle.wrapKey(format, keyToWrap, wrappingKey, wrappingAlgorithm);
                    break;
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
            return promisedOperation(op);
        },

        'unwrapKey': function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usage) {
            var op;
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    op = nfCryptoSubtle.unwrapKey(wrappedKey, unwrappedKeyAlgorithm, unwrappingKey);
                    break;
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                case WebCryptoVersion.NRDJS:
                    var ext = normalizeExtractable(extractable);
                    var ku = normalizeKeyUsage(usage);
                    op = nfCryptoSubtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, ext, ku);
                    break;
                default:
                    throw new Error("Unsupported Web Crypto version " + mslCrypto$version + ".");
            }
            return promisedOperation(op);
        },
    };

    // Exports.
    module.exports.WebCryptoVersion = WebCryptoVersion;
    module.exports.setWebCryptoVersion = MslCrypto$setWebCryptoVersion;
    module.exports.getWebCryptoVersion = MslCrypto$getWebCryptoVersion;
    module.exports.setCryptoSubtle = MslCrypto$setCryptoSubtle;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslCrypto'));

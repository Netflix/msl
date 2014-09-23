/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
 */
var mslCrypto;
var mslCrypto$version;
var MslCrypto$WebCryptoVersion;

/**
 * <p>Set the Web Crypto version that should be used by MSL. This method must
 * be called before Web Crypto will work.</p>
 * 
 * @param {MslCrypto$WebCryptoVersion} version Web Crypto version to use.
 */
function MslCrypto$setWebCryptoVersion(version) {
    mslCrypto$version = version;
}

(function(){
    "use strict";
    
    /**
     * Web Crypto API version.
     * @enum {number}
     */
    var WebCryptoVersion = MslCrypto$WebCryptoVersion = {
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
        /** Latest (most compatible) version. */
        LATEST: 3,
    };
    Object.freeze(MslCrypto$WebCryptoVersion);
    
    // Default to the latest Web Crypto version.
    mslCrypto$version = WebCryptoVersion.LATEST;
    
    // Detect Safari.
    if (window.crypto && window.crypto.webkitSubtle)
        mslCrypto$version = WebCryptoVersion.V2014_02_SAFARI;

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
    
    mslCrypto = {
        'encrypt': function(algorithm, key, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.encrypt(algorithm, key, buffer);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    // Return an ArrayBufferView instead of the ArrayBuffer as a workaround for
                    // MSL-164.
                    return cryptoSubtle.encrypt(algorithm, key, buffer);
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'decrypt': function(algorithm, key, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.decrypt(algorithm, key, buffer);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.decrypt(algorithm, key, buffer);
               default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'sign': function(algorithm, key, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.sign(algorithm, key, buffer);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.sign(algorithm, key, buffer);
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'verify': function(algorithm, key, signature, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.verify(algorithm, key, signature, buffer);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.verify(algorithm, key, signature, buffer);
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'digest': function(algorithm, buffer) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = cryptoSubtle.digest(algorithm, buffer);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.digest(algorithm, buffer);
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'generateKey': function(algorithm, extractable, keyUsage) {
            var ext = normalizeExtractable(extractable);
            var ku = normalizeKeyUsage(keyUsage);
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.generateKey(algorithm, ext, ku);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.generateKey(algorithm, ext, ku);
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'deriveKey': function(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsage) {
            var ext = normalizeExtractable(extractable);
            var ku = normalizeKeyUsage(keyUsage);
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, ext, ku);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, ext, ku);
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'importKey': function(format, keyData, algorithm, extractable, keyUsage) {
            var ext = normalizeExtractable(extractable);
            var ku = normalizeKeyUsage(keyUsage);
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.importKey(format, keyData, algorithm, ext, ku);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                    return cryptoSubtle.importKey(format, keyData, algorithm, ext, ku);
                case WebCryptoVersion.V2014_02_SAFARI:
                    if (format == 'spki' || format == 'pkcs8') {
                        return Promise.resolve().then(function() {
                            var alg = ASN1.webCryptoAlgorithmToJwkAlg(algorithm);
                            var keyOps = ASN1.webCryptoUsageToJwkKeyOps(ku);
                            var jwkObj = ASN1.rsaDerToJwk(keyData, alg, keyOps, ext);
                            if (!jwkObj) {
                                throw new Error("Could not make valid JWK from DER input");
                            }
                            var jwk = JSON.stringify(jwkObj);
                            return cryptoSubtle.importKey('jwk', utf8$getBytes(jwk), algorithm, ext, ku);
                        }).catch(function(e){
                           throw e; 
                        });
                    } else {
                        return cryptoSubtle.importKey(format, keyData, algorithm, ext, ku);
                    }
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'exportKey': function(format, key) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = nfCrypto.exportKey(format, key);
                        op.oncomplete = function(e) {
                            var res = e.target.result;
                            resolve(res);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                    return cryptoSubtle.exportKey(format, key);
                case WebCryptoVersion.V2014_02_SAFARI:
                    if (format == 'spki' || format == 'pkcs8') {
                        return cryptoSubtle.exportKey('jwk', key).then(function (result) {
                            var jwkObj = JSON.parse(utf8$getString(new Uint8Array(result)));
                            var rsaKey = ASN1.jwkToRsaDer(jwkObj);
                            if (!rsaKey) {
                                throw new Error("Could not make valid DER from JWK input");
                            }
                            return rsaKey.getDer().buffer;
                        });
                    } else {
                        return cryptoSubtle.exportKey(format, key);
                    }
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'wrapKey': function(format, keyToWrap, wrappingKey, wrappingAlgorithm) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = cryptoSubtle.wrapKey(keyToWrap, wrappingKey, wrappingAlgorithm);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.wrapKey(format, keyToWrap, wrappingKey, wrappingAlgorithm);
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },

        'unwrapKey': function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usage) {
            switch (mslCrypto$version) {
                case WebCryptoVersion.LEGACY:
                    return new Promise(function(resolve, reject) {
                        var op = cryptoSubtle.unwrapKey(wrappedKey, unwrapAlgorithm, unwrappingKey);
                        op.oncomplete = function(e) {
                            resolve(e.target.result);
                        };
                        op.onerror = function(e) {
                            reject(e);
                        };
                    });
                case WebCryptoVersion.V2014_01:
                case WebCryptoVersion.V2014_02:
                case WebCryptoVersion.V2014_02_SAFARI:
                    return cryptoSubtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, normalizeExtractable(extractable), normalizeKeyUsage(usage));
                default:
                    throw new Error("Unsupported Web Crypto version " + WEB_CRYPTO_VERSION + ".");
            }
        },
    };
})();

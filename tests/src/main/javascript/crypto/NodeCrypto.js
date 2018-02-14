/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
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
 * <p>A Node.js crypto implementation of the MSL crypto abstraction.</p>
 * 
 * <p>This implementation is not hardened, does not safely detect errors or
 * protect against abuse, and is not suitable for production use.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    // Warn against production use.
    console.warn("WARNING: This Node.js implementation of the MSL crypto abstraction is not\n" +
        "hardened, does not safely detect errors or protect against abuse, and is not\n" +
        "suitable for production use.\n");
    console.warn("WARNING: In addition, since many crypto features are not supported by Node.js\n" +
        "proper, and instead the use of third party modules is advocated (many without\n" +
        "promises of support or bug fixes), crypto within a Node.js environment should be\n" +
        "approached very carefully. We strongly advise against running MSL in a Node.js\n" +
        "environment.\n");

    var Arrays = require('msl-core/util/Arrays.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var JsonWebKeyAlgorithm = require('msl-core/crypto/JsonWebKeyAlgorithm.js');
    var WebCryptoNamedCurve = require('msl-core/crypto/WebCryptoNamedCurve.js');
    var KeyFormat = require('msl-core/crypto/KeyFormat.js');
    var Base64 = require('msl-core/util/Base64.js');
    var MslCrypto = require('msl-core/crypto/MslCrypto.js');
    var MslUtils = require('msl-core/util/MslUtils.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');
    
    var NodeCryptoKey = require('../crypto/NodeCryptoKey.js');
    
    // Reference these but do not add them to the package.json since we should
    // avoid pulling in modules by default.
    var crypto = require('crypto');
    var rs = require('jsrsasign');
    var ECKey = require('ec-key');
    var ursa = require('ursa');
    var EC = require('elliptic').ec;
    
    /** AES-KW alternative IV. */
    var AESKW_AIV = new Uint8Array([0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]);
    /** AES-KW block size. */
    var AESKW_BLOCK_SIZE = 8;
    
    // Shortcuts.
    var KeyType = NodeCryptoKey.KeyType;
    
    /**
     * <p>This setup is fairly confusing because Node.js crypto does not have
     * standard key types, and certain algorithms are only supported via third
     * party libraries (many of which are lacking detailed documentation). Also,
     * despite advertising support for certain algorithms or operations in the
     * Node.js 'crypto' module, the behavior was not always successful or
     * correct which is why a third party library is used instead.</p>
     * 
     * <p>This is unfortunately necessary because the Node.js maintainers do not
     * agree with supporting the Web Crypto standard as part of Node.js proper
     * and instead advocate for third-party translation libraries.</p>
     * 
     * <p>See {@link https://github.com/nodejs/node/issues/2833}.</p>
     * 
     * <p>RSA is supported by 'ursa' and Node.js 'crypto'.
     * <ul>
     * <li>Public key raw values are PEM encoded strings.</li>
     * <li>Private key raw values are PEM encoded strings.</li>
     * </ul>
     * </p>
     * 
     * <p>ECDSA is supported by 'ec-key' and 'elliptic'.
     * <ul>
     * <li>Public key raw values are ECKey instances.</li>
     * <li>Private key raw values are ECKey instances.</li>
     * <li>
     * </ul>
     * </p>
     * 
     * <p>ECDH is supported by 'ec-key'.
     * <ul>
     * <li>Public key raw values are ECKey instances.</li>
     * <li>Private key raw values are ECKey instances.</li>
     * </ul>
     * </p>
     * 
     * <p>Diffie-Hellman is supported by Node.js 'crypto'.
     * <ul>
     * <li>Public key raw values are TypedArrays of the public key.</li>
     * <li>Private key raw values are DiffieHellman instances.</li>
     * </ul>
     * </p>
     * 
     * <p>Symmetric keys are supported by Node.js 'crypto'.
     * <ul>
     * <li>Secret key raw values are TypedArrays of the key bytes.</li>
     * </ul>
     * </p>
     */
    
    /**
     * Normalize the Web Crypto algorithm name. The key is required as the
     * algorithm name may depend upon the key length.
     * 
     * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
     * @param {NodeCryptoKey} key the key.
     * @returns the normalized algorithm name.
     * @throws {Error} if the algorithm name cannot be constructed.
     */
    function normalizeAlgorithmName(algo, key) {
        var rawkey, bitlen;
        
        // The names are based on OpenSSL and the output of crypto.getCiphers()
        // and crypto.getHashes().
        if (!('name' in algo))
            throw new Error("No name provided in Web Crypto algorithm " + JSON.stringify(algo) + ".");
        switch (algo['name']) {
            case WebCryptoAlgorithm.A128KW['name']:
            {
                // We have to implement AES key wrap ourselves using ECB.
                rawkey = key.rawkey;
                if (!(rawkey instanceof Uint8Array))
                    throw new Error("Expected raw key to be a Uint8Array but was of type " + typeof key + ".");
                bitlen = rawkey.length * 8;
                return 'aes-' + bitlen + '-ecb';
            }
            case WebCryptoAlgorithm.AES_CBC['name']:
            {
                rawkey = key.rawkey;
                if (!(rawkey instanceof Uint8Array))
                    throw new Error("Expected raw key to be a Uint8Array but was of type " + typeof key + ".");
                bitlen = rawkey.length * 8;
                return 'aes-' + bitlen + '-cbc';
            }
            case WebCryptoAlgorithm.HMAC_SHA256['name']:
                return normalizeHashName(algo);
            case WebCryptoAlgorithm.RSASSA['name']:
            case WebCryptoAlgorithm.RSASSA_SHA1['name']:
            case WebCryptoAlgorithm.RSASSA_SHA256['name']:
            {
                if ('hash' in algo && 'name' in algo['hash']) {
                    if (algo['hash']['name'] == WebCryptoAlgorithm.RSASSA_SHA256['hash']['name'])
                        return 'RSA-SHA256';
                    return 'RSA-SHA1';
                } else {
                    throw new Error("No hash algorithm specified for use with RSA sign/verify.");
                }
            }
            case WebCryptoAlgorithm.SHA_256['name']:
                return 'sha256';
            case WebCryptoAlgorithm.SHA_384['name']:
                return 'sha384';
            case WebCryptoAlgorithm.ECDSA_SHA256['name']:
            case WebCryptoAlgorithm.DIFFIE_HELLMAN['name']:
            case WebCryptoAlgorithm.RSA_OAEP['name']:
            case WebCryptoAlgorithm.RSAES['name']:
            case WebCryptoAlgorithm.AES_CMAC['name']:
            case WebCryptoAlgorithm.AUTHENTICATED_DH['name']:
            default:
                throw new Error("Node.js algorithm name for Web Crypto algorithm " + algo['name'] + " is not known.");
        }
    }
    
    /**
     * Normalize the Web Crypto hash name.
     * 
     * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
     * @returns the normalized hash name.
     * @throws {Error} if the hash name cannot be constructed.
     */
    function normalizeHashName(algo) {
        // The names are based on OpenSSL and the output of crypto.getHashes().
        if (!('name' in algo))
            throw new Error("No name provided in Web Crypto algorithm " + JSON.stringify(algo) + ".");
        switch (algo['name']) {
            case WebCryptoAlgorithm.SHA_256['name']:
            case WebCryptoAlgorithm.ECDSA_SHA256['name']:
                return 'sha256';
            case WebCryptoAlgorithm.SHA_384['name']:
                return 'sha384';
            default:
                // Fall through.
        }

        if (!('hash' in algo))
            throw new Error("No hash name provided in Web Crypto algorithm " + JSON.stringify(algo) + ".");
        switch (algo['hash']['name']) {
            case 'SHA-256':
                return 'sha256';
            default:
                throw new Error("Node.js hash name for Web Crypto hash " + algo['hash']['name'] + " is not known.");
        }
    }
    
    /**
     * Return the 'jsrsasign' algorithm name for the Web Crypto algorithm. The
     * key is required as the algorithm name may depend upon the key length.
     * 
     * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
     * @param {NodeCryptoKey} key the key.
     * @returns the 'jsrsasign' algorithm name.
     * @throws {Error} if the algorithm name cannot be constructed.
     */
    function jsrsasignAlgorithmName(algo, key) {
        if (!('name' in algo))
            throw new Error("No name provided in Web Crypto algorithm " + JSON.stringify(algo) + ".");
        switch (algo['name']) {
            case WebCryptoAlgorithm.RSASSA['name']:
            case WebCryptoAlgorithm.RSASSA_SHA1['name']:
            case WebCryptoAlgorithm.RSASSA_SHA256['name']:
            {
                if ('hash' in algo && 'name' in algo['hash']) {
                    if (algo['hash']['name'] == WebCryptoAlgorithm.RSASSA_SHA256['hash']['name'])
                        return 'SHA256withRSA';
                    return 'SHA1withRSA';
                } else {
                    throw new Error("No hash algorithm specified for use with RSA sign/verify.");
                }
            }
            case WebCryptoAlgorithm.RSA_OAEP['name']:
                return 'RSAOAEP';
            default:
                throw new Error("jsrsasign algorithm name for Web Crypto algorithm " + algo['name'] + " is not known.");
        }
    }
    
    /**
     * Normalize 'elliptic' module curve name for the Web Crypto algorithm.
     * 
     * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
     * @param {NodeCryptoKey} key the key.
     * @returns the normalized curve name.
     * @throws {Error} if the curve name cannot be constructed.
     */
    function ellipticCurveName(algo, key) {
        if (!('namedCurve' in algo))
            throw new Error("No curve name provided in Web Crypto algorithm " + JSON.stringify(algo) + ".");
        switch (algo['namedCurve']) {
            case WebCryptoNamedCurve.P_256:
                return 'p256';
            case WebCryptoNamedCurve.P_384:
                return 'p384';
            case WebCryptoNamedCurve.P_521:
                return 'p521';
            default:
                throw new Error("Node.js named curve for Web Crypto named curve " + algo['namedCurve'] + " is not known.");
        }
    }
    
    /**
     * Return the 'ec-key' module curve name for the Web Crypto algorithm.
     * 
     * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
     * @returns the 'ec-key' module curve name.
     * @throws {Error} if the curve name cannot be constructed.
     */
    function eckeyCurveName(algo) {
        if (!('namedCurve' in algo))
            throw new Error("No curve name provided in Web Crypto algorithm " + JSON.stringify(algo) + ".");
        switch (algo['namedCurve']) {
            case WebCryptoNamedCurve.P_256:
                return 'P-256';
            case WebCryptoNamedCurve.P_384:
                return 'P-384';
            case WebCryptoNamedCurve.P_521:
                return 'P-521';
            default:
                throw new Error("Node.js named curve for Web Crypto named curve " + algo['namedCurve'] + " is not known.");
        }
    }
    
    /**
     * @param {Uint8Array} buffer the big-endian byte buffer.
     * @returns the integer representation of the buffer.
     * @throws Error if the buffer value would exceed the maximum integer.
     */
    function getBigEndianInteger(buffer) {
        // If the length is more than 7 bytes, or 7 bytes but any of the top
        // three bits are set, we can't fit this in a JavaScript integer.
        if (buffer.length > 7 || (buffer.length == 7 && buffer[0] & 0xe0))
            throw new Error("Big-endian byte buffer value exceeds maximum integer.");
        var integer = 0;
        for (var i = 0; i < buffer.length; ++i) {
            integer <<= 8;
            integer |= buffer[i];
        }
        return integer;
    }
    
    /**
     * @param {string} buffer the (URL-safe) Base64-encoded big-endian integer.
     * @returns the integer representation of the encoded integer.
     * @throws Error if the value would exceed the maximum integer.
     */
    function base64UrlToInteger(s) {
        var binary = Base64.decode(s, true);
        return getBigEndianInteger(binary);
    }

    /**
     * @param {number} bytes number of bytes to return.
     * @param {Uint8Array} w the value.
     * @return {Uint8Array} the specified number of most significant (big-endian) bytes of
     *         the value.
     */
    function msb(bytes, w) {
        return w.subarray(0, bytes);
    }

    /**
     * @param {number} bytes number of bytes to return.
     * @param {Uint8Array} w the value.
     * @return {Uint8array} the specified number of least significant (big-endian) bytes of
     *         the value.
     */
    function lsb(bytes, w) {
        return w.subarray(w.length - bytes);
    }

    /**
     * Modifies the provided byte array by XOR'ing it with the provided value.
     * The byte array is processed in big-endian order.
     * 
     * @param {Uint8Array} b 8-byte value that will be modified.
     * @param {number} t the 64-bit value to XOR the value with.
     */
    function xor(b, t) {
        // We must split on the 32-bit boundaries because JavaScript
        // bitwise operations are limited to 32-bit values.
        var low = t | 0;
        if (low < 0) low += 4294967296;
        var high = t - low;
        high /= 4294967296;
        
        // Perform the XOR.
        b[0] ^= high >>> 56;
        b[1] ^= high >>> 48;
        b[2] ^= high >>> 40;
        b[3] ^= high >>> 32;
        b[4] ^= low >>> 24;
        b[5] ^= low >>> 16;
        b[6] ^= low >>> 8;
        b[7] ^= low;
    }
    
    /**
     * Returns the PEM encoding of the provided DER encoded key data.
     * 
     * @param {Uint8Array} der DER encoded key.
     * @param {KeyFormat} format provided key format (SPKI|PKCS8).
     * @returns {string} PEM encoded key.
     */
    function der2pem(der, format) {
        var b64 = Base64.encode(der);
        switch (format) {
            case KeyFormat.SPKI:
                return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----";
            case KeyFormat.PKCS8:
                return "-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----";
            default:
                throw new Error("Cannot convert key format " + format + " from DER to PEM.");
        }
    }
    
    /**
     * Returns the DER encoding of the provided PEM encoded key data.
     * 
     * @param {string} pem PEM encoded key.
     * @returns {Uint8Array} DER encoded key.
     */
    function pem2der(pem) {
        var b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("\n", "");
        return Base64.decode(b64);
    }

    var NodeCryptoSubtle = module.exports = {
        encrypt: function(algorithm, key, buffer) {
            return Promise.resolve().then(function() {
                // Handle RSA-OAEP.
                if (algorithm['name'] == WebCryptoAlgorithm.RSA_OAEP['name']) {
                    var pem = key.rawkey;
                    var pubkey = ursa.coercePublicKey(pem);
                    return pubkey.encrypt(buffer, undefined, undefined, ursa.RSA_PKCS1_OAEP_PADDING);
                }
                
                // Handle symmetric keys.
                else {
                    var algoName = normalizeAlgorithmName(algorithm, key);
                    var rawkey = key.rawkey;
                    var iv = algorithm['iv'];
                    var cipher = crypto.createCipheriv(algoName, rawkey, iv);
                    var ciphertext_pre = cipher.update(buffer);
                    var ciphertext_post = cipher.final();
                    var ciphertext = new Uint8Array(ciphertext_pre.length + ciphertext_post.length);
                    ciphertext.set(ciphertext_pre, 0);
                    ciphertext.set(ciphertext_post, ciphertext_pre.length);
                    return ciphertext;
                }

                // Unsupported.
                throw new Error("Cannot encrypt using algorithm " + JSON.stringify(algorithm) + ".");
            });
        },
        decrypt: function(algorithm, key, buffer) {
            return Promise.resolve().then(function() {
                // Handle RSA-OAEP.
                if (algorithm['name'] == WebCryptoAlgorithm.RSA_OAEP['name']) {
                    var pem = key.rawkey;
                    var privkey = ursa.coercePrivateKey(pem);
                    return privkey.decrypt(buffer, undefined, undefined, ursa.RSA_PKCS1_OAEP_PADDING);
                }
                
                // Handle symmetric keys.
                else {                
                    var algoName = normalizeAlgorithmName(algorithm, key);
                    var rawkey = key.rawkey;
                    var iv = algorithm['iv'];
                    var decipher = crypto.createDecipheriv(algoName, rawkey, iv);
                    var plaintext_pre = decipher.update(buffer);
                    var plaintext_post = decipher.final();
                    var plaintext = new Uint8Array(plaintext_pre.length + plaintext_post.length);
                    plaintext.set(plaintext_pre, 0);
                    plaintext.set(plaintext_post, plaintext_pre.length);
                    return plaintext;
                }

                // Unsupported.
                throw new Error("Cannot decrypt using algorithm " + JSON.stringify(algorithm) + ".");
            });
        },
        sign: function(algorithm, key, buffer) {
            return Promise.resolve().then(function() {
                var rawkey, hashName, signature;
                
                // Handle RSA keys.
                if (WebCryptoAlgorithm.isRsa(algorithm)) {
                    var algoName = jsrsasignAlgorithmName(algorithm, key);
                    var sign = new rs.KJUR.crypto.Signature({alg: algoName});
                    rawkey = key.rawkey;
                    sign.init(rawkey);
                    var bufferHex = rs.ArrayBuffertohex(buffer.buffer);
                    var signatureHex = sign.signHex(bufferHex);
                    signature = rs.hextoArrayBuffer(signatureHex);
                    return new Uint8Array(signature);
                }
                
                // Handle HMAC.
                else if (WebCryptoAlgorithm.isHmac(algorithm)) {
                    hashName = normalizeHashName(algorithm);
                    rawkey = key.rawkey;
                    var hmac = crypto.createHmac(hashName, rawkey);
                    hmac.update(buffer);
                    return hmac.digest();
                }
                
                // Handle EC keys.
                else if (WebCryptoAlgorithm.isEc(algorithm)) {
                    // Compute the hash.
                    hashName = normalizeHashName(algorithm);
                    var hash = crypto.createHash(hashName);
                    hash.update(buffer);
                    var digest = hash.digest();
                    
                    // Construct the 'elliptic' private key from ECKey.
                    var curveName = ellipticCurveName(algorithm, key);
                    var ec = new EC(curveName);
                    rawkey = key.rawkey;
                    var privkey = rawkey.d;
                    var eckey = ec.keyFromPrivate(privkey);
                    signature = eckey.sign(digest);
                    return signature.toDER();
                }
                
                // Unsupported.
                throw new Error("Cannot sign using algorithm " + JSON.stringify(algorithm) + ".");
            });
        },
        verify: function(algorithm, key, signature, buffer) {
            return Promise.resolve().then(function() {
                var rawkey, hashName, digest;
                
                // Handle RSA keys.
                if (WebCryptoAlgorithm.isRsa(algorithm)) {
                    var algoName = jsrsasignAlgorithmName(algorithm, key);
                    rawkey = key.rawkey;
                    var sign = new rs.KJUR.crypto.Signature({alg: algoName});
                    rawkey = key.rawkey;
                    sign.init(rawkey);
                    var bufferHex = rs.ArrayBuffertohex(buffer.buffer);
                    sign.updateHex(bufferHex);
                    var signatureHex = rs.ArrayBuffertohex(signature.buffer);
                    return sign.verify(signatureHex);
                }
                
                // Handle HMAC.
                if (WebCryptoAlgorithm.isHmac(algorithm)) {
                    hashName = normalizeHashName(algorithm);
                    rawkey = key.rawkey;
                    var hmac = crypto.createHmac(hashName, rawkey);
                    hmac.update(buffer);
                    digest = hmac.digest();
                    return MslUtils.safeEquals(digest, signature);
                }
                
                // Handle EC keys.
                else if (WebCryptoAlgorithm.isEc(algorithm)) {
                    // Compute the hash.
                    hashName = normalizeHashName(algorithm);
                    var hash = crypto.createHash(hashName);
                    hash.update(buffer);
                    digest = hash.digest();
                    
                    // Construct the 'elliptic' public key from ECKey.
                    var curveName = ellipticCurveName(algorithm);
                    var ec = new EC(curveName);
                    rawkey = key.rawkey;
                    var pubpt = {
                        x: rawkey.x,
                        y: rawkey.y
                    };
                    var eckey = ec.keyFromPublic(pubpt);
                    return eckey.verify(digest, signature);
                }

                // Unsupported.
                throw new Error("Cannot verify using algorithm " + JSON.stringify(algorithm) + ".");
            });
        },
        digest: function(algorithm, buffer) {
            return Promise.resolve().then(function() {
                var hashName = normalizeHashName(algorithm);
                var hash = crypto.createHash(hashName);
                hash.update(buffer);
                return hash.digest();
            });
        },
        generateKey: function(algorithm, ext, ku) {
            return Promise.resolve().then(function() {
                // Handle RSA keys.
                if (WebCryptoAlgorithm.isRsa(algorithm)) {
                    var pubexp = getBigEndianInteger(algorithm['publicExponent']);
                    var rsaKeypair = ursa.generatePrivateKey(algorithm['modulusLength'], pubexp);
                    var rsaPubkey = rsaKeypair.toPublicPem('utf8');
                    var rsaPrivkey = rsaKeypair.toPrivatePem('utf8');
                    return {
                        publicKey: new NodeCryptoKey(rsaPubkey, KeyType.PUBLIC, algorithm, true, ku),
                        privateKey: new NodeCryptoKey(rsaPrivkey, KeyType.PRIVATE, algorithm, ext, ku),
                    };
                }
                
                // Handle ECDH and EC keys.
                else if (algorithm['name'] == WebCryptoAlgorithm.ECDH['name'] ||
                         WebCryptoAlgorithm.isEc(algorithm))
                {
                    var curveName = eckeyCurveName(algorithm);
                    var ecKeypair = ECKey.createECKey(curveName);
                    return {
                        publicKey: new NodeCryptoKey(ecKeypair, KeyType.PUBLIC, algorithm, true, ku),
                        privateKey: new NodeCryptoKey(ecKeypair, KeyType.PRIVATE, algorithm, ext, ku),
                    };
                }
                
                // Handle Diffie-Hellman.
                else if (algorithm['name'] == WebCryptoAlgorithm.DIFFIE_HELLMAN['name']) {
                    throw new Error("Diffie-Hellman is not supported.");
                    /*
                    var diffieHellman = crypto.createDiffieHellman(algorithm['prime'], null, algorithm['generator'], null);
                    var dhKeypair = diffieHellman.generateKeys();
                    var dhPubkey = dhKeypair.getPublicKey();
                    return {
                        publicKey: new NodeCryptoKey(dhPubkey, KeyType.PUBLIC, algorithm, true, ku),
                        privateKey: new NodeCryptoKey(diffieHellman, KeyType.PRIVATE, algorithm, ext, ku),
                    };
                    */
                }
                
                // Handle symmetric keys.
                var bitlength = algorithm['length'];
                var bytelength = Math.ceil(bitlength / 8);
                var rawkey = new Uint8Array(bytelength);
                crypto.randomFillSync(rawkey);
                var zerobits = bytelength * 8 - bitlength;
                if (zerobits > 0)
                    rawkey.fill(rawkey[0] >> zerobits, 0, 1);
                return new NodeCryptoKey(rawkey, KeyType.SECRET, algorithm, ext, ku);
            });
        },
        deriveKey: function(algorithm, baseKey, derivedKeyAlgorithm, ext, ku) {
            return Promise.resolve().then(function() {
                // Handle ECDH.
                // There is no key pair derivation algorithm specified for ECDH.
                
                // Handle Diffie-Hellman.
                // Diffie-Hellman is not defined anymore.

                // Unsupported.
                throw new Error("Cannot derive key using algorithm " + JSON.stringify(algorithm) + " with base key type " + baseKey['type'] + ".");
            });
        },
        deriveBits: function(algorithm, baseKey, length) {
            return Promise.resolve().then(function() {
                var bits, zerobits;
                
                // Handle ECDH.
                if (algorithm['name'] == WebCryptoAlgorithm.ECDH['name'] && baseKey['type'] == KeyType.PRIVATE) {
                    throw new Error("Elliptic Curve Diffie-Hellman is not supported.");
                    
                    /*
                    // Compute shared secret.
                    if (!('public' in algorithm))
                        throw new Error("Missing peer public key in algorithm " + JSON.stringify(algorithm) + ".");
                    var ecPeerkey = algorithm['public'].rawkey;
                    var ecKeypair = baseKey.rawkey;
                    var ecdh = ecKeypair.createECDH();
                    var ecSecret = ecdh.computeSecret(ecPeerkey);
                    
                    // Zero-pad and truncate to the requested bit length.
                    var byteLength = (length != null) ? Math.ceil(length / 8) : ecSecret.length;
                    if (byteLength > ecSecret.length)
                        throw new Error("Cannot derive " + length + " bits from shared secret of length " + (ecSecret.length * 8) + " bits.");
                    bits = ecSecret.slice(0, byteLength);
                    zerobits = bits.length * 8 - length;
                    if (zerobits > 0)
                        bits.fill(bits[0] << zerobits >> zerobits, 0, 1);
                    return bits;
                    */
                }
                
                // Handle Diffie-Hellman.
                else if (algorithm['name'] == WebCryptoAlgorithm.DIFFIE_HELLMAN['name'] && baseKey['type'] == KeyType.PRIVATE) {
                    throw new Error("Diffie-Hellman is not supported.");
                    
                    /*
                    if (!('public' in algorithm))
                        throw new Error("Missing peer public key in algorithm " + JSON.stringify(algorithm) + ".");
                    var dhPeerkey = algorithm['public'].rawkey;
                    var diffieHellman = baseKey.rawkey;
                    var dhSecret = diffieHellman.computeSecret(dhPeerkey);

                    // Zero-pad and truncate to the requested bit length.
                    var byteLength = (length != null) ? Math.ceil(length / 8) : dhSecret.length;
                    if (byteLength > dhSecret.length)
                        throw new Error("Cannot derive " + length + " bits from shared secret of length " + (dhSecret.length * 8) + " bits.");
                    bits = dhSecret.slice(0, byteLength);
                    zerobits = bits.length * 8 - length;
                    if (zerobits)
                        bits.fill(bits[0] << zerobits >> zerobits, 0, 1);
                    return bits;
                    */
                }
                
                // Unsupported.
                throw new Error("Cannot derive bits using algorithm " + JSON.stringify(algorithm) + ".");
            });
        },
        importKey: function(format, keyData, algorithm, ext, ku) {
            return Promise.resolve().then(function() {
                var pem, key, rawkey;
                
                // Handle RSA keys.
                if (WebCryptoAlgorithm.isRsa(algorithm)) {
                    if (format == KeyFormat.SPKI) {
                        pem = der2pem(keyData, format);
                        key = ursa.coercePublicKey(pem);
                        rawkey = key.toPublicPem('utf8');
                        return new NodeCryptoKey(rawkey, KeyType.PUBLIC, algorithm, ext, ku);
                    } else if (format == KeyFormat.PKCS8) {
                        pem = der2pem(keyData, format);
                        key = ursa.coercePrivateKey(pem);
                        rawkey = key.toPrivatePem('utf8');
                        return new NodeCryptoKey(rawkey, KeyType.PRIVATE, algorithm, ext, ku);
                    } else if (format == KeyFormat.JWK) {
                        throw new Error("Cannot import RSA keys in JWK format.");
                    }
                }
                
                // Handle ECDH and EC keys.
                else if (algorithm['name'] == WebCryptoAlgorithm.ECDH['name'] ||
                         WebCryptoAlgorithm.isEc(algorithm))
                {
                    var curveName = eckeyCurveName(algorithm);
                    if (format == KeyFormat.SPKI) {
                        var spki = Buffer.from(keyData);
                        var pubkey = new ECKey(spki, 'spki');
                        return new NodeCryptoKey(pubkey, KeyType.PUBLIC, algorithm, ext, ku);
                    } else if (format == KeyFormat.PKCS8) {
                        var pkcs8 = Buffer.from(keyData);
                        var privkey = new ECKey(pkcs8, 'pkcs8');
                        return new NodeCryptoKey(privkey, KeyType.PRIVATE, algorithm, ext, ku);
                    } else if (format == KeyFormat.JWK) {
                        var ecJwk = keyData;
                        var ecKey = new ECKey(ecJwk);
                        if (ecKey.isPrivateECKey) {
                            return new NodeCryptoKey(ecKey, KeyType.PRIVATE, algorithm, ext, ku);
                        } else {
                            return new NodeCryptoKey(ecKey, KeyType.PUBLIC, algorithm, ext, ku);
                        }
                    }
                }
                
                // Handle Diffie-Hellman.
                else if (algorithm['name'] == WebCryptoAlgorithm.DIFFIE_HELLMAN['name']) {
                    throw new Error("Diffie-Hellman is not supported.");
                    
                    /*
                    if (format == KeyFormat.SPKI) {
                        var y = keyData;
                        return new NodeCryptoKey(y, keytype, algorithm, ext, ku);
                    }
                    */
                }
                
                // Handle symmetric keys.
                else if (format == KeyFormat.JWK) {
                    var json = TextEncoding.getString(keyData);
                    var jwk = JSON.parse(json);
                    var k = Base64.decode(jwk['k'], true);
                    return new NodeCryptoKey(k, KeyType.SECRET, algorithm, ext, ku);
                } else if (format == KeyFormat.RAW) {
                    // Check key format.
                    if (!(keyData instanceof Uint8Array))
                        throw new Error("Expected raw key to be a Uint8Array but was of type " + typeof key + ".");
                    
                    // Check key length.
                    if (!('name' in algorithm))
                        throw new Error("No name provided in Web Crypto algorithm " + JSON.stringify(algorithm) + ".");
                    switch (algorithm['name']) {
                        case WebCryptoAlgorithm.A128KW['name']:
                        case WebCryptoAlgorithm.AES_CBC['name']:
                        case WebCryptoAlgorithm.AES_CMAC['name']:
                        {
                            var bitlen = keyData.length * 8;
                            if (bitlen != 128 && bitlen != 192 && bitlen != 256)
                                throw new Error("AES raw key data is not 128b, 192b, or 256b in size.");
                            break;
                        }
                        case WebCryptoAlgorithm.HMAC_SHA256['name']:
                        {
                            if (keyData.length == 0)
                                throw new Error("HMAC raw key data is zero length.");
                            break;
                        }
                        default:
                            // Fall through.
                    }
                    
                    // Return key.
                    return new NodeCryptoKey(keyData, KeyType.SECRET, algorithm, ext, ku);
                }
                
                // Unsupported.
                throw new Error("Cannot import key format " + format + " with algorithm " + JSON.stringify(algorithm) + ".");
            });
        },
        exportKey: function(format, key) {
            return Promise.resolve().then(function() {
                // Cannot export non-extractable keys.
                if (!key['extractable'])
                    throw new Error("Cannot export non-exportable keys.");
                
                // Grab the key algorithm.
                var algorithm = key['algorithm'];
                
                // Handle RSA keys.
                if (WebCryptoAlgorithm.isRsa(algorithm)) {
                    if (format == KeyFormat.SPKI || format == KeyFormat.PKCS8) {
                        return pem2der(key.rawkey);
                    } else if (format == KeyFormat.JWK) {
                        throw new Error("Cannot export RSA keys in JWK format.");
                    }
                }

                // Handle ECDH and EC keys.
                else if (algorithm['name'] == WebCryptoAlgorithm.ECDH['name'] ||
                         WebCryptoAlgorithm.isEc(algorithm))
                {
                    if (format == KeyFormat.SPKI && key['type'] == KeyType.PUBLIC) {
                        return key.rawkey.toBuffer('spki');
                    } else if (format == KeyFormat.PKCS8 && key['type'] == KeyType.PRIVATE) {
                        return key.rawkey.toBuffer('pkcs8');
                    } else if (format == KeyFormat.JWK) {
                        return key.rawkey.toJSON();
                    }
                }
                
                // Handle Diffie-Hellman.
                else if (algorithm['name'] == WebCryptoAlgorithm.DIFFIE_HELLMAN['name']) {
                    throw new Error("Diffie-Hellman is not supported.");
                    
                    /*
                    if (key['type'] == KeyType.PUBLIC)
                        return key.rawkey;
                    else if (key['type'] == KeyType.PRIVATE)
                        return key.rawkey.getPrivateKey();
                    */
                }
                
                // Handle symmetric keys.
                else if (format == KeyFormat.JWK) {
                    var rawkey = key.rawkey;
                    var jwk = {
                        'kty': 'oct',
                        'alg': algorithm['name'],
                        'k': Base64.encode(rawkey, true),
                    };
                    var json = JSON.stringify(jwk);
                    return TextEncoding.getBytes(json);
                } else if (format == KeyFormat.RAW) {
                    return key.rawkey;
                }

                // Unsupported.
                throw new Error("Cannot export key of algorithm " + JSON.stringify(algorithm) + " to format " + format + ".");
            });
        },
        wrapKey: function(format, keyToWrap, wrappingKey, wrappingAlgorithm) {
            var self = this;
            
            return Promise.resolve().then(function() {
                // Cannot wrap non-extractable keys.
                if (!keyToWrap['extractable'])
                    throw new Error("Cannot export non-exportable keys.");
                
                // Handle RSA-OAEP key wrap.
                if (wrappingAlgorithm['name'] == WebCryptoAlgorithm.RSA_OAEP['name']) {
                    return self.exportKey(format, keyToWrap)
                        .then(function(plaintext) {
                            return self.encrypt(wrappingAlgorithm, wrappingKey, plaintext);
                        });
                }
                
                // Handle AES key wrap.
                else if (wrappingAlgorithm['name'] == WebCryptoAlgorithm.A128KW['name']) {
                    return self.exportKey(format, keyToWrap)
                        .then(function(plaintext) {
                            // Compute alternate initial value.
                            var a = Arrays.copyOf(AESKW_AIV);
                            var r = Arrays.copyOf(plaintext);

                            // Prepare cipher arguments.
                            var algoName = normalizeAlgorithmName(wrappingAlgorithm, wrappingKey);
                            var rawkey = wrappingKey.rawkey;
                            var dummyIv = new Uint8Array(0);
                            
                            // Initialize variables.
                            var n = Math.floor(r.length / AESKW_BLOCK_SIZE);
                            
                            // Calculate intermediate values.
                            for (var j = 0; j < 6; ++j) {
                                for (var i = 1; i <= n; ++i) {
                                    var r_i = Arrays.copyOf(r, (i - 1) * AESKW_BLOCK_SIZE, AESKW_BLOCK_SIZE);
                                    var ar_i = Arrays.copyOf(a, 0, a.length + r_i.length);
                                    ar_i.set(r_i, a.length);
                                    var cipher = crypto.createCipheriv(algoName, rawkey, dummyIv);
                                    cipher.setAutoPadding(false);
                                    var ciphertext_pre = cipher.update(ar_i);
                                    var ciphertext_post = cipher.final();
                                    var b = new Uint8Array(ciphertext_pre.length + ciphertext_post.length);
                                    b.set(ciphertext_pre, 0);
                                    b.set(ciphertext_post, ciphertext_pre.length);
                                    a = msb(AESKW_BLOCK_SIZE, b);
                                    var t = (n * j) + i; // Because n is capped at (2^53-1 >> 3), n*6 < 2^53-1 and fits as an integer.
                                    xor(a, t);
                                    r_i = lsb(AESKW_BLOCK_SIZE, b);
                                    r.set(r_i, (i - 1) * AESKW_BLOCK_SIZE);
                                }
                            }
                            
                            // Output results.
                            var c = new Uint8Array(a.length + r.length);
                            c.set(a, 0);
                            c.set(r, a.length);
                            return c;
                        });
                }

                // Unsupported.
                throw new Error("Wrap algorithm " + JSON.stringify(wrappingAlgorithm) + " is not supported.");
            });
        },
        unwrapKey: function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, ext, ku) {
            var self = this;
            
            return Promise.resolve().then(function() {
                // Handle RSA-OAEP key wrap.
                if (unwrapAlgorithm['name'] == WebCryptoAlgorithm.RSA_OAEP['name']) {
                    return self.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey)
                        .then(function(plaintext) {
                            return self.importKey(format, plaintext, unwrappedKeyAlgorithm, ext, ku);
                        });
                }

                // Handle AES key wrap.
                else if (unwrapAlgorithm['name'] == WebCryptoAlgorithm.A128KW['name']) {
                    // Prepare decipher arguments.
                    var algoName = normalizeAlgorithmName(unwrapAlgorithm, unwrappingKey);
                    var rawkey = unwrappingKey.rawkey;
                    var dummyIv = new Uint8Array(0);
                    
                    // Prepare initial values.
                    var a = Arrays.copyOf(wrappedKey, 0, AESKW_BLOCK_SIZE);
                    var r = Arrays.copyOf(wrappedKey, a.length, wrappedKey.length - a.length);
                    var n = Math.floor((wrappedKey.length - AESKW_BLOCK_SIZE) / AESKW_BLOCK_SIZE);
                    
                    // Calculate intermediate values.
                    for (var j = 5; j >= 0; --j) {
                        for (var i = n; i >= 1; --i) {
                            var t = (n * j) + i; // Because n is capped at (2^53-1 >> 3), n*6 < 2^53-1 and fits as an integer.
                            xor(a, t);
                            var r_i = Arrays.copyOf(r, (i - 1) * AESKW_BLOCK_SIZE, AESKW_BLOCK_SIZE);
                            var ar_i = Arrays.copyOf(a, 0, a.length + r_i.length);
                            ar_i.set(r_i, a.length);
                            var decipher = crypto.createDecipheriv(algoName, rawkey, dummyIv);
                            decipher.setAutoPadding(false);
                            var plaintext_pre = decipher.update(ar_i);
                            var plaintext_post = decipher.final();
                            var b = new Uint8Array(plaintext_pre.length + plaintext_post.length);
                            b.set(plaintext_pre, 0);
                            b.set(plaintext_post, plaintext_pre.length);
                            a = msb(AESKW_BLOCK_SIZE, b);
                            r_i = lsb(AESKW_BLOCK_SIZE, b);
                            r.set(r_i, (i - 1) * AESKW_BLOCK_SIZE);
                        }
                    }
                    
                    // Output results.
                    if (MslUtils.safeEquals(a, AESKW_AIV) && r.length % AESKW_BLOCK_SIZE == 0)
                        return self.importKey(format, r, unwrappedKeyAlgorithm, ext, ku);
                    throw new Error("AES key unwrap failed.");
                }

                // Unsupported.
                throw new Error("Wrap algorithm " + JSON.stringify(unwrapAlgorithm) + " is not supported.");
            });
        },
    };
})(require, (typeof module !== 'undefined') ? module : mkmodule('NodeCrypto'));
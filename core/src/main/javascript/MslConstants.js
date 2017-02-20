/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
 * <p>Message security layer constants.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	const WebCryptoAlgorithm = require('./crypto/WebCryptoAlgorithm.js');

    /** RFC-4327 defines UTF-8 as the default encoding. */
    var MslConstants$DEFAULT_CHARSET = "utf-8";

    /** Maximum long integer value (2^53 limited by JavaScript). */
    var MslConstants$MAX_LONG_VALUE = 9007199254740992;

    /**
     * The maximum number of MSL messages (requests sent or responses received)
     * to allow before giving up. Six exchanges, or twelve total messages,
     * should be sufficient to capture all possible error recovery and
     * handshake requirements in both trusted network and peer-to-peer modes.
     *
     * @type {number}
     * @const
     */
    var MslConstants$MAX_MESSAGES = 12;

    /**
     * Compression algorithm.
     * @enum {string}
     */
    var CompressionAlgorithm = MslConstants$CompressionAlgorithm = {
        // In order of most preferred to least preferred.
        // Keep in-sync with getPreferredAlgorithm().
        /** GZIP */
        GZIP : "GZIP",
        /** LZW */
        LZW : "LZW",
    };
    Object.freeze(MslConstants$CompressionAlgorithm);

    /**
     * Returns the most preferred compression algorithm from the provided
     * set of algorithms.
     *
     * @param {Array.<MslConstants$CompressionAlgorithm>} algos the set of algorithms to choose from.
     * @return {?MslConstants$CompressionAlgorithm>} the most preferred compression algorithm or {@code null} if
     *         the algorithm set is empty.
     */
    var MslConstants$CompressionAlgorithm$getPreferredAlgorithm = function MslConstants$CompressionAlgorithm$getPreferredAlgorithm(algos) {
        var preferredAlgos = [ CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW ];
        for (var i = 0; i < preferredAlgos.length && algos.length > 0; ++i) {
            var preferredAlgo = preferredAlgos[i];
            for (var j = 0; j < algos.length; ++j) {
                if (algos[j] == preferredAlgo)
                    return preferredAlgo;
            }
        }
        return null;
    };

    /** Encryption algorithms. */
    var EncryptionAlgo = MslConstants$EncryptionAlgo = {
        /** AES */
        AES : "AES",
    };
    Object.freeze(MslConstants$EncryptionAlgo);

    /**
     * @param {WebCryptoAlgorithm|string} value the Web Crypto algorithm or
     *        string value of the encryption algorithm.
     * @return {?MslConstants$EncryptionAlgo} the associated encryption
     *         algorithm or undefined if there is none.
     */
    var MslConstants$EncryptionAlgo$fromString = function MslConstants$EncryptionAlgo$fromString(value) {
        // IE 11 uses lowercase algorithm names, contrary to spec.
        var algoName = value;
        if (typeof value === 'string')
            algoName = value.toLowerCase();
        if (typeof value === 'object' && typeof value['name'] === 'string')
            algoName = value['name'].toLowerCase();

        // Web Crypto does not define key types independent of cipher
        // specifications, so unfortunately the AES-CBC cipher spcification
        // maps onto the AES key type.
        if (WebCryptoAlgorithm.AES_CBC['name'].toLowerCase() == algoName)
            return EncryptionAlgo.AES;
        return EncryptionAlgo[value];
    };

    /**
     * @param {EncryptionAlgo} the encryption algorithm.
     * @return {?WebCryptoAlgorithm} the Web Crypto algorithm associated with
     *         the encryption algorithm or undefined if there is none.
     */
    var MslConstants$EncryptionAlgo$toWebCryptoAlgorithm = function MslConstants$EncryptionAlgo$toWebCryptoAlgorithm(value) {
        // Web Crypto does not define key types independent of cipher
        // specifications, so unfortunately the AES key type maps onto the
        // AES-CBC cipher specification.
        if (EncryptionAlgo.AES == value)
            return WebCryptoAlgorithm.AES_CBC;
        return undefined;
    };

    /** Cipher specifications. */
    var CipherSpec = MslConstants$CipherSpec = {
        /** AES/CBC/PKCS5Padding */
        AES_CBC_PKCS5Padding : "AES/CBC/PKCS5Padding",
        /** AESWrap */
        AESWrap : "AESWrap",
        /** RSA/ECB/PKCS1Padding */
        RSA_ECB_PKCS1Padding : "RSA/ECB/PKCS1Padding",
    };
    Object.freeze(MslConstants$CipherSpec);

    /**
     * @param {string} value the string value of the cipher specification.
     * @return {?MslConstants$CipherSpec} the cipher specification associated
     *         with the string value or undefined if there is none.
     */
    var MslConstants$CipherSpec$fromString = function MslConstants$CipherSpec$fromString(value) {
        if (CipherSpec.AES_CBC_PKCS5Padding == value)
            return CipherSpec.AES_CBC_PKCS5Padding;
        if (CipherSpec.RSA_ECB_PKCS1Padding == value)
            return CipherSpec.RSA_ECB_PKCS1Padding;
        return CipherSpec[value];
    };

    /** Signature algorithms. */
    var SignatureAlgo = MslConstants$SignatureAlgo = {
        /** HmacSHA256 */
        HmacSHA256 : "HmacSHA256",
        /** SHA256withRSA */
        SHA256withRSA : "SHA256withRSA",
        /** AESCmac */
        AESCmac : "AESCmac",
    };
    Object.freeze(MslConstants$SignatureAlgo);

    /**
     * @param {WebCryptoAlgorithm|string} value the Web Crypto algorithm or
     *        string value of the signature algorithm.
     * @return {?MslConstants$SignatureAlgo} the associated signature algorithm
     *         or undefined if there is none.
     */
    var MslConstants$SignatureAlgo$fromString = function MslConstants$SignatureAlgo$fromString(value) {
        // IE 11 uses lowercase algorithm names, contrary to spec.
        var algoName = value;
        if (typeof value === 'string')
            algoName = value.toLowerCase();
        if (typeof value === 'object' && typeof value['name'] === 'string')
            algoName = value['name'].toLowerCase();
        var hashName = undefined;
        if (typeof value['hash'] === 'object')
            hashName = value['hash']['name'].toLowerCase();

        // FIXME
        // This is an ugly approach to mapping Web Crypto algorithms onto
        // signature algorithms. We should probably use some sort of subset-
        // JSON object function to compare.
        if (WebCryptoAlgorithm.HMAC_SHA256['name'].toLowerCase() == algoName &&
            WebCryptoAlgorithm.HMAC_SHA256['hash']['name'].toLowerCase() == hashName)
        {
            return SignatureAlgo.HmacSHA256;
        }
        if (WebCryptoAlgorithm.RSASSA_SHA256['name'].toLowerCase() == algoName &&
            WebCryptoAlgorithm.RSASSA_SHA256['hash']['name'].toLowerCase() == hashName)
        {
            return SignatureAlgo.SHA256withRSA;
        }
        if (WebCryptoAlgorithm.AES_CMAC['name'].toLowerCase() == algoName) {
            return SignatureAlgo.AESCmac;
        }
        return SignatureAlgo[value];
    };

    /**
     * @param {SignatureAlgo} the signature algorithm.
     * @return {?WebCryptoAlgorithm} the Web Crypto algorithm associated with
     *         the signature algorithm or undefined if there is none.
     */
    var MslConstants$SignatureAlgo$toWebCryptoAlgorithm = function MslConstants$SignatureAlgo$toWebCryptoAlgorithm(value) {
        if (SignatureAlgo.HmacSHA256 == value)
            return WebCryptoAlgorithm.HMAC_SHA256;
        if (SignatureAlgo.SHA256withRSA == value)
            return WebCryptoAlgorithm.SHA256withRSA;
        if (SignatureAlgo.AESCmac == value)
            return WebCryptoAlgorithm.AES_CMAC;
        return undefined;
    };

    /**
     * Error response codes.
     * @enum {number}
     */
    var MslConstants$ResponseCode = {
        /** The message is erroneous and will continue to fail if retried. */
        FAIL: 1,
        /** The message is expected to succeed if retried after a delay. */
        TRANSIENT_FAILURE: 2,
        /** The message is expected to succeed post entity re-authentication. */
        ENTITY_REAUTH: 3,
        /** The message is expected to succeed post user re-authentication. */
        USER_REAUTH: 4,
        /** The message is expected to succeed post key exchange. */
        KEYX_REQUIRED: 5,
        /** The message is expected to succeed with new entity authentication data. */
        ENTITYDATA_REAUTH: 6,
        /** The message is expected to succeed with new user authentication data. */
        USERDATA_REAUTH: 7,
        /** The message is expected to succeed if retried with a renewed master token or renewable message. */
        EXPIRED: 8,
        /** The non-replayable message is expected to succeed if retried with the newest master token. */
        REPLAYED: 9,
        /** The message is expected to succeed with new user authentication data containing a valid single-sign-on token. */
        SSOTOKEN_REJECTED: 10
    };
    Object.freeze(MslConstants$ResponseCode);
    
    // Exports.
    module.exports = {};
    module.exports.DEFAULT_CHARSET = MslConstants$DEFAULT_CHARSET;
    module.exports.MAX_LONG_VALUE =  MslConstants$MAX_LONG_VALUE;
    module.exports.MAX_MESSAGES = MslConstants$MAX_MESSAGES;
    module.exports.CompressionAlgorithm = MslConstants$CompressionAlgorithm;
    module.exports.CompressionAlgorithm.getPreferredAlgorithm = MslConstants$CompressionAlgorithm$getPreferredAlgorithm;
    module.exports.EncryptionAlgo = MslConstants$EncryptionAlgo;
    module.exports.EncryptionAlgo.fromString = MslConstants$EncryptionAlgo$fromString;
    module.exports.EncryptionAlgo.toWebCryptoAlgorithm = MslConstants$EncryptionAlgo$toWebCryptoAlgorithm
    module.exports.CipherSpec = MslConstants$CipherSpec;
    module.exports.CipherSpec.fromString = MslConstants$CipherSpec$fromString;
    module.exports.SignatureAlgo = MslConstants$SignatureAlgo;
    module.exports.SignatureAlgo.fromString = MslConstants$SignatureAlgo$fromString;
    module.exports.SignatureAlgo.toWebCryptoAlgorithm = MslConstants$SignatureAlgo$toWebCryptoAlgorithm
    module.exports.ResponseCode = MslConstants$ResponseCode;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslConstants'));
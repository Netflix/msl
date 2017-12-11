/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Base64 encoder/decoder. Can be configured with a backing
 * implementation.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function (require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    
    /** Whitespace regular expression. */
    var WHITESPACE_REGEX = /\s*/g;
    /** Base64 validation regular expression. */
    var BASE64_PATTERN = new RegExp('^([A-Za-z0-9+/_-]{4})*([A-Za-z0-9+/_-]{4}|[A-Za-z0-9+/_-]{3}=|[A-Za-z0-9+/_-]{2}==)?$');
    /** Padding character. */
    var PADCHAR = "=";

    /**
     * <p>Validates that a string is a valid Base64 encoding. This uses a
     * regular expression to perform the check. The empty string is also
     * considered valid. All whitespace is ignored.</p>
     *
     * @param {string} s the string to validate.
     * @param {?boolean} urlSafe true if URL-safe Base64-encoding validation
     *        should be used (http://tools.ietf.org/html/rfc4648#section-5)
     * @return {boolean} true if the string is a valid Base64 encoding.
     */
    var isValidBase64 = function isValidBase64(s, urlSafe) {
        var sanitized = s.replace(WHITESPACE_REGEX, '');

        // Pad out urlsafe data so we can treat padded and unpadded incoming
        // data the same below.
        if (urlSafe) {
            var overhang = sanitized.length % 4;
            if (overhang) {
                var toPad = 4 - overhang;
                for (var i = 0; i < toPad; ++i)
                    sanitized += PADCHAR;
            }
        }

        // Verify string is a multiple of four and only contains valid
        // characters.
        if (sanitized.length % 4 != 0 || !BASE64_PATTERN.test(sanitized))
            return false;
        return true;
    };

    /** Backing implementation. */
    var impl;

    /**
     * <p>A Base64 encoder/decoder implementation. Implementations must be
     * thread-safe.</p>
     */
    var Base64Impl = Class.create({
        /**
         * <p>Base64 encodes binary data.</p>
         *
         * @param {Uint8array} b the binary data.
         * @param {?boolean} urlSafe true if unpadding URL-safe Base64-encoding
         *        should be used (http://tools.ietf.org/html/rfc4648#section-5)
         * @return {string} the Base64-encoded binary data.
         */
        encode: function(b, urlSafe) {},

        /**
         * <p>Decodes a Base64-encoded string into its binary form.</p>
         *
         * @param {string} s the Base64-encoded string.
         * @param {?boolean} urlSafe true if unpadded URL-safe Base64 decoding
         *        should be used (http://tools.ietf.org/html/rfc4648#section-5)
         * @return {Uint8Array} the binary data.
         * @throws Error if the argument is not a valid Base64-encoded string.
         *         The empty string is considered valid.
         */
        decode: function(s, urlSafe) {},
    });
    
    /**
     * Set the backing implementation.
     * 
     * @param {Base64Impl} i the backing implementation.
     * @throws TypeError if the implementation is {@code null}.
     */
    var setImpl = function setImpl(i) {
        if (!i)
            throw new TypeError("Base64 implementation cannot be null.");
        impl = i;
    };

    /**
     * <p>Base64 encodes binary data.</p>
     *
     * @param {Uint8Array} b the binary data.
     * @param {?boolean} urlSafe true if unpadding URL-safe Base64-encoding
     *        should be used (http://tools.ietf.org/html/rfc4648#section-5)
     * @return the Base64-encoded binary data.
     */
    var encode = function encode(b, urlSafe) {
        return impl.encode(b, urlSafe);
    };

    /**
     * <p>Decodes a Base64-encoded string into its binary form.</p>
     *
     * @param {string} s the Base64-encoded string.
     * @param {?boolean} urlSafe true if unpadded URL-safe Base64 decoding
     *        should be used (http://tools.ietf.org/html/rfc4648#section-5)
     * @return {Uint8Array} the binary data.
     * @throws Error if the argument is not a valid Base64-encoded string.
     *         The empty string is considered valid.
     */
    var decode = function decode(s, urlSafe) {
        return impl.decode(s, urlSafe);
    };
    
    // Exports.
    module.exports.isValidBase64 = isValidBase64;
    module.exports.Base64Impl = Base64Impl;
    module.exports.setImpl = setImpl;
    module.exports.encode = encode;
    module.exports.decode = decode;
})(require, (typeof module !== 'undefined') ? module : mkmodule('Base64'));

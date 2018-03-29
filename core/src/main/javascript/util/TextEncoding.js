/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
(function(require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    
    /** Character Encodings. */
    var Encoding = {
        /**
         * UTF-8 "utf-8"
         * @type {string}
         * @const
         */
        UTF_8: 'utf-8',
        /**
         * UTF-16 "utf-16"
         * @type {string}
         * @const
         */
        UTF_16: 'utf-16',
    };
    
    /** Backing implementation. */
    var impl;
    
    /**
     * <p>A text encoding/decoding implementation. Implementations must be
     * thread-safe.</p>
     */
    var TextEncodingImpl = Class.create({
        /**
         * <p>Decodes binary data into a string.</p>
         * 
         * @param {Uint8Array} bytes encoded bytes.
         * @param {Encoding=} encoding character encoding (default UTF_8).
         * @returns {string} the decoded string.
         * @throws Error if the encoded bytes are not valid or if the specified
         *         character encoding is not recognized or supported.
         */
        getString: function(bytes, encoding) {},
        
        /**
         * <p>Encodes a string into binary data.</p>
         * 
         * @param {string} str string to encode.
         * @param {Encoding=} encoding character encoding (default UTF_8).
         * @returns {Uint8Array} the encoded data.
         * @throws Error if the string cannot be encoded or if the specified
         *         character encoding is not recognized or supported.
         */
        getBytes: function(str, encoding) {},
    });

    /**
     * Set the backing implementation.
     * 
     * @param {TextEncodingImpl} i the backing implementation.
     * @throws TypeError if the implementation is {@code null}.
     */
    var setImpl = function setImpl(i) {
        if (!i)
            throw new TypeError("Text encoding implementation cannot be null.");
        impl = i;
    };
    
    /**
     * <p>Decodes binary data into a string.</p>
     * 
     * @param {Uint8Array} bytes encoded bytes.
     * @param {Encoding=} encoding character encoding (default UTF-8).
     * @returns {string} the decoded string.
     * @throws Error if the encoded bytes are not valid or if the specified
     *         character encoding is not recognized or supported.
     */
    var getString = function getString(bytes, encoding) {
        return impl.getString(bytes, encoding);
    };
    
    /**
     * <p>Encodes a string into binary data.</p>
     * 
     * @param {string} str string to encode.
     * @param {Encoding=} encoding character encoding (default UTF-8).
     * @returns {Uint8Array} the encoded data.
     * @throws Error if the string cannot be encoded or if the specified
     *         character encoding is not recognized or supported.
     */
    var getBytes = function getBytes(str, encoding) {
        return impl.getBytes(str, encoding);
    };
    
    // Exports.
    module.exports.Encoding = Encoding;
    module.exports.TextEncodingImpl = TextEncodingImpl;
    module.exports.setImpl = setImpl;
    module.exports.getString = getString;
    module.exports.getBytes = getBytes;
})(require, (typeof module !== 'undefined') ? module : mkmodule('TextEncoding'));
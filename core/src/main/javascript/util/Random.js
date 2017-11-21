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
(function(require, module) {
	"use strict";
	
	var MslConstants = require('../MslConstants.js');
    var MslInternalException = require('../MslInternalException.js');
	var Class = require('../util/Class.js');

    // Shift multiplication.
    var SHIFT_24 = 0x1000000;
    var SHIFT_20 = 0x100000;
    // Minimum integer.
    var MIN_LONG_VALUE = 0 - MslConstants.MAX_LONG_VALUE;
    // 2^52.
    var POW_NEGATIVE_52 = Math.pow(2,-52);

    // Determine nfCrypto.
    var nfCrypto;
    if (typeof window !== "undefined") {
        nfCrypto = window.msCrypto || window.crypto;
    }

    /**
     * Override the crypto interface providing the function getRandomValues().
     *
     * @param {object} crypto the new crypto interface.
     */
    var Random$setCrypto = function Random$setCrypto(crypto) {
        nfCrypto = crypto;
    };

    /**
     * @param min minimum value.
     * @param max maximum value.
     * @returns a random (JavaScript) integer between min and max inclusive.
     */
    function random(min, max) {
        var b = new Uint8Array(4);
        nfCrypto.getRandomValues(b);
        var r = ((b[3] & 0x7f) << 24) | (b[2] << 16) |( b[1] << 8) | b[0];
        var factor = r / (0x7fffffff + 1);
        return Math.floor(factor * (max - min + 1) + min);
    }

    var Random = module.exports = Class.create({
        /**
         * @return {boolean} a random boolean value.
         */
        nextBoolean: function nextBoolean() {
            var b = new Uint8Array(1);
            nfCrypto.getRandomValues(b);
            return (b[0] & 0x1) ? true : false;
        },

        /**
         * Return a random number from [-2<sup>31</sup>,2<sup>31</sup>-1].
         *
         * @param {number=} if specified a random number between [0,n) is
         *        generated instead.
         * @return {number} a random number.
         */
        nextInt: function nextInt(n) {
            // Currently, n is only passed in by unit tests. Therefore any
            // potential randomness skew associated with the private random
            // function is unimportant.
            if (n !== null && n !== undefined) {
                if (typeof n !== 'number')
                    throw new TypeError('n must be of type number');
                if (n < 1)
                    throw new RangeError('n must be greater than zero');
                return random(0, n - 1);
            }

            var b = new Uint8Array(4);
            nfCrypto.getRandomValues(b);
            var abs = ((b[3] & 0x7f) << 24) | (b[2] << 16) | (b[1] << 8) | b[0];
            return (b[3] & 0x80) ? -abs : abs;
        },

        /**
         * @return {number} a random number from [-2<sup>63</sup>,2<sup>63</sup>-1].
         */
        nextLong: function nextLong() {
            // Discard the maximum negative value as a result to avoid bias of
            // it happening twice.
            var result = MIN_LONG_VALUE;
            while (result == MIN_LONG_VALUE) {
                // We will actually clamp at 2^53 due to JavaScript limitations. If
                // we assume each bit is equally random then truncating does not
                // reduce the randomness.
                var b = new Uint8Array(7);
                nfCrypto.getRandomValues(b);
                // We have to do some strange bit math because JavaScript will only
                // shift < 32 bits.
                var highbits = ((b[6] & 0x1f) << 24) | (b[5] << 16) | (b[4] << 8) | b[3];
                var lowbits = (b[2] << 16) | (b[1] << 8) | b[0];
                var abs = SHIFT_24 * highbits + lowbits;
                result = (b[6] & 0x80) ? -abs - 1 : abs;
            }
            return result;
        },
        
        /**
         * @return {number} a random number.
         */
        nextDouble: function nextDouble() {
            // Ask for 64 random bits, but we will only use 53 of them to
            // compute the number.
            var b = new Uint32Array(2);
            nfCrypto.getRandomValues(b);
            // Use the least significant bit for the sign.
            var sign = b[1] & 0x1;
            // Use the top 52 bits for the mantissa.
            var mantissa = b[0] * SHIFT_20 + b[1] >> 12;
            // Convert to a number between [0,1).
            var multiplier = mantissa * POW_NEGATIVE_52;
            return ((sign) ? 1 : -1) * multiplier * Number.MAX_VALUE;
        },

        /**
         * Generates random bytes and places them into a user-supplied array.
         * The number of random bytes produced is equal to the length of the
         * array.
         *
         * @param {Uint8Array} buffer the array in which to put the random
         *        bytes.
         */
        nextBytes: function nextBytes(buffer) {
            // The API maximum is 65536. Iterate over the buffer until we fill
            // it.
            var offset = 0;
            while (true) {
                var length = Math.min(65536, buffer.length - offset);
                if (length == 0) break;
                var view = new Uint8Array(length);
                nfCrypto.getRandomValues(view);
                buffer.set(view, offset);
                offset += length;
            }
        }
    });
    
    // Exports.
    module.exports.setRandom = Random$setCrypto;
})(require, (typeof module !== 'undefined') ? module : mkmodule('Random'));

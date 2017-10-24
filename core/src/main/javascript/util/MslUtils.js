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
 * Utility methods.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
    
    var MslConstants = require('../MslConstants.js');
    var MslException = require('../MslException.js');
    var MslError = require('../MslError.js');
    
    /**
     * <p>Returns true if the provided number is a safe integer.</p>
     * 
     * <p>A safe integer is an integer that:
     * <ul>
     * <li>can be exactly represented as an IEEE-754 double precision number</li>
     * <li>whose IEEE-754 representation cannot be the result of rounding any other integer to fit the IEEE-754 representation</li>
     * </ul></p>
     * 
     * @param {number} n the number to check.
     */
    function isSafeInteger(n) {
        var isInteger = (typeof n === 'number' && isFinite(n) && Math.floor(n) == n);
        return isInteger && Math.abs(n) <= Number.MAX_SAFE_INTEGER;
    }
    
    /**
     * Safely compares two byte arrays to prevent timing attacks.
     * 
     * @param {Uint8Array} a first array for the comparison.
     * @param {Uint8Array} b second array for the comparison.
     * @return {boolean} true if the arrays are equal, false if they are not.
     */
    function MslUtils$safeEquals(a, b) {
        if (a.length != b.length)
            return false;

        var result = 0;
        for (var i = 0; i < a.length; ++i)
            result |= a[i] ^ b[i];
        return result == 0;
    }

    /**
     * Return true if the number is a non-negative power of two. Zero is
     * considered a power of two and will return true.
     * 
     * @param {number} n the number to test.
     * @return {boolean} true if the number is a non-negative power of two.
     */
    function MslUtils$isPowerOf2(n) {
        // If the number is a power of two, a binary AND operation between
        // the number and itself minus one will equal zero.
        if (!isSafeInteger(n) || n < 0) return false;
        if (n == 0) return true;
        return (n & (n - 1)) == 0;
    }
    
    /**
     * Returns a random number between zero and the maximum long value as
     * defined by {@link MslConstants#MAX_LONG_VALUE}, inclusive.
     * 
     * @param {MslContext} ctx MSL context.
     * @return {number} a random number between zero and the maximum long value,
     *         inclusive.
     */
    function MslUtils$getRandomLong(ctx) {
        // If the maximum long value is a power of 2, then we can perform a
        // bitmask on the randomly generated long value to restrict to our
        // target number space.
        var isPowerOf2 = MslUtils$isPowerOf2(MslConstants.MAX_LONG_VALUE);

        // Generate the random value.
        var r = ctx.getRandom();
        var n = -1;
        do {
            n = r.nextLong();

            // Perform a bitmask if permitted, which will force this loop
            // to exit immediately.
            if (isPowerOf2)
                n &= (MslConstants.MAX_LONG_VALUE - 1);
        } while (n < 0 || n > MslConstants.MAX_LONG_VALUE);

        // Return the random value.
        return n;
    }

    // Exports.
    module.exports.safeEquals = MslUtils$safeEquals;
    module.exports.getRandomLong = MslUtils$getRandomLong;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslUtils'));

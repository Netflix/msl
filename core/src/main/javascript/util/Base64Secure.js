/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
 * <p>Base64 encoder/decoder implementation that strictly enforces the validity
 * of the encoding and does not exit early if an error is encountered.
 * Whitespace (space, tab, newline, carriage return) are skipped.</p>
 * 
 * <p>Based upon {@link javax.xml.bind.DatatypeConverter}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function (require, module) {
    "use strict";
    
    var Base64 = require('../util/Base64.js');

    /** Tab character value. */
    var TAB = String.fromCharCode(9);
    /** Newline character value. */
    var NEWLINE = String.fromCharCode(10);
    /** Carriage return character value. */
    var CARRIAGE_RETURN = String.fromCharCode(13);
    /** Space character value. */
    var SPACE = String.fromCharCode(32);
    /** Padding character sentinel value. */
    var PADDING = String.fromCharCode(127);
    
    /** The encode map. */
    var ENCODE_MAP = initEncodeMap();
    /** The decode map. */
    var DECODE_MAP = initDecodeMap();
    
    /**
     * @return {Array} the 64-character Base64 encode map.
     */
    function initEncodeMap() {
        var i;
        var map = [];
        for (i = 0; i < 26; i++)
            map[i] = String.fromCharCode(65 + i);
        for (i = 26; i < 52; i++)
            map[i] = String.fromCharCode(97 + (i - 26));
        for (i = 52; i < 62; i++)
            map[i] = String.fromCharCode(48 + (i - 52));
        map[62] = '+';
        map[63] = '/';

        return map;
    }
    
    /**
     * @return the 128-byte Base64 decode map.
     */
    function initDecodeMap() {
        var i;
        var map = [];
        for (i = 0; i < 128; i++)
            map[i] = -1;

        for (i = 65; i <= 90; i++)
            map[i] = (i - 65);
        for (i = 97; i <= 122; i++)
            map[i] = (i - 97 + 26);
        for (i = 48; i <= 57; i++)
            map[i] = (i - 48 + 52);
        map[43] = 62;
        map[47] = 63;
        map[61] = PADDING;

        return map;
    }
    
    /**
     * @param {number} i the value to encode.
     * @param {?boolean} urlSafe true if URL-safe encoding should be used.
     * @return {string} the character the value maps onto.
     */
    function encodeValue(i, urlSafe) {
        var c = ENCODE_MAP[i & 0x3F];
        if (urlSafe) {
            if (c == '+') return '-';
            if (c == '/') return '_';
        }
        return c;
    }
    
    /**
     * @param {string} c the character to decode.
     * @param {?boolean} urlSafe true if URL-safe decoding should be used.
     * @return {number} the value the character maps onto or undefined if not
     *         found or out of range.
     */
    function decodeChar(c, urlSafe) {
        var cc = c.charCodeAt(0);
        if (isNaN(cc)) return undefined;
        
        var v = DECODE_MAP[cc];
        if (urlSafe) {
            if (v == '-') return '+';
            if (v == '_') return '/';
        }
        return v;
    }
    
    var Base64Secure = module.exports = Base64.Base64Impl.extend({
        /** @inheritDoc */
        encode: function encode(b, urlSafe) {
            var pad = (urlSafe) ? '' : '=';
            
            // Allocate the character buffer.
            var buf = '';
            
            // Encode elements until there are only 1 or 2 left.
            var remaining = b.length;
            var i;
            for (i = 0; remaining >= 3; remaining -= 3, i += 3) {
                buf += encodeValue(b[i] >> 2)
                    + encodeValue(((b[i] & 0x3) << 4) | ((b[i+1] >> 4) & 0xF))
                    + encodeValue(((b[i + 1] & 0xF) << 2) | ((b[i + 2] >> 6) & 0x3))
                    + encodeValue(b[i + 2] & 0x3F);
            }
            // If there is one final element...
            if (remaining == 1) {
                buf += encodeValue(b[i] >> 2)
                    + encodeValue(((b[i]) & 0x3) << 4);
                if (!urlSafe)
                    buf += '==';
            }
            // If there are two final elements...
            else if (remaining == 2) {
                buf += encodeValue(b[i] >> 2)
                    + encodeValue(((b[i] & 0x3) << 4) | ((b[i + 1] >> 4) & 0xF))
                    + encodeValue((b[i + 1] & 0xF) << 2);
                if (!urlSafe)
                    buf += '=';
            }
            
            // Return the encoded string.
            return buf;
        },
    
        /** @inheritDoc */
        decode: function decode(s, urlSafe) {
            // Flag to remember if we've encountered an invalid character or have
            // reached the end of the string prematurely.
            var invalid = false;
            
            // Convert string to ISO 8859-1 bytes.
            var sb = s;
            
            // Allocate the destination buffer, which may be too large due to
            // whitespace.
            var strlen = sb.length;
            var outlen = Math.floor(strlen * 3 / 4);
            var out = new Array(outlen);
            var o = 0;
            
            // Convert each quadruplet to three bytes.
            var quadruplet = new Array(4);
            var q = 0;
            var lastQuad = false;
            for (var i = 0; i < strlen; ++i) {
                var c = sb[i];
                
                // Lookup the character in the decoder map.
                var b = decodeChar(c, urlSafe);
                
                // Skip invalid characters.
                if (b === undefined || b == -1) {
                    // Flag invalid for non-whitespace.
                    if (c != SPACE && c != TAB && c != NEWLINE && c != CARRIAGE_RETURN)
                        invalid = true;
                    continue;
                }
                
                // If we already saw the last quadruplet, we shouldn't see anymore.
                if (lastQuad)
                    invalid = true;
                
                // Append value to quadruplet.
                quadruplet[q++] = b;
                
                // If the quadruplet is full, append it to the destination buffer.
                if (q == 4) {
                    // If the quadruplet starts with padding, flag invalid.
                    if (quadruplet[0] == PADDING || quadruplet[1] == PADDING)
                        invalid = true;
                    
                    // If the quadruplet ends with padding, this better be the last
                    // quadruplet.
                    if (quadruplet[2] == PADDING || quadruplet[3] == PADDING)
                        lastQuad = true;
                    
                    // Decode into the destination buffer.
                    out[o++] = (quadruplet[0] << 2) | (quadruplet[1] >> 4);
                    if (quadruplet[2] != PADDING)
                        out[o++] = (quadruplet[1] << 4) | (quadruplet[2] >> 2);
                    if (quadruplet[3] != PADDING)
                        out[o++] = (quadruplet[2] << 6) | (quadruplet[3]);
                    
                    // Reset the quadruplet index.
                    q = 0;
                }
            }
            
            // If performing URL-safe decoding and the quadruplet contains
            // data, append it to the destination buffer.
            if (urlSafe && q >= 2) {
                // Decode into the destination buffer.
                out[o++] = (quadruplet[0] << 2) | (quadruplet[1] >> 4);
                if (q == 3 && quadruplet[2] != PADDING)
                    out[o++] = (quadruplet[1] << 4) | (quadruplet[2] >> 2);
                
                // Reset the quadruplet index.
                q = 0;
            }
            
            // If the quadruplet is not empty, flag invalid.
            if (q != 0)
                invalid = true;
            
            // If invalid throw an exception.
            if (invalid)
                throw new Error("Invalid Base64 encoded string: " + s);
            
            // Always copy the destination buffer into the return buffer to
            // maintain consistent runtime.
            var ret = new Uint8Array(o);
            for (var j = 0, k = 0; j < out.length; ++j) {
                if (urlSafe && out[j] == PADDING)
                    continue;
                ret[j] = out[k++];
            }
            return ret;
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('Base64Secure'));

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
(function (require, module) {
    "use strict";

    var map =    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
        urlmap = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
        padchar =    '=',
        charNumber1 = { },
        charNumber2 = { },
        charNumber3 = { '=': 0, '.': 0 },
        charNumber4 = { '=': 0, '.': 0 },
        prepRegex = /\s*/g,
        checkRegex = new RegExp('^([A-Za-z0-9+/_-]{4})*([A-Za-z0-9+/_-]{4}|[A-Za-z0-9+/_-]{3}=|[A-Za-z0-9+/_-]{2}==)?$');

    var i = map.length;
    while (i--) {
        // pre-calculate values for each of quad-s
        charNumber1[map[i]] = i * 0x40000;
        charNumber2[map[i]] = i * 0x1000;
        charNumber3[map[i]] = i * 0x40;
        charNumber4[map[i]] = i;
    }
    var j = urlmap.length;
    while (j--) {
        // stop once we've already seen this character
        if (map[j] == urlmap[j]) break;
        // pre-calculate values for each of quad-s
        charNumber1[urlmap[j]] = j * 0x40000;
        charNumber2[urlmap[j]] = j * 0x1000;
        charNumber3[urlmap[j]] = j * 0x40;
        charNumber4[urlmap[j]] = j;
    }

    /**
     * Base64 encode a byte array.
     *
     * @param {Uint8Array} a the data to encode.
     * @param {?boolean} urlSafe true if unpadded URL-safe Base64 encoding
     *        should be used (http://tools.ietf.org/html/rfc4648#section-5)
     * @return {String} the Base64 string representation of the data.
     */
    var base64$encode = function (a, urlSafe) {
        var s = '',
            i = 0,
            l = a.length,
            lMinus2 = l - 2,
            triplet;

        var table = (!urlSafe) ? map : urlmap;
        var pad = (!urlSafe) ? padchar : '';

        while (i < lMinus2) {
            triplet =
                (a[i++] * 0x10000) +
                (a[i++] * 0x100) +
                (a[i++]);

            s +=
                table[(triplet >>> 18)] +
                table[(triplet >>> 12) & 0x3F] +
                table[(triplet >>> 6) & 0x3F] +
                table[(triplet) & 0x3F];
        }

        if (i == lMinus2) {
            triplet =
                (a[i++] * 0x10000) +
                (a[i++] * 0x100);

            s +=
                table[(triplet >>> 18)] +
                table[(triplet >>> 12) & 0x3F] +
                table[(triplet >>> 6) & 0x3F] +
                pad;

        } else if (i == l - 1) {
            triplet =
                (a[i++] * 0x10000);

            s +=
                table[(triplet >>> 18)] +
                table[(triplet >>> 12) & 0x3F] +
                pad + pad;

        }

        return s;
    };

    /**
     * Base64 decode a string.
     *
     * @param {String} a Base64 string representation of data.
     * @param {?boolean} urlSafe true if unpadded URL-safe Base64 decoding
     *        should be used (http://tools.ietf.org/html/rfc4648#section-5)
     * @return {Uint8Array} the decoded data.
     * @throws Error if the Base64 string is the wrong length or is not Base64
     *         encoded data. The empty string is considered valid.
     */
    var base64$decode = function (s, urlSafe) {
        s = s.replace(prepRegex, '');
        
        // Pad out urlsafe data so we can treat padded and unpadded incoming
        // data the same below.
        if (urlSafe) {
            var overhang = s.length % 4;
            if (overhang) {
                var toPad = 4 - overhang;
                for (var i = 0; i < toPad; ++i) {
                    s += padchar;
                };
            }
        }

        var l = s.length,
            triplet;

        if (l % 4 != 0 || !checkRegex.test(s))
            throw new Error('bad base64: ' + s);

        var aLength = (l / 4) * 3 -
                (s[l - 1] == padchar ? 1 : 0) -
                (s[l - 2] == padchar ? 1 : 0),
            a = new Uint8Array(aLength),
            si = 0,
            ai = 0;

        while (si < l) {
            triplet =
                charNumber1[s[si++]] +
                charNumber2[s[si++]] +
                charNumber3[s[si++]] +
                charNumber4[s[si++]];

            a[ai++] = (triplet >>> 16);
            if (ai < aLength) {
                a[ai++] = (triplet >>> 8) & 0xFF;
                if (ai < aLength) {
                    a[ai++] = (triplet) & 0xFF;
                }
            }
        }

        return a;
    };
    
    // Exports.
    module.exports.encode = base64$encode;
    module.exports.decode = base64$decode;
})(require, (typeof module !== 'undefined') ? module : mkmodule('Base64'));

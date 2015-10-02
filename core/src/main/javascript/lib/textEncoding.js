/**
 * Copyright (c) 2013-2015 Netflix, Inc.  All rights reserved.
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
 * @param {Uint8Array} bytes encoded data
 * @param {string=} encoding "utf-8", "utf-16" (default="utf-8")
 *
 * @returns {string}
 */
function textEncoding$getString(bytes, encoding) {
    if (!encoding || encoding === "utf-8") {
        return utf8$getString(bytes);
    }
    throw new Error("unsupported encoding");
};

/**
 * @param {string} str string to encode
 * @param {string=} encoding "utf-8", "utf-16" (default="utf-8")
 *
 * @returns {Uint8Array}
 */
function textEncoding$getBytes(str, encoding) {
    if (!encoding || encoding === "utf-8") {
        return utf8$getBytes(str);
    }
    throw new Error("unsupported encoding");
};

/**
 * @param {Uint8Array} bytes encoded data
 *
 * @returns {string}
 */
function utf8$getString(bytes) {
    var i = 0,
        charCode,
        bytesLength = bytes.length,
        str = "";

    while(i < bytesLength) {
        charCode = bytes[i++];

        // check the first flag, which indicates that this is a multi-byte character
        if (charCode & 0x80) {
            // 1xxxxxxx
            if ((charCode & 0xE0) === 0xC0) {
                // 110xxxxx	10xxxxxx
                charCode = ((charCode & 0x1F) << 6) + (bytes[i++] & 0x3F);
            } else if ((charCode & 0xF0) === 0xE0) {
                // 1110xxxx	10xxxxxx 10xxxxxx
                charCode = ((charCode & 0x0F) << 12) + ((bytes[i++] & 0x3F) << 6) + (bytes[i++] & 0x3F);
            } else {
                // 1111xxxx	10xxxxxx 10xxxxxx 10xxxxxx (or more)
                // JavaScript only rupports 2 byte characters
                throw new Error("unsupported character");
            }
        }

        str += String.fromCharCode(charCode);
    }

    return str;
};

/**
 * @param {string} str string to encode
 *
 * @returns {Uint8Array}
 */
function utf8$getBytes(str) {
    var strLength = str.length,
        bytes,
        bytesLength = 0,
        i,
        j = 0,
        charCode;

    // Note: JavaScript only rupports 2 byte characters, so the charCode can never be more than 0xFFFF

    // first pass to calculate the size, which we need to allocate the bytesay
    i = strLength;
    while (i--) {
        charCode = str.charCodeAt(i);
        if (charCode < 0x0080) {
            bytesLength++;
        } else if (charCode < 0x0800) {
            bytesLength += 2;
        } else {
            bytesLength += 3;
        }
    }

    // second pass, allocate the bytesay and do actual encoding
    bytes = new Uint8Array(bytesLength);
    for (i = 0; i < strLength; i++) {
        charCode = str.charCodeAt(i);
        if (charCode < 0x0080) {
            // 0xxxxxxx
            bytes[j++] = charCode;
        } else if (charCode < 0x0800) {
            // 110xxxxx	10xxxxxx
            bytes[j++] = 0xC0 | (charCode >>> 6);
            bytes[j++] = 0x80 | (charCode & 0x3F);
        } else {
            // 1110xxxx 10xxxxxx 10xxxxxx
            bytes[j++] = 0xE0 | (charCode >>> 12);
            bytes[j++] = 0x80 | ((charCode >>> 6) & 0x3F);
            bytes[j++] = 0x80 | (charCode & 0x3F);
        }
    }

    return bytes;
};

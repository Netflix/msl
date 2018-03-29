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
 * <p>LZW data compression and uncompression backed by pure JavaScript
 * implementation.</p>
 *
 * <p>This class is thread-safe.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var MslCompression = require('../util/MslCompression.js');
    var MslIoException = require('../MslIoException.js');
    
    // Shortcuts.
    var CompressionImpl = MslCompression.CompressionImpl;

    /**
     * Byte size in bits.
     * @const
     * @type {number}
     */
    var BYTE_SIZE = 8;
    /**
     * Maximum number of values represented by a byte.
     * @const
     * @type {number}
     */
    var BYTE_RANGE = 256;
    /**
     * The initial compression dictionary.
     * @type {Object.<string,number>}
     */
    var COMPRESS_DICTIONARY = {};
    for (var ci = 0; ci < BYTE_RANGE; ++ci) {
        var key = createKey([ci]);
        COMPRESS_DICTIONARY[key] = ci;
    }
    /**
     * The initial compression dictionary length.
     * @const
     * @type {number}
     */
    var COMPRESS_DICTIONARY_LENGTH = Object.keys(COMPRESS_DICTIONARY).length;
    /**
     * The initial decompression dictionary.
     * @type {Array.<Array.<number>>}
     */
    var UNCOMPRESS_DICTIONARY = [];
    for (var ui = 0; ui < BYTE_RANGE; ++ui) {
        UNCOMPRESS_DICTIONARY[ui] = [ui];
    }

    /**
     * Construct a compression map key value from the given byte array.
     *
     * @param {Array.<number>} bytes the byte array.
     * @param {number=} count the number of bytes to create the key from.
     * @return {string} the key value.
     */
    function createKey(bytes, count) {
        if (!count)
            count = bytes.length;
        return bytes.reduce(function(previousValue, currentValue, index) {
            if (index < count)
                return previousValue + String.fromCharCode(currentValue);
            return previousValue;
        }, '');
    }
    
    /**
     * Default LZW compression implementation.
     */
    var LzwCompression = module.exports = CompressionImpl.extend({
        /** @inheritDoc */
        compress: function compress(data) {
            // Populate the initial dictionary.
            var dictionary = {};
            for (var cd in COMPRESS_DICTIONARY)
                dictionary[cd] = COMPRESS_DICTIONARY[cd];
            var dictlen = COMPRESS_DICTIONARY_LENGTH;

            // Working symbols.
            var symbols = [];
            // Current bit length.
            var bits = 8;
            // Compressed data. If it exceeds the data length then we abort.
            var compressed = new Uint8Array(data.length);
            // Compressed data current byte index.
            var index = 0;
            // Bits available in the current byte.
            var available = BYTE_SIZE;
            // Temporary variables.
            var key, value;

            // Compress all the data.
            for (var i = 0; i < data.length; ++i) {
                // Add a byte to the input.
                var c = data[i];
                symbols.push(c);

                // Check if the input is in the dictionary.
                key = createKey(symbols);
                value = dictionary[key];

                // If the value is not in the dictionary, then...
                if (value === undefined) {
                    // emit the previous input's code...
                    var prevkey = createKey(symbols, symbols.length - 1);
                    var prevvalue = dictionary[prevkey];
                    if (!emit(prevvalue, bits))
                        return null;

                    // and add the new input to the dictionary.
                    //
                    // The bit width increases from p to p + 1 when the new code is
                    // the first code requiring p + 1 bits.
                    if (dictlen >> bits != 0)
                        ++bits;
                    dictionary[key] = dictlen++;

                    // Remove the emitted symbol from the current input.
                    symbols = [c];
                }
            }

            // If there are any symbols left we have to emit those codes now.
            if (symbols.length > 0) {
                key = createKey(symbols);
                value = dictionary[key];
                if (!emit(value, bits))
                    return null;
            }

            function emit(code, bits) {
                var msbits;
                
                // Write the current code bits MSB-first.
                while (bits > 0) {
                    // If we've run out of compressed storage return false.
                    if (index >= compressed.length)
                        return false;

                    // If the code has more bits than available, shift right to get
                    // the most significant bits. This finishes off the current
                    // byte.
                    if (bits > available) {
                        msbits = code;
                        msbits >>>= bits - available;
                        compressed[index] |= (msbits & 0xff);

                        // We've written 'available' bits of the current code. The
                        // next byte is completely available so reset the values.
                        bits -= available;
                        available = BYTE_SIZE;
                        ++index;
                    }

                    // If the code has less then or equal bits available, shift
                    // left to pack against the previous bits.
                    else if (bits <= available) {
                        // First shift left to erase the most significant bits then
                        // shift right to start at the correct offset.
                        msbits = code;
                        msbits <<= available - bits;
                        msbits &= 0xff;
                        msbits >>>= BYTE_SIZE - available;
                        compressed[index] |= (msbits & 0xff);

                        // We've written 'bits' bits into the current byte. There
                        // are no more bits to write for the current code.
                        available -= bits;
                        bits = 0;

                        // If this finished the current byte then write it and
                        // reset the values.
                        if (available == 0) {
                            available = BYTE_SIZE;
                            ++index;
                        }
                    }
                }

                // Success.
                return true;
            }

            // Return the compressed data. We have to include the current byte if
            // the number of bits available is less than the byte size (meaning
            // some bits have been placed into it).
            var length = (available < BYTE_SIZE) ? index + 1 : index;
            return compressed.subarray(0, length);
        },
        
        /** @inheritDoc */
        uncompress: function uncompress(data, maxDeflateRatio) {
            // Populate the initial dictionary by copying the initial dictionary
            var dictionary = UNCOMPRESS_DICTIONARY.slice();

            // Current code byte index.
            var codeIndex = 0;
            // Current code byte bit offset.
            var codeOffset = 0;
            // Current bit length.
            var bits = BYTE_SIZE;
            // Uncompressed data. Start off with 50% more than the data length.
            var uncompressed = new Uint8Array(Math.ceil(data.length * 1.5));
            // Uncompressed data current byte index.
            var index = 0;
            // Uncompressed data next byte index.
            var nextIndex = 0;
            // Previously buffered decoded bytes for building the dictionary.
            var prevvalue = [];

            // Uncompress the data.
            while (codeIndex < data.length) {
                // If there are not enough bits available for the next code then
                // stop.
                var bitsAvailable = (data.length - codeIndex) * BYTE_SIZE - codeOffset;
                if (bitsAvailable < bits)
                    break;

                // Decode the next code.
                var code = 0;
                var bitsDecoded = 0;
                while (bitsDecoded < bits) {
                    // Read the next batch of bits.
                    var bitlen = Math.min(bits - bitsDecoded, BYTE_SIZE - codeOffset);
                    var msbits = data[codeIndex];

                    // First shift left to erase the most significant bits then
                    // shift right to get the correct number of bits.
                    msbits <<= codeOffset;
                    msbits &= 0xff;
                    msbits >>>= BYTE_SIZE - bitlen;

                    // If we read to the end of this byte then zero the code bit
                    // offset and remove the byte.
                    bitsDecoded += bitlen;
                    codeOffset += bitlen;
                    if (codeOffset == BYTE_SIZE) {
                        codeOffset = 0;
                        ++codeIndex;
                    }

                    // Shift left by the number of bits remaining to decode and add
                    // the current bits to the value.
                    code |= (msbits & 0xff) << (bits - bitsDecoded);
                }

                // Grab the bytes for this code.
                var value = dictionary[code];
                // This is the first iteration. The next code will have a larger
                // bit length.
                if (prevvalue.length == 0) {
                    ++bits;
                }

                // If there is previous data then add the previous data plus this
                // data's first character to the dictionary.
                else {
                    // If the code was not in the dictionary then we have
                    // encountered the code that we are going to enter into the
                    // dictionary right now.
                    //
                    // This is the odd case where the decoder is one code behind
                    // the encoder in populating the dictionary and the byte that
                    // will be added to create the sequence is equal to the first
                    // byte of the previous sequence.
                    if (!value) {
                        prevvalue.push(prevvalue[0]);
                    } else {
                        prevvalue.push(value[0]);
                    }

                    // Add the dictionary entry.
                    dictionary[dictionary.length] = prevvalue;
                    prevvalue = [];

                    // If we just generated the code for 2^p - 1 then increment the
                    // code bit length.
                    if (dictionary.length == (1 << bits))
                        ++bits;

                    // If the code was not in the dictionary before, it should be
                    // now. Grab the data.
                    if (!value)
                        value = dictionary[code];
                }

                nextIndex = index + value.length;
                
                // Check if the deflate ratio has been exceeded.
                if (nextIndex > maxDeflateRatio * data.length)
                    throw new MslIoException("Deflate ratio " + maxDeflateRatio + " exceeded. Aborting uncompression.");

                // Expand the uncompressed data container if necessary.
                if (nextIndex >= uncompressed.length) {
                    var u = new Uint8Array(Math.ceil(nextIndex * 1.5));
                    u.set(uncompressed);
                    uncompressed = u;
                }

                // Append the decoded bytes to the uncompressed data.
                uncompressed.set(value, index);
                index = nextIndex;

                // Save this data for the next iteration.
                prevvalue = prevvalue.concat(value);
            }

            // Return the uncompressed data which may be empty.
            return uncompressed.subarray(0, index);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('LzwCompression'));
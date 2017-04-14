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
 * Utility methods.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
    
    const MslConstants = require('../MslConstants.js');
    const MslException = require('../MslException.js');
    const MslError = require('../MslError.js');
    const lzw = require('lzw');
    const gzip = require('gzip');

    // Shortcuts
    var CompressionAlgorithm = MslConstants.CompressionAlgorithm;

    /**
     * Compress the provided data using the specified compression algorithm.
     *
     * @param {CompressionAlgorithm} compressionAlgo the compression algorithm.
     * @param {Uint8Array} data the data to compress.
     * @return {Uint8Array} the compressed data or null if the compressed data would be larger than the
     *         uncompressed data.
     * @throws MslException if there is an error compressing the data.
     */
    var MslUtils$compress = function MslUtils$compress(compressionAlgo, data) {
        switch (compressionAlgo) {
        case CompressionAlgorithm.LZW:
            return lzw.compress(data);
        case CompressionAlgorithm.GZIP:
            if (typeof gzip.compress === "function")
                return gzip.compress(data);
        default:
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo);
        }
    };

    /**
     * Uncompress the provided data using the specified compression algorithm.
     *
     * @param {CompressionAlgorithm} compressionAlgo the compression algorithm.
     * @param {Uint8Array} data the data to uncompress.
     * @return {Uint8Array} the uncompressed data.
     * @throws MslException if there is an error uncompressing the data.
     */
    var MslUtils$uncompress = function MslUtils$uncompress(compressionAlgo, data, callback) {
        switch (compressionAlgo) {
        case CompressionAlgorithm.LZW:
                        return lzw.extend(data);
        case CompressionAlgorithm.GZIP:
            if (typeof gzip.uncompress === "function")
                return gzip.uncompress(data);
        default:
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
        }
    };
    
    // Exports.
    module.exports.compress = MslUtils$compress;
    module.exports.uncompress = MslUtils$uncompress;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslUtils'));

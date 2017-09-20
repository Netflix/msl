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
    
    const MslConstants = require('../MslConstants.js');
    const MslException = require('../MslException.js');
    const MslError = require('../MslError.js');
    const Base64 = require('../util/Base64.js');
    
    const lzw = require('../lib/lzw.js');
    const zlib = require('zlib');

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
        try {
            switch (compressionAlgo) {
                case CompressionAlgorithm.LZW:
                {
                    if (lzw && typeof lzw.compress === 'function') {
                        var compressed = lzw.compress(data);
                        return (compressed && compressed.length < data.length) ? compressed : null;
                    }
                    break;
                }
                case CompressionAlgorithm.GZIP:
                {
                    if (zlib && typeof zlib.deflateSync === 'function') {
                        var deflated = zlib.deflateSync(data);
                        return (deflated && deflated.length < data.length) ? deflated : null;
                    }
                    break;
                }
            }
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo);
        } catch (e) {
            if (e instanceof MslException)
                throw e;
            var dataB64 = Base64.encode(data);
            throw new MslException(MslError.COMPRESSION_ERROR, "algo " + compressionAlgo + " data " + dataB64, e);
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
        try {
            switch (compressionAlgo) {
                case CompressionAlgorithm.LZW:
                {
                    if (lzw && typeof lzw.extend === 'function')
                        return lzw.extend(data);
                    break;
                }
                case CompressionAlgorithm.GZIP:
                {
                    if (zlib && typeof zlib.inflateSync === "function")
                        return zlib.inflateSync(data);
                    break;
                }
            }
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
        } catch (e) {
            if (e instanceof MslException)
                throw e;
            var dataB64 = Base64.encode(data);
            throw new MslException(MslError.UNCOMPRESSION_ERROR, "algo " + compressionAlgo + " data " + dataB64, e);
        }
    };
    
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
    
    // Exports.
    module.exports.compress = MslUtils$compress;
    module.exports.uncompress = MslUtils$uncompress;
    module.exports.safeEquals = MslUtils$safeEquals;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslUtils'));

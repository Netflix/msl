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
 * <p>Data compression and uncompression. Can be configured with a backing
 * implementation.</p>
 * 
 * <p>This class is thread-safe.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var MslConstants = require('../MslConstants.js');
    var MslException = require('../MslException.js');
    var MslError = require('../MslError.js');
    var Class = require('../util/Class.js');
    var MslIoException = require('../MslIoException.js');
    
    // Shortcuts
    var CompressionAlgorithm = MslConstants.CompressionAlgorithm;
    
    /**
     * Registered compression implementations.
     * @type {Object<CompressionAlgorithm,CompressionImpl>}
     */
    var impls = {};
    
    /**
     * Maximum deflate ratio.
     * @type {number}
     */
    var maxDeflateRatio = 200;
    
    /**
     * <p>A data compression implementation. Implementations must be thread-
     * safe.</p>
     */
    var CompressionImpl = Class.create({
        /**
         * Compress the provided data.
         * 
         * @param {Uint8Array} data the data to compress.
         * @return {?Uint8Array} the compressed data. May also return {@code null} if the
         *         compressed data would exceed the original data size.
         * @throws IOException if there is an error compressing the data.
         */
        compress: function(data) {},
        
        /**
         * <p>Uncompress the provided data.</p>
         *
         * <p>If the uncompressed data ever exceeds the maximum deflate ratio
         * then uncompression must abort and an exception thrown.</p>
         * 
         * @param {Uint8Array} data the data to uncompress.
         * @param {number} maxDeflateRatio the maximum deflate ratio.
         * @return {Uint8Array} the uncompressed data.
         * @throws IOException if there is an error uncompressing the data or
         *         if the ratio of uncompressed data to the compressed data
         *         ever exceeds the specified deflate ratio.
         */
        uncompress: function(data, maxDeflateRatio) {},
    });
        
    /**
     * <p>Register a compression algorithm implementation. Pass {@code null} to
     * remove an implementation.</p>
     * 
     * @param {CompressionAlgorithm} algo the compression algorithm.
     * @param {CompressionImpl} impl the data compression implementation. May be {@code null}.
     */
    function MslCompression$register(algo, impl) {
        if (!impl)
            delete impls[algo];
        else
            impls[algo] = impl;
    }

    /**
     * <p>Sets the maximum deflate ratio used during uncompression. If the
     * ratio is exceeded uncompression will abort.</p>
     *
     * @param {number} deflateRatio the maximum deflate ratio.
     * @throws RangeError if the specified ratio is less than one.
     */
    function MslCompression$setMaxDeflateRatio(deflateRatio) {
        if (deflateRatio < 1)
            throw new RangeError("The maximum deflate ratio must be at least one.");
        maxDeflateRatio = deflateRatio;
    }

    /**
     * Compress the provided data using the specified compression algorithm.
     * 
     * @param {CompressionAlgorithm} compressionAlgo the compression algorithm.
     * @param {Uint8Array} data the data to compress.
     * @return {?Uint8Array} the compressed data or null if the compressed data would be larger than the
     *         uncompressed data.
     * @throws MslException if there is an error compressing the data.
     */
    function MslCompression$compress(compressionAlgo, data) {
        var impl = impls[compressionAlgo];
        if (!impl)
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo);
        try {
            var compressed = impl.compress(data);
            return (compressed && compressed.length < data.length) ? compressed : null;
        } catch (e) {
            if (e instanceof MslIoException)
                throw new MslException(MslError.COMPRESSION_ERROR, "algo " + compressionAlgo, e);
            throw e;
        }
    }

    /**
     * Uncompress the provided data using the specified compression algorithm.
     * 
     * @param {CompressionAlgorithm} compressionAlgo the compression algorithm.
     * @param {Uint8Array} data the data to uncompress.
     * @return {Uint8Array} the uncompressed data.
     * @throws MslException if there is an error uncompressing the data.
     */
    function MslCompression$uncompress(compressionAlgo, data) {
        var impl = impls[compressionAlgo];
        if (!impl)
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo);
        try {
            return impl.uncompress(data);
        } catch (e) {
            if (e instanceof MslIoException)
                throw new MslException(MslError.UNCOMPRESSION_ERROR, "algo " + compressionAlgo, e);
            throw e;
        }
    }
    
    // Exports.
    module.exports.CompressionImpl = CompressionImpl;
    module.exports.register = MslCompression$register;
    module.exports.setMaxDeflateRatio = MslCompression$setMaxDeflateRatio;
    module.exports.compress = MslCompression$compress;
    module.exports.uncompress = MslCompression$uncompress;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslCompression'));
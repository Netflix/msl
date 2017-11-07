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
(function(require, module) {
    "use strict";
    
    var MslConstants = require("msl-core/MslConstants.js");
    var MslCompression = require("msl-core/util/MslCompression.js");
    
    var zlib = require('zlib');

    // Shortcuts.
    var CompressionAlgorithm = MslConstants.CompressionAlgorithm;
    var CompressionImpl = MslCompression.CompressionImpl;

    var GzipCompression = module.exports = CompressionImpl.extend({
        /** @inheritDoc */
        compress: function(data) {
            return zlib.deflateSync(data);
        },

        /** @inheritDoc */
        uncompress: function(data) {
            return zlib.inflateSync(data);
        }
    });

    // Export Node GZIP.
    var gzip = new GzipCompression();
    MslCompression.register(CompressionAlgorithm.GZIP, gzip);
})(require, (typeof module !== 'undefined') ? module : mkmodule('NodeGzipCompression'));

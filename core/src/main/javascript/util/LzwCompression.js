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
    
    var lzw = require('../lib/lzw.js');
    
    // Shortcuts.
    var CompressionImpl = MslCompression.CompressionImpl;
    
    /**
     * Default LZW compression implementation.
     */
    var LzwCompression = module.exports = CompressionImpl.extend({
        /** @inheritDoc */
        compress: function compress(data) {
            return lzw.compress(data);
        },
        
        /** @inheritDoc */
        uncompress: function uncompress(data) {
            return lzw.extend(data);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('LzwCompression'));
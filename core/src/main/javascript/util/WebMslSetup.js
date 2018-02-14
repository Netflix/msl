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
 * <p>Default MSL setup for a web environment.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var Base64Secure = require('../util/Base64Secure.js');
    var LzwCompression = require('../util/LzwCompression.js');
    var TextEncodingUtf8 = require('../util/TextEncodingUtf8.js');
    var MslConstants = require('../MslConstants.js');

    var MslSetup = require('../util/MslSetup.js');

    var WebMslSetup = module.exports = MslSetup.extend({
        /**
         * <p>Create new default MSL setup for a web environment.</p>
         */
        init: function init() {
            var base64Impl = new Base64Secure();
            var compressionImpls = {};
            compressionImpls[MslConstants.CompressionAlgorithm.LZW] = new LzwCompression();
            var textEncodingImpl = new TextEncodingUtf8();
            
            // The properties.
            var props = {
                _base64Impl: { value: base64Impl, writable: false, enumerable: false, configurable: false },
                _compressionImpls: { value: compressionImpls, writable: false, enumerable: false, configurable: false },
                _textEncodingImpl: { value: textEncodingImpl, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        getBase64Impl: function getBase64Impl() {
            return this._base64Impl;
        },
        
        /** @inheritDoc */
        getCompressionImpls: function getCompressionImpls() {
            return this._compressionImpls;
        },
        
        /** @inheritDoc */
        getTextEncodingImpl: function getTextEncodingImpl() {
            return this._textEncodingImpl;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('WebMslSetup'));
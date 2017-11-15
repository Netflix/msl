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
 * <p>Initializes MSL with default implementions in a web environment.</p>
 */
(function(require, module) {
    "use strict";
    
    var Base64Secure = require('../util/Base64Secure.js');
    var LzwCompression = require('../util/LzwCompression.js');
    var MslConstants = require('../MslConstants.js');

    var MslInit = require('../util/MslInit.js');

    var config = {};
    config[MslInit.KEY_BASE64] = new Base64Secure();
    config[MslInit.KEY_COMPRESSION] = {};
    config[MslInit.KEY_COMPRESSION][MslConstants.CompressionAlgorithm.LZW] = new LzwCompression();
    console.log(config);
    MslInit.initialize(config);
})(require, (typeof module !== 'undefined') ? module : mkmodule('WebMslInit'));
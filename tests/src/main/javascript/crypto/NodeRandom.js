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
 * <p>A Node.js crypto implementation of the MSL random abstraction.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var Random = require('../../../../../core/src/main/javascript/util/Random.js');

    var crypto = require('crypto');
    
    var NodeRandom = module.exports = {
        /**
         * Fill the provided array buffer with random bytes.
         * 
         * @param {Uint8Array} b the array buffer.
         */
        getRandomValues(b) {
            var bytes = crypto.randomBytes(b.length);
            b.set(bytes);
        },
    };

    // Export Node random.
    Random.setRandom(NodeRandom);
})(require, (typeof module !== 'undefined') ? module : mkmodule('NodeRandom'));
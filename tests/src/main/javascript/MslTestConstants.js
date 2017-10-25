/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 * Constants common to many unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var MslTestConstants = module.exports = {
        /** MslContext initialization timeout in milliseconds. */
        TIMEOUT_CTX: 1500,
        /** Crypto (expensive) operation timeout in milliseconds. */
        TIMEOUT_CRYPTO: 900,
        /** Default test timeout in milliseconds. */
        TIMEOUT: 100,
    };
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslTestConstants'));
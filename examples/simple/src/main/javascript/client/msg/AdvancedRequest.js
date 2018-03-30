/**
 * Copyright (c) 2015-2018 Netflix, Inc.  All rights reserved.
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
 * <p>Advanced request type.</p>
 *
 * <p>Advanced requests have no defined message structure and instead contain
 * exactly the application data provided.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */

(function(require, module) {
    "use strict";

    var Class = require('msl-core/util/Class.js');

    var AdvancedRequest = module.exports = Class.create({
        /**
         * <p>Create an advanced request with the specified message properties
         * and application data.</p>
         *
         * @param {string} identity the remote entity identity. May be null.
         * @param {boolean} isEncrypted true if encryption is required.
         * @param {boolean} isIntegrityProtected true if integrity protection
         *        is required.
         * @param {boolean} isNonReplayable true if the application data must
         *        be non-replayable.
         * @param {boolean} isRequestingTokens true if the application expects
         *        tokens in the response.
         * @param {Uint8Array} data the application data.
         */
        init: function init(identity, isEncrypted, isIntegrityProtected, isNonReplayable, isRequestingTokens, data) {
            // Set properties.
            var props = {
                data: { value: data, writable: false, enumerable: true, configurable: false },
                // Message context properties.
                remoteEntityIdentity: { value: identity, writable: false, enuemrable: true, configurable: false },
                isEncrypted: { value: isEncrypted, writable: false, enumerable: true, configurable: false },
                isIntegrityProtected: { value: isIntegrityProtected, writable: false, enumerable: true, configurable: false },
                isNonReplayable: { value: isNonReplayable, writable: false, enumerable: true, configurable: false },
                isRequestingTokens: { value: isRequestingTokens, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('AdvancedRequest'));

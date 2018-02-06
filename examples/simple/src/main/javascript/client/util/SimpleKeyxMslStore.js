/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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

    var SimpleMslStore = require('msl-core/util/SimpleMslStore.js');

    /**
     * <p>An in-memory MSL store that manages state and is integrated with the
     * key exchange manager to trigger key exchange request data generation
     * upon successful receipt of key response data.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleKeyxMslStore = module.exports = SimpleMslStore.extend({
        /**
         * <p>Create a new key exchange-aware MSL store.</p>
         *
         * @param {SimpleKeyxManager} keyxMgr key exchange manager.
         * @param {function(string|Error)} errorCallback key manager generation error
         *        callback.
         */
        init: function init(keyxMgr, errorCallback) {
            init.base.call(this);

            // Set properties.
            var props = {
                _keyxMgr: { value: keyxMgr, writable: false, enumerable: false, configurable: false },
                _errorCallback: { value: errorCallback, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        setCryptoContext: function setCryptoContext(masterToken, cryptoContext) {
            setCryptoContext.base.call(this, masterToken, cryptoContext);

            // If we receive a new master token then trigger key request data
            // generation.
            this._keyxMgr.regenerate({
                result: function(success) {
                    if (!success)
                        this._errorCallback("Failed to regenerate key exchange data.");
                },
                error: this._errorCallback
            });
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleKeyxMslStore'));

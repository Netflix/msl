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
 * This crypto context repository provides a simple in-memory store of wrapping
 * key crypto contexts.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var WrapCryptoContextRepository = require('msl-core/keyx/WrapCryptoContextRepository.js');
    var Base64 = require('msl-core/util/Base64.js');
    
    var MockCryptoContextRepository = module.exports = WrapCryptoContextRepository.extend({
        init: function init() {
            // The properties.
            var props = {
                /**
                 * Newest wrap data.
                 * @type {Uint8Array}
                 */
                _wrapdata : { value: null, writable: true, enumerable: false, configurable: false },
                _wrapdataB64 : { value: null, writable: true, enumerable: false, configurable: false },
                /**
                 * Map of wrap data onto crypto contexts.
                 * @type {Object.<String,ICryptoContext>}
                 */
                _cryptoContexts: { value: {}, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        addCryptoContext: function addCryptoContext(wrapdata, cryptoContext) {
            var key = Base64.encode(wrapdata);
            this._cryptoContexts[key] = cryptoContext;
            this._wrapdata = wrapdata;
            this._wrapdataB64 = key;
        },
    
        /** @inheritDoc */
        getCryptoContext: function getCryptoContext(wrapdata) {
            var key = Base64.encode(wrapdata);
            return (this._cryptoContexts[key]) ? this._cryptoContexts[key] : null;
        },
    
        /** @inheritDoc */
        removeCryptoContext: function removeCryptoContext(wrapdata) {
            var key = Base64.encode(wrapdata);
            delete this._cryptoContexts[key];
            if (this._wrapdataB64 == key) {
                this._wrapdata = null;
                this._wrapdataB64 = null;
            }
        },
        
        /**
         * @return {Uint8Array} the newest wrap data or null if there is none.
         */
        getWrapdata: function getWrapdata() {
            return this._wrapdata;
        },
        
        /**
         * Clear the repository of all state data.
         */
        clear: function clear() {
            this._cryptoContexts = {};
            this._wrapdata = null;
            this._wrapdataB64 = null;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockCryptoContextRepository'));
/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * Test Diffie-Hellman parameters.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var DiffieHellmanParameters = require('msl-core/keyx/DiffieHellmanParameters.js');
    var DhParameterSpec = require('msl-core/keyx/DhParameterSpec.js');

    /** Default parameters. */
    var p = new Uint8Array([23]);
    var g = new Uint8Array([5]);
    
    /** Default parameter ID. */
    var DEFAULT_ID = "default1";
    
    var MockDiffieHellmanParameters = module.exports = DiffieHellmanParameters.extend({
        /**
         * Create a new test Diffie-Hellman parameters instance.
         */
        init: function init() {
            // Define properties.
            var props = {
                params: { value: {}, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /**
         * Add Diffie-Hellman parameters.
         * 
         * @param {string} id parameters ID.
         * @param {DHParameterSpec} spec Diffie-Hellman parameters.
         */
        addParameterSpec: function addParameterSpec(id, spec) {
            this.params[id] = spec;
        },
        
        /**
         * Remove all known parameter specs.
         */
        clear: function clear() {
            this.params = {};
        },
        
        /** @inheritDoc */
        getParameterSpecs: function getParameterSpecs() {
            return this.params;
        },
    
        /** @inheritDoc */
        getParameterSpec: function getParameterSpec(id) {
            return this.params[id];
        },
    });
    
    /**
     * Returns the default test parameters containing a single set of Diffie-
     * Hellman parameters associated with parameter ID {@link #DEFAULT_ID}.
     * 
     * @return the default test parameters.
     */
    var MockDiffieHellmanParameters$getDefaultParameters = function MockDiffieHellmanParameters$getDefaultParameters() {
        var params = new MockDiffieHellmanParameters();
        var paramSpec = new DhParameterSpec(p, g);
        params.addParameterSpec(DEFAULT_ID, paramSpec);
        return params;
    };
    
    // Exports.
    module.exports.DEFAULT_ID = DEFAULT_ID;
    module.exports.getDefaultParameters = MockDiffieHellmanParameters$getDefaultParameters;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockDiffieHellmanParameters'));
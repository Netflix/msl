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
 * Diffie-Hellman parameter specification.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	
    var DhParameterSpec = module.exports = Class.create({
        /**
         * Create a new Diffie-Hellman parameter specification with the provided
         * prime modulus and base generator.
         * 
         * @param {Uint8Array} p prime modulus.
         * @param {Uint8Array} g base generator.
         */
        init: function init(p, g) {
            // Set properties.
            var props = {
                p: { value: p, writable: false, configurable: false },
                g: { value: g, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('DhParameterSpec'));
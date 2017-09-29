/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Provisioned entity authentication data. This form of authentication is
 * used by entities that cannot provide any form of entity authentication and
 * also want to delegate the generation or assignment of their identity to the
 * remote entity.</p>
 * 
 * <p>Provisioned entity authentication data is represented as
 * {@code
 * provisionedauthdata = {
 * }}</p>
 * 
 * <p>Until the entity identity has been provisioned, the entity identity will
 * be equal to the empty string.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var EntityAuthenticationData = require('../entityauth/EntityAuthenticationData.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    
    var ProvisionedAuthenticationData = module.exports = EntityAuthenticationData.extend({
        /**
         * Construct a new provisioned entity authentication data instance. 
         */
        init: function init() {
            init.base.call(this, EntityAuthenticationScheme.PROVISIONED);
            
            // The properties.
            var props = {
                /**
                 * Entity identity.
                 * @type {string}
                 */
                identity: { value: null, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /**
         * <p>Sets the entity identity.</p>
         * 
         * @param {string} identity the entity identity.
         */
        setIdentity: function setIdentity(identity) {
            this.identity = identity;
        },
        
        /** @inheritDoc */
        getIdentity: function getIdentity() {
            return this.identity;
        },
        
        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof ProvisionedAuthenticationData)) return false;
            return (equals.base.call(this, that));
        }
    });
    
    var ProvisionedAuthenticationData$parse = function ProvisionedAuthenticationData$parse(provisionedAuthJo) {
        return new ProvisionedAuthenticationData();
    };
    
    // Exports.
    module.exports.parse = ProvisionedAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('ProvisionedAuthenticationData'));

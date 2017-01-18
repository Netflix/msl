/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
 * <p>Provisioned entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var ProvisionedAuthenticationFactory;

/**
 * An identity provisioning service returns unique entity identities.
 * @interface
 */
var ProvisionedAuthenticationFactory$IdentityProvisioningService;

(function() {
    "use strict";

    var IdentityProvisioningService = ProvisionedAuthenticationFactory$IdentityProvisioningService = util.Class.create({
        /**
         * @return {string} the next unique entity identity.
         */
        nextIdentity: function() {},
    });

    ProvisionedAuthenticationFactory = EntityAuthenticationFactory.extend({
        /**
         * Construct a new provisioned authentication factory instance.
         * 
         * @param {IdentityProvisioningService} service the identity provisioning service to use.
         */
        init: function init(service) {
            init.base.call(this, EntityAuthenticationScheme.PROVISIONED);
            
            // The properties.
            var props = {
                service: { value: service, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        createData: function createData(ctx, entityAuthJO, callback) {
            AsyncExecutor(callback, function() {
                return new ProvisionedAuthenticationData(entityAuthJO);
            });
        },
        
        /** @inheritDoc */
        getCryptoContext: function getCryptoContext(ctx, authdata) {
            // Make sure we have the right kind of entity authentication data.
            if (!(authdata instanceof ProvisionedAuthenticationData))
                throw new MslInternalException("Incorrect authentication data type " + authdata + ".");
            var pad = authdata;
            
            // Provision an entity identity.
            var identity = service.nextIdentity();
            pad.setIdentity(identity);
            
            // Return the crypto context.
            return new NullCryptoContext();
        },
    });
})();

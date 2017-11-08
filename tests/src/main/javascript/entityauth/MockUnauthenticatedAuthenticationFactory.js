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
 * Test unauthenticated authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var UnauthenticatedAuthenticationFactory = require('msl-core/entityauth/UnauthenticatedAuthenticationFactory.js');
    var UnauthenticatedAuthenticationData = require('msl-core/entityauth/UnauthenticatedAuthenticationData.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var MslError = require('msl-core/MslError.js');
    
    var MockAuthenticationUtils = require('../util/MockAuthenticationUtils.js');
    
    var MockUnauthenticatedAuthenticationFactory = module.exports = UnauthenticatedAuthenticationFactory.extend({
        /**
         * Create a new test unauthenticated authentication factory.
         */
        init: function init() {
            init.base.call(this, new MockAuthenticationUtils());
    
            // Define properties.
            var props = {
                _revokedIdentity: { value: null, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    
        /** @inheritDoc */
        getCryptoContext: function getCryptoContext(ctx, authdata) {
            // Check for revocation.
            if (authdata instanceof UnauthenticatedAuthenticationData) {
                var identity = authdata.identity;
                if (this._revokedIdentity && identity == this._revokedIdentity)
                    throw new MslEntityAuthException(MslError.ENTITY_REVOKED, identity);
            }
            return getCryptoContext.base.call(this, ctx, authdata);
        },
    
        /**
         * Set the revoked entity identity. If {@code null} all identities are
         * accepted.
         * 
         * @param {string} identity revoked entity identity. May be {@code null}.
         */
        setRevokedIdentity: function setRevokedIdentity(identity) {
            this._revokedIdentity = identity;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockUnauthenticatedAuthenticationFactory'));

/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
 * <p>A user authentication factory creates authentication data instances and
 * performs authentication for a specific user authentication scheme.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    
    var UserAuthenticationFactory = module.exports = Class.create({
        /**
         * Create a new user authentication factory for the specified scheme.
         *
         * @param scheme the user authentication scheme.
         * @constructor
         * @interface
         */
        init: function init(scheme) {
            // The properties.
            var props = {
                scheme: { value: scheme, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    
        /**
         * <p>Construct a new user authentication data instance fromthe provided
         * JSON.</p>
         * 
         * <p>A master token may be required for certain user authentication
         * schemes.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {MasterToken} the entity master token. May be {@code null}.
         * @param {MslObject} entityAuthMo the MSL object.
         * @param {{result: function(UserAuthenticationData), error: function(Error)}}
         *        callback the callback functions that will receive the user
         *        authentication data or any thrown exceptions.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslUserAuthException if there is an error creating the user
         *         authentication data.
         * @throws MslCryptoException if there is an error with the user
         *         authentication data cryptography.
         */
        createData: function(ctx, masterToken, entityAuthMo, callback) {},
    
        /**
         * <p>Authenticate the user using the provided authentication data.</p>
         * 
         * <p>If a user ID token is provided then also validate the authenticated
         * user against the provided user ID token. This is typically a check to
         * ensure the user identities are equal but not always. The returned
         * user must be the user identified by the user ID token.</p>
         *
         * @param {MslContet} ctx MSL context.
         * @param {string} identity the entity identity.
         * @param {UserAuthenticationData} data the user authentication data.
         * @param {?UserIdToken} userIdToken user ID token. May be {@code null}.
         * @param {{result: function(MslUser), error: function(Error)}}
         *        callback the callback that will receive the MSL user or any
         *        thrown exceptions.
         * @throws MslUserAuthException if there is an error authenticating the
         *         user.
         * @throws MslUserIdTokenException if there is a problem with the user ID
         *         token.
         */
        authenticate: function(ctx, identity, data, userIdToken, callback) {},
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('UserAuthenticationFactory'));
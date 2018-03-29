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

/**
 * Test user ID token authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var UserAuthenticationFactory = require('msl-core/userauth/UserAuthenticationFactory.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var UserIdTokenAuthenticationData = require('msl-core/userauth/UserIdTokenAuthenticationData.js');
    var MslUserAuthException = require('msl-core/MslUserAuthException.js');
    var MslException = require('msl-core/MslException.js');
    var MslError = require('msl-core/MslError.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    
    var MockUserIdTokenAuthenticationFactory = module.exports = UserAuthenticationFactory.extend({
        /**
         * Create a new test user ID token authentication factory. By default no
         * tokens are accepted.
         */
        init: function init() {
            init.base.call(this, UserAuthenticationScheme.USER_ID_TOKEN);
            
            // The properties.
            var props = {
                masterToken: { value: null, writable: true, configurable: false },
                userIdToken: { value: null, writable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    
        /**
         * <p>Set the master token and user ID token pair to accept. The user ID
         * token must be bound to the master token.</p>
         * 
         * @param {MasterToken} masterToken the master token to accept.
         * @param {UserIdToken} userIdToken the user ID token to accept.
         */
        setTokens: function setTokens(masterToken, userIdToken) {
            if (!userIdToken.isBoundTo(masterToken))
                throw new MslInternalException("The user ID token must be bound to the master token.");
            this.masterToken = masterToken;
            this.userIdToken = userIdToken;
        },
    
        /** @inheritDoc */
        createData: function createData(ctx, masterToken, userAuthMo, callback) {
            UserIdTokenAuthenticationData.parse(ctx, userAuthMo, callback);
        },
    
        /** @inheritDoc */
        authenticate: function authentication(ctx, identity, data, userIdToken, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                // Make sure we have the right kind of user authentication data.
                if (!(data instanceof UserIdTokenAuthenticationData))
                    throw new MslInternalException("Incorrect authentication data type " + data + ".");
                var uitad = data;

                // Extract and check master token.
                var uitadMasterToken = uitad.masterToken;
                var uitadIdentity = uitadMasterToken.identity;
                if (!uitadIdentity)
                    throw new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_NOT_DECRYPTED).setUserAuthenticationData(uitad);
                if (identity != uitadIdentity)
                    throw new MslUserAuthException(MslError.USERAUTH_ENTITY_MISMATCH, "entity identity " + identity + "; uad identity " + uitadIdentity).setUserAuthenticationData(uitad);

                // Authenticate the user.
                var uitadUserIdToken = uitad.userIdToken;
                var user = uitadUserIdToken.user;
                if (!user)
                    throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_NOT_DECRYPTED).setUserAuthenticationData(uitad);

                // Verify the user.
                if (!uitadMasterToken.equals(this.masterToken) ||
                        !uitadUserIdToken.equals(this.userIdToken))
                {
                    throw new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA, "Authentication scheme " + this.scheme.name + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);
                }

                // Verify token has not been revoked.
                ctx.getTokenFactory().isUserIdTokenRevoked(ctx, uitadMasterToken, uitadUserIdToken, {
                    result: function(revokeMslError) {
                        AsyncExecutor(callback, function() {
                            if (revokeMslError)
                                throw new MslUserAuthException(revokeMslError, "User ID token used to authenticate was revoked.").setUserAuthenticationData(uitad);
                            validateIdentities(user, uitad);
                        }, self);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException)
                                throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_REVOKE_CHECK_ERROR, "Error while checking User ID Token for revocation", e).setUserAuthenticationData(uitad);
                            throw e;
                        }, self);
                    }
                });
            }, self);
            
            function validateIdentities(user, uitad) {
                AsyncExecutor(callback, function() {
                    // If a user ID token was provided validate the user identities.
                    if (userIdToken) {
                        var uitUser = userIdToken.user;
                        if (!user.equals(uitUser))
                            throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser).setUserAuthenticationData(uitad);
                    }

                    // Return the user.
                    return user;
                }, this);
            }
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockUserIdTokenAuthenticationFactory'));
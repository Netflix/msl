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
 * <p>User ID token-based user authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "mastertoken", "useridtoken" ],
 *   "mastertoken" : mastertoken,
 *   "useridtoken" : useridtoken,
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token</li>
 * <li>{@code useridtoken} is the user ID token</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var UserAuthenticationData = require('../userauth/UserAuthenticationData.js');
	var UserAuthenticationScheme = require('../userauth/UserAuthenticationScheme.js');
	var MslInternalException = require('../MslInternalException.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var UserIdToken = require('../tokens/UserIdToken.js');
	var MslException = require('../MslException.js');
	var MslUserAuthException = require('../MslUserAuthException.js');
    
    /**
     * Key master token key.
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    /**
     * Key user ID token key.
     * @const
     * @type {string}
     */
    var KEY_USER_ID_TOKEN = "useridtoken";
    
    var UserIdTokenAuthenticationData = module.exports = UserAuthenticationData.extend({
        /**
         * Construct a new user ID token authentication data instance from the
         * provided master token and user ID token.
         * 
         * @param {MasterToken} masterToken the master token.
         * @param {UserIdToken} userIdToken the user ID token.
         */
        init: function init(masterToken, userIdToken) {
            init.base.call(this, UserAuthenticationScheme.USER_ID_TOKEN);
            if (!userIdToken.isBoundTo(masterToken))
                throw new MslInternalException("User ID token must be bound to master token.");
            
            // The properties.
            var props = {
                masterToken: { value: masterToken, writable: false, configurable: false },
                userIdToken: { value: userIdToken, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getAuthData: function getAuthData(encoder, format, callback) {
        	var self = this;
        	
            AsyncExecutor(callback, function() {
                var authdata = encoder.createObject();
                authdata.put(KEY_MASTER_TOKEN, this.masterToken);
                authdata.put(KEY_USER_ID_TOKEN, this.userIdToken);
                encoder.encodeObject(authdata, format, {
                	result: function(encode) {
                		AsyncExecutor(callback, function() {
                			return encoder.parseObject(encode);
                		}, self);
                	},
                	error: callback.error,
                });
            }, self);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof UserIdTokenAuthenticationData)) return false;
            return (equals.base.call(this, this, that) &&
                this.masterToken.equals(that.masterToken) &&
                this.userIdToken.equals(that.userIdToken));
        },
    });
    
    /**
     * Construct a new user ID token authentication data instance from the
     * provided JSON representation.
     * 
     * @param {MslContext} ctx MSl context.
     * @param {MslObject} userIdTokenAuthMo the MSL object.
     * @param {{result: function(UserIdTokenAuthenticationData), error: function(Error)}}
     *        callback the callback that will receive the user ID token
     *        authentication data or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if the token data is invalid or the user ID
     *         token is not bound to the master token.
     */
    var UserIdTokenAuthenticationData$parse = function UserIdTokenAuthenticationData$parse(ctx, userIdTokenAuthMo, callback) {
        AsyncExecutor(callback, function() {
            // Extract master token and user ID token representations.
            var encoder = ctx.getMslEncoderFactory();
            var masterTokenMo, userIdTokenMo;
            try {
                masterTokenMo = userIdTokenAuthMo.getMslObject(KEY_MASTER_TOKEN, encoder);
                userIdTokenMo = userIdTokenAuthMo.getMslObject(KEY_USER_ID_TOKEN, encoder);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "user ID token authdata " + userIdTokenAuthMo, e);
                throw e;
            }
            
            // Convert any MslExceptions into MslUserAuthException because we don't
            // want to trigger entity or user re-authentication incorrectly.
            MasterToken.parse(ctx, masterTokenMo, {
                result: function(masterToken) {
                    UserIdToken.parse(ctx, userIdTokenMo, masterToken, {
                        result: function(userIdToken) {
                            AsyncExecutor(callback, function() {
                                return new UserIdTokenAuthenticationData(masterToken, userIdToken);
                            });
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException)
                                    throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_INVALID, "user ID token authdata " + userIdTokenAuthMo, e);
                                throw e;
                            });
                        },
                    });
                },
                error: function(e) {
                    AsyncExecutor(callback, function() {
                        if (e instanceof MslException)
                            throw new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_INVALID, "user ID token authdata " + userIdTokenAuthMo, e);
                        throw e;
                    });
                },
            });
        });
    };
    
    // Exports.
    module.exports.parse = UserIdTokenAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('UserIdTokenAuthenticationData'));
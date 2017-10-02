/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Email/password-based user authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "email", "password" ],
 *   "email" : "string",
 *   "password" : "string"
 * }} where:
 * <ul>
 * <li>{@code email} is the user email address</li>
 * <li>{@code password} is the user password</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var UserAuthenticationData = require('../userauth/UserAuthenticationData.js');
	var UserAuthenticationScheme = require('../userauth/UserAuthenticationScheme.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
    
    /**
     * Key email key.
     * @const
     * @type {string}
     */
    var KEY_EMAIL = "email";
    /**
     * Key password key.
     * @const
     * @type {string}
     */
    var KEY_PASSWORD = "password";

    var EmailPasswordAuthenticationData = module.exports = UserAuthenticationData.extend({
        /**
         * Construct a new email/password authentication data instance from the
         * specified email and password.
         *
         * @param {string} email the email address.
         * @param {string} password the password.
         */
        init: function init(email, password) {
            init.base.call(this, UserAuthenticationScheme.EMAIL_PASSWORD);

            // The properties.
            var props = {
                email: { value: email, writable: false, configurable: false },
                password: { value: password, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getAuthData: function getAuthData(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_EMAIL, this.email);
                mo.put(KEY_PASSWORD, this.password);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof EmailPasswordAuthenticationData)) return false;
            return (equals.base.call(this, this, that) && this.email == that.email && this.password == that.password);
        },
    });

    /**
     * Construct a new email/password authentication data instance from the
     * provided MSL representation.
     *
     * @param {MslObject} emailPasswordAuthMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    var EmailPasswordAuthenticationData$parse = function EmailPasswordAuthenticationData$parse(emailPasswordAuthMo) {
        try {
            var email = emailPasswordAuthMo.getString(KEY_EMAIL);
            var password = emailPasswordAuthMo.getString(KEY_PASSWORD);

            // Return the authentication data.
            return new EmailPasswordAuthenticationData(email, password);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "email/password authdata " + emailPasswordAuthMo, e);
            throw e;
        }
    };
    
    // Exports.
    module.exports.parse = EmailPasswordAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('EmailPasswordAuthenticationData'));

/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
var EmailPasswordAuthenticationData;
var EmailPasswordAuthenticationData$parse;

(function() {
    "use strict";
    
    /**
     * JSON email key.
     * @const
     * @type {string}
     */
    var KEY_EMAIL = "email";
    /**
     * JSON password key.
     * @const
     * @type {string}
     */
    var KEY_PASSWORD = "password";

    EmailPasswordAuthenticationData = UserAuthenticationData.extend({
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
        getAuthData: function getAuthData() {
            var result = {};
            result[KEY_EMAIL] = this.email;
            result[KEY_PASSWORD] = this.password;
            return result;
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
     * provided JSON representation.
     *
     * @param {Object} emailPasswordAuthJO the JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON.
     */
    EmailPasswordAuthenticationData$parse = function EmailPasswordAuthenticationData$parse(emailPasswordAuthJO) {
        var email = emailPasswordAuthJO[KEY_EMAIL];
        var password = emailPasswordAuthJO[KEY_PASSWORD];

        // Verify authentication data.
        if (typeof email !== 'string' || typeof password !== 'string')
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "email/password authdata " + JSON.stringify(emailPasswordAuthJO));

        // Return the authentication data.
        return new EmailPasswordAuthenticationData(email, password);
    };
})();

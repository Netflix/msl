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
 * <p>The user authentication data provides proof of user identity.</p>
 *
 * <p>Specific user authentication mechanisms should define their own user
 * authentication data types.</p>
 *
 * <p>User authentication data is represented as
 * {@code
 * userauthdata = {
 *   "#mandatory" : [ "scheme"., "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where
 * <ul>
 * <li>{@code scheme} is the user authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific authentication data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var UserAuthenticationData;
var UserAuthenticationData$parse;

(function() {
    /**
     * JSON key user authentication scheme.
     * @const
     * @type {string}
     */
    var KEY_SCHEME = "scheme";
    /**
     * JSON key user authentication data.
     * @const
     * @type {string}
     */
    var KEY_AUTHDATA = "authdata";

    UserAuthenticationData = util.Class.create({
        /**
         * Create a new user authentication data object with the specified user
         * authentication scheme.
         *
         * @param {UserAuthenticationScheme} scheme the user authentication scheme.
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
         * Returns the scheme-specific user authentication data. This method is
         * expected to succeed unless there is an internal error.
         *
         * @return {Object} the authentication data JSON representation.
         * @throws MslEncodingException if there was an error constructing the
         *         JSON representation.
         */
        getAuthData: function() {},

        /**
         * @param {Object} that the object with which to compare.
         * @return {boolean} true if this object is equal to that object.
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof UserAuthenticationData)) return false;
            return this.scheme == that.scheme;
        },

        /** @inheritDoc */
        toJSON: function toJSON() {
            var result = {};
            result[KEY_SCHEME] = this.scheme.name;
            result[KEY_AUTHDATA] = this.getAuthData();
            return result;
        },
    });

    /**
     * <p>Construct a new user authentication data instance of the correct type
     * from the provided JSON object.</p>
     * 
     * <p>A master token may be required for certain user authentication
     * schemes.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {MasterToken} masterToken the master token associated with the user
     *        authentication data. May be {@code null}.
     * @param {Object} userAuthJO the JSON object.
     * @param {{result: function(UserAuthenticationData), error: function(Error)}}
     *        callback the callback functions that will receive the user
     *        authentication data or any thrown exceptions.
     * @return {UserAuthenticationData} the user authentication data concrete instance.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslUserAuthException if there is an error instantiating the user
     *         authentication data.
     * @throws MslCryptoException if there is an error with the entity
     *         authentication data cryptography.
     */
    UserAuthenticationData$parse = function UserAuthenticationData$parse(ctx, masterToken, userAuthJO, callback) {
        AsyncExecutor(callback, function() {
            var schemeName = userAuthJO[KEY_SCHEME];
            var authdata = userAuthJO[KEY_AUTHDATA];

            // Verify user authentication data.
            if (typeof schemeName !== 'string' ||
                typeof authdata !== 'object')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "userauthdata " + JSON.stringify(userAuthJO));
            }

            // Verify user authentication scheme.
            var scheme = UserAuthenticationScheme$getScheme(schemeName);
            if (!scheme)
                throw new MslUserAuthException(MslError.UNIDENTIFIED_USERAUTH_SCHEME, schemeName);

            // Construct an instance of the concrete subclass.
            var factory = ctx.getUserAuthenticationFactory(scheme);
            if (!factory)
                throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme.name);
            factory.createData(ctx, masterToken, authdata, callback);
        });
    };
})();

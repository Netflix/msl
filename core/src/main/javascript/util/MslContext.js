/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
 * Re-authentication reason codes.
 * @enum
 */
var MslContext$ReauthCode = {
    /** The master token was rejected as bad or invalid. */
    ENTITY_REAUTH: MslConstants$ResponseCode.ENTITY_REAUTH,
    /** The entity authentication data failed to authenticate the entity. */
    ENTITYDATA_REAUTH: MslConstants$ResponseCode.ENTITYDATA_REAUTH,
};
Object.freeze(MslContext$ReauthCode);

/**
 * <p>The context provides access to all factories, builders, and containers
 * that are needed by the MSL library. There is expected to be one global
 * context per trusted services network or peer-to-peer network. By extension,
 * the MSL store instance returned by the context is expected to be specific to
 * the owning context.</p>
 *
 * @see MslStore
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @interface
 */
var MslContext = util.Class.create({
    /**
     * <p>Returns the local entity time. This need not be the real time as long
     * as it moves forward accurately (i.e. this time value should increase by
     * one second for each second of elapsed real time).</p>
     *
     * <p>It is advisable that this time value be persistently stored so that
     * it does not roll back at next application launch. This is not necessary
     * but it will ensure issued tokens are eventually renewed.</p>
     *
     * @return {number} the local entity time in milliseconds since the epoch.
     */
    getTime: function() {},

    /**
     * <p>Returns a random number generator.</p>
     * 
     * <p>It is extremely important to provide a secure (pseudo-)random number
     * generator with a good source of entropy. Many random number generators,
     * including those found in the Java Runtime Environment, JavaScript, and
     * operating systems do not provide sufficient randomness.</p>
     * 
     * <p>If in doubt, performing an {@code XOR} on the output of two or more
     * independent random sources can be used to provide better random
     * values.</p>
     *
     * @return {Random} a random number generator.
     */
    getRandom: function() {},

    /**
     * Returns true if the context is operating in a peer-to-peer network. The
     * message processing logic is slightly different in peer-to-peer networks.
     *
     * @return {boolean} true if in peer-to-peer mode.
     */
    isPeerToPeer: function() {},

    /**
     * Returns the message capabilities for this entity.
     *
     * @return {MessageCapabilities} this entity's message capabilities.
     */
    getMessageCapabilities: function() {},

    /**
     * <p>Returns the entity authentication data for this entity. This is used
     * to authenticate messages prior to generation of a master token.</p>
     * 
     * <p>This method should never return {@code null} but may do so in the one
     * situation when the {@code reauthCode} parameter is provided and the
     * application knows that the request being sent can no longer succeed
     * because the existing master token, user ID token, or service tokens are
     * no longer valid. This will abort the request.</p>
     * 
     * <p>If the {@code reauthCode} parameter is equal to
     * {@link ReauthCode#ENTITY_REAUTH} then the existing master token has been
     * rejected, along with its bound user ID tokens and service tokens.</p>
     * 
     * <p>If the {@code reauthCode} parameter is equal to
     * {@link ReauthCode#ENTITYDATA_REAUTH} then new entity re-authentication
     * data should be returned for this and all subsequent calls.</p>
     * 
     * <p>The entity authentication scheme must never change.</p>
     * 
     * <p>This method will be called multiple times.</p>
     *
     * @param {MslControl$ReauthCode} reauthCode non-{@code null} if the master token or entity
     *        authentication data was rejected. If the entity authentication
     *        data was rejected then new entity authentication data is
     *        required.
     * @param {{result: function(?EntityAuthenticationData), error: function(Error)}}
     *        callback the callback that will receive the entity authentication
     *        data or null or any thrown exceptions.
     */
    getEntityAuthenticationData: function(reauthCode, callback) {},

    /**
     * <p>Returns the primary crypto context used for MSL-level crypto
     * operations. This is used for the master tokens and user ID tokens.</p>
     * 
     * <p>Trusted network clients should return a crypto context that always
     * returns false for verification. The other crypto context methods will
     * not be used by trusted network clients.</p>
     *
     * @return {ICryptoContext} the primary MSL crypto context.
     * @throws MslCryptoException if there is an error creating the crypto
     *         context.
     */
    getMslCryptoContext: function() {},

    /**
     * <p>Returns the entity authentication scheme identified by the specified
     * name or {@code null} if there is none.</p>
     * 
     * @param {string} name the entity authentication scheme name.
     * @return {EntityAuthenticationScheme} the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    getEntityAuthenticationScheme: function(name) {},
    
    /**
     * Returns the entity authentication factory for the specified scheme.
     *
     * @param {EntityAuthenticationScheme} scheme the entity authentication scheme.
     * @return {EntityAuthenticationFactory} the entity authentication factory, or null if no factory is
     *         available.
     */
    getEntityAuthenticationFactory: function(scheme) {},

    /**
     * <p>Returns the user authentication scheme identified by the specified
     * name or {@code null} if there is none.</p>
     * 
     * @param {string} name the user authentication scheme name.
     * @return {UserAuthenticationScheme} the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    getUserAuthenticationScheme: function getUserAuthenticationScheme(name) {},

    /**
     * Returns the user authentication factory for the specified scheme.
     *
     * Trusted network clients should always return null.
     *
     * @param {UserAuthenticationScheme} scheme the user authentication scheme.
     * @return {UserAuthenticationFactory} the user authentication factory, or null if no factory is
     *         available.
     */
    getUserAuthenticationFactory: function(scheme) {},

    /**
     * Returns the token factory.
     *
     * This method will not be called by trusted network clients.
     *
     * @return {TokenFactory} the token factory.
     */
    getTokenFactory: function() {},

    /**
     * <p>Returns the key exchange scheme identified by the specified name or
     * {@code null} if there is none.</p>
     * 
     * @param {string} name the key exchange scheme name.
     * @return {KeyExchangeScheme} the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    getKeyExchangeScheme: function getKeyExchangeScheme(name) {},

    /**
     * Returns the key exchange factory for the specified scheme.
     *
     * @param {KeyExchangeScheme} scheme the key exchange scheme.
     * @return {KeyExchangeFactory} the key exchange factory, or null if no factory is available.
     */
    getKeyExchangeFactory: function(scheme) {},

    /**
     * Returns the supported key exchange factories in order of preferred use.
     * This should return an immutable collection.
     *
     * @return {Array.<KeyExchangeFactory>} the key exchange factories, or the empty set.
     */
    getKeyExchangeFactories: function() {},

    /**
     * Returns the MSL store specific to this MSL context.
     *
     * @return {MslStore} the MSL store.
     */
    getMslStore: function() {},
});

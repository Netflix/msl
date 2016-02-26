/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
var PresharedProfileAuthenticationFactory;

/**
 * <p>Preshared keys profile entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var PresharedProfileAuthenticationFactory = EntityAuthenticationFactory.extend({
    /**
     * Construct a new preshared keys profile authentication factory instance.
     *
     * @param {PresharedKeyStore} store preshared key store.
     * @param {AuthenticationUtils} authutils authentication utilities.
     */
    init: function init(store, authutils) {
        init.base.call(this, EntityAuthenticationScheme.PSK_PROFILE);

        // The properties.
        var props = {
            store: { value: store, writable: false, enumerable: false, configurable: false },
            authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
        };
        Object.defineProperties(this, props);
    },

    /** @inheritDoc */
    createData: function createData(ctx, entityAuthJO, callback) {
        AsyncExecutor(callback, function() {
            return PresharedProfileAuthenticationData$parse(entityAuthJO);
        });
    },

    /** @inheritDoc */
    getCryptoContext: function getCryptoContext(ctx, authdata) {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof PresharedProfileAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + JSON.stringify(authdata) + ".");
        var ppad = authdata;
        
        // Check for revocation.
        var pskId = ppad.presharedKeysId;
        if (this.authutils.isEntityRevoked(pskId))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "psk profile " + pskId).setEntityAuthenticationData(ppad);
        
        // Verify the scheme is permitted.
        if (!this.authutils.isSchemePermitted(pskId, this.scheme))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication scheme for entity " + pskId + " not supported:" + this.scheme).setEntityAuthenticationData(ppad);
        
        // Load preshared keys authentication data.
        var keys = this.store.getKeys(pskId);
        if (!keys)
            throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "psk profile " + pskId).setEntityAuthenticationData(ppad);
        
        // Return the crypto context.
        var identity = ppad.getIdentity();
        return new SymmetricCryptoContext(ctx, identity, keys.encryptionKey, keys.hmacKey, keys.wrappingKey);
    },
});

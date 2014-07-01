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
var PresharedAuthenticationFactory;
var PresharedAuthenticationFactory$create;

/**
 * Preshared keys entity authentication factory.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
PresharedAuthenticationFactory = EntityAuthenticationFactory.extend({
    /**
     * Construct a new preshared keys authentication factory instance.
     *
     * @param {string} identity my local identity.
     */
    init: function init(identity) {
        init.base.call(this, EntityAuthenticationScheme.PSK);

        // The properties.
        var props = {
            localIdentity: { value: identity, writable: false, enumerable: false, configurable: false },
        };
        Object.defineProperties(this, props);
    },

    /** @inheritDoc */
    createData: function createData(ctx, entityAuthJO) {
        return PresharedAuthenticationData$parse(entityAuthJO);
    },

    /** @inheritDoc */
    getCryptoContext: function getCryptoContext(ctx, authdata) {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof PresharedAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + JSON.stringify(authdata) + ".");

        // If the authdata is not for me then we can't do anything with it.
        if (authdata.getIdentity() != this.localIdentity)
            throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "psk " + authdata.identity).setEntity(authdata);

        // Return the crypto context.
        // FIXME need the crypto stuff.
        return new NullCryptoContext();
    },
});

/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
 * <p>Master token protected entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MasterTokenProtectedAuthenticationFactory = EntityAuthenticationFactory.extend({
    /**
     * <p>Construct a new master token protected entity authentication factory
     * instance.</p>
     * 
     * @param {AuthenticationUtils} authutils authentication utilities.
     */
    init: function init(authutils) {
        init.base.call(this, EntityAuthenticationScheme.MT_PROTECTED);
        
        // The properties.
        var props = {
            authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
        };
        Object.defineProperties(this, props);
    },

    /** @inheritDoc */
    createData: function createData(ctx, entityAuthJO, callback) {
        MasterTokenProtectedAuthenticationData$parse(ctx, entityAuthJO, callback);
    },

    /** @inheritDoc */
    getCryptoContext: function getCryptoContext(ctx, authdata) {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof MasterTokenProtectedAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + JSON.stringify(authdata) + ".");
        var mtpad = authdata;

        // Check for revocation.
        var identity = mtpad.getIdentity();
        if (this.authutils.isEntityRevoked(identity))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "mt protected " + identity).setEntity(mtpad);

        // Verify the scheme is permitted.
        if (!this.authutils.isSchemePermitted(identity, this.scheme))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication scheme for entity " + identity + " not supported:" + this.scheme).setEntity(mtpad);
        
        // Authenticate using the encapsulated authentication data.
        var ead = mtpad.encapsulatedAuthdata;
        var scheme = ead.scheme;
        var factory = ctx.getEntityAuthenticationFactory(scheme);
        if (!factory)
            throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name).setEntity(mtpad);
        return factory.getCryptoContext(ctx, ead);
    },
});

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
 * An RSA public key store contains trusted RSA public keys.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var RsaStore = util.Class.create({
    init: function init() {
        // Map of RSA keys by key pair identity.
        var rsaKeys = {};

        // The properties.
        var props = {
            rsaKeys: { value: rsaKeys, writable: false, enumerable: false, configurable: false },
        };
        Object.defineProperties(this, props);
    },

    /**
     * Add an RSA public key to the store.
     *
     * @param {string} identity RSA key pair identity.
     * @param {PublicKey} RSA public key
     * @throws MslInternalException if there is a problem with the public key.
     */
    addPublicKey: function addPublicKey(identity, key) {
        if (!(key instanceof PublicKey))
            throw new MslInternalException("Incorrect key data type " + key + ".");

        this.rsaKeys[identity] = key;
    },

    /** @inheritDoc */
    getIdentities: function getIdentities() {
        return Object.keys(this.rsaKeys);
    },

    /** @inheritDoc */
    removePublicKey: function removePublicKey(identity) {
        delete this.rsaKeys[identity];
    },

    /** @inheritDoc */
    getPublicKey: function getPublicKey(identity) {
        return this.rsaKeys[identity];
    },
});

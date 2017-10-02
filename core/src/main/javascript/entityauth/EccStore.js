/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
 * An ECC public key store contains trusted ECC public keys.
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var PublicKey = require('../crypto/PublicKey.js');
	var PrivateKey = require('../crypto/PrivateKey.js');
	var MslInternalException = require('../MslInternalException.js');
		
	var EccStore = module.exports = Class.create({
	    /**
	     * <p>Create a new ECC key store that contains no keys.</p>
	     */
	    init: function init() {
	        // Map of ECC keys by key pair identity.
	        var publicKeys = {};
	        var privateKeys = {};
	
	        // The properties.
	        var props = {
	            publicKeys: { value: publicKeys, writable: true, enumerable: false, configurable: false },
	            privateKeys: { value: privateKeys, writable: true, enumerable: false, configurable: false },
	        };
	        Object.defineProperties(this, props);
	    },
	
	    /**
	     * @return {Array.<string>} the known key pair identities.
	     */
	    getIdentities: function getIdentities() {
	        var ids = Object.keys(this.publicKeys).concat(Object.keys(this.privateKeys));
	        for (var i = 0; i < ids.length; ++i) {
	            for (var j = 0; j < ids.length; ++i) {
	                if (ids[i] == ids[j])
	                    ids.splice(j--, 1);
	            }
	        }
	        return ids;
	    },
	
	    /**
	     * Add an ECC public key to the store.
	     *
	     * @param {string} identity ECC key pair identity.
	     * @param {PublicKey} key ECC public key
	     * @throws MslInternalException if there is a problem with the public key.
	     */
	    addPublicKey: function addPublicKey(identity, key) {
	        if (!(key instanceof PublicKey))
	            throw new MslInternalException("Incorrect key data type " + key + ".");
	
	        this.publicKeys[identity] = key;
	    },
	
	    /**
	     * Remove an ECC public key from the store.
	     * 
	     * @param {string} identity ECC key pair identity.
	     */
	    removePublicKey: function removePublicKey(identity) {
	        delete this.publicKeys[identity];
	    },
	
	    /**
	     * Return the public key of the identified ECC key pair.
	     *
	     * @param {string} identity ECC key pair identity.
	     * @return {PublicKey} the public key of the identified key pair or null if not found.
	     */
	    getPublicKey: function getPublicKey(identity) {
	        return this.publicKeys[identity];
	    },
	    
	    /**
	     * Add an ECC private key to the store.
	     *
	     * @param {string} identity ECC key pair identity.
	     * @param {PrivateKey} key ECC private key
	     * @throws MslInternalException if there is a problem with the private key.
	     */
	    addPrivateKey: function addPrivateKey(identity, key) {
	        if (!(key instanceof PrivateKey))
	            throw new MslInternalException("Incorrect key data type " + key + ".");
	
	        this.privateKeys[identity] = key;
	    },
	    
	    /**
	     * Remove an ECC private key from the store.
	     * 
	     * @param {string} identity ECC key pair identity.
	     */
	    removePrivateKey: function removePrivateKey(identity) {
	        delete this.privateKeys[identity];
	    },
	
	    /**
	     * Return the private key of the identified ECC key pair.
	     * 
	     * @param {string} identity ECC key pair identity.
	     * @return {PrivateKey} the private key of the identified key pair or null if not found.
	     */
	    getPrivateKey: function getPrivateKey(identity) {
	        return this.privateKeys[identity];
	    },
	    
	    /**
	     * Clear the store of all public and private keys.
	     */
	    clear: function clear() {
	        this.publicKeys = {};
	        this.privateKeys = {};
	    }
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('EccStore'));

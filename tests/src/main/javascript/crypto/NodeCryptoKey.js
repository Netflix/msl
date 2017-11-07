/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
(function(require, module) {
    "use strict";
    
    var Class = require('msl-core/util/Class.js');
    var Arrays = require('msl-core/util/Arrays.js');
    
    /** Web Crypto key type. */
    var KeyType = {
        PUBLIC: 'public',
        PRIVATE: 'private',
        SECRET: 'secret',
    };
    
    /**
     * Performs a deep comparison of two objects.
     * 
     * @param {object} x the first object.
     * @param {object} y the second object.
     * @returns true if both objects are equal.
     */
    function objectsEqual(x, y) {
        if (typeof x !== 'object' || typeof y !== 'object') return false;
        if (Object.keys(x).length != Object.keys(y).length) return false;
        for (var p in x) {
            if (!y[p]) return false;
            var xv = x[p];
            var yv = y[p];
            if (xv instanceof Array) {
                if (!(yv instanceof Array)) return false;
                if (!Arrays.equals(xv, yv)) return false;
            } else if (typeof xv === 'function' || yv === 'function') {
                return false;
            } else if (typeof xv === 'object') {
                if (typeof yv !== 'object') return false;
                if (!objectsEqual(xv, yv)) return false;
            } else {
                if (xv != yv) return false;
            }
        }
        return true;
    }
    
    /**
     * A Web Crypto compatible key object.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var NodeCryptoKey = module.exports = Class.create({
        /**
         * Create a Node crypto key.
         * 
         * @param {*} rawkey the raw key object.
         * @param {KeyType} type key type.
         * @param {WebCryptoAlgorithm} algo Web Crypto algorithm.
         * @param {boolean} ext extractable.
         * @param {WebCryptoUsage} ku key usages.
         * @returns the key.
         */
        init: function init(rawkey, type, algo, ext, ku) {
            this.rawkey = rawkey;
            this['type'] = type;
            this['algorithm'] = algo;
            this['extractable'] = ext;
            this['usages'] = ku;
        },

        /**
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a Node crypto key with
         *         the same values.
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof NodeCryptoKey)) return false;
            
            // Compare raw keys.
            var rawkeysEqual = false;
            if (this.rawkey instanceof Array)
                rawkeysEqual = (that.rawkey instanceof Array) && Arrays.equal(this.rawkey, that.rawkey);
            else if (this.rawkey instanceof Uint8Array)
                rawkeysEqual = (that.rawkey instanceof Uint8Array) && Arrays.equal(this.rawkey, that.rawkey);
            else if (this.rawkey instanceof Object)
                rawkeysEqual = (that.rawkey instanceof Object) && objectsEqual(this.rawkey, that.rawkey);
            else
                rawkeysEqual = (this.rawkey == that.rawkey);

            // Compare primitives.
            var primitivesEqual = this['type'] == that['type'] &&
                this['extractable'] == that['extractable'] &&
                Arrays.equal(this['usages'], that['usages']);
            
            // Compare algorithms.
            var algosEqual = objectsEqual(this['algorithm'], that['algorithm']);
            
            // Return result.
            return rawkeysEqual && primitivesEqual && algosEqual;
        }
    });
    
    // Exports.
    NodeCryptoKey.KeyType = KeyType;
})(require, (typeof module !== 'undefined') ? module : mkmodule('NodeCryptoKey'));
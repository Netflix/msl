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

/**
 * <p>Convenience class for initializing MSL with configurable
 * implementations.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var Base64 = require('../util/Base64.js');
    var MslCompression = require('../util/MslCompression.js');
    var Random = require('../util/Random.js');
    var MslCrypto = require('../crypto/MslCrypto.js');
    var MslInternalException = require('../MslInternalException.js');
    var PromiseFactory = require('../util/PromiseFactory.js');
    
    /** Map key Base64. */
    var KEY_BASE64 = 'base64';
    /** Map key Compression. */
    var KEY_COMPRESSION = 'compression';
    /** Map key Random. */
    var KEY_RANDOM = 'random';
    /** Map key MslCrypto. */
    var KEY_CRYPTO = 'crypto';
    /** Map key Promise. */
    var KEY_PROMISE = 'promise';
    
    // Configuration function map.
    var f = {};
    
    /**
     * <p>Sets the Base64 implementation.</p>
     * 
     * @param {Base64Impl} b64 the Base64 implementation.
     */
    f[KEY_BASE64] = function setBase64(b64) {
        Base64.setImpl(b64);
    };

    /**
     * <p>Registers one or more compression algorithm implementations. Pass
     * {@code null} as a value to remove an implementation.</p>
     * 
     * @param {object<CompressionAlgorithm,CompressionImpl>} map the
     *        compression algorithm implementations to register or remove.
     */
    f[KEY_COMPRESSION] = function setCompression(map) {
        for (var algo in map) {
            var impl = map[algo];
            MslCompression.register(algo, impl);
        }
    };

    /**
     * <p>Sets the object used to access the {@code getRandomValues()}
     * function. This is typically an instance of the crypto interface.</p>
     * 
     * @param {object} r the random function object.
     */
    f[KEY_RANDOM] = function setRandom(r) {
        Random.setRandom(r);
    };

    /**
     * <p>Sets the Web Crypto version and subtle interface providing the
     * Web Crypto API.</p>
     * 
     * @param {WebCryptoVersion} version Web Crypto version to use.
     * @param {object} crypto the crypto subtle object to use.
     */
    f[KEY_CRYPTO] = function setCrypto(version, crypto) {
        MslCrypto.setWebCryptoVersion(version);
        MslCrypto.setCryptoSubtle(crypto);
    };

    /**
     * <p>Sets the Promise class definition.</p>
     * 
     * @param {function} p the Promise class definition.
     */
    f[KEY_PROMISE] = function setPromise(p) {
        PromiseFactory.setImpl(p);
    };
    
    /**
     * <p>Initialize multiple implementations using the provided map.</p>
     * 
     * <p>The map supports the following key/value pairs.
     * <ul>
     * <li><b>base64</b>: {@see #setBase64(object)}</li>
     * <li><b>compression</b>: {@see #setCompression(object<CompressionAlgorithm,CompressionImpl>)}</li>
     * <li><b>domparser</b>: {@see #setDOMParser(function)}</li>
     * <li><b>random</b>: {@see #setRandom(object)}</li>
     * <li><b>mslcrypto</b>: {@see #setMslCrypto(version, object)} as an array</li>
     * </ul></p>
     * 
     * @param {object<string,*>} config the configuration map.
     * @throws MslInternalException if any of the provided keys are not
     *         recognized. Initialization for all recognized keys will have
     *         been performed, so the caller may wish to ignore this exception.
     */
    var initialize = function initialize(config) {
        var unrecognizedKeys = [];
        
        // Perform the requested configurations.
        for (var key in config) {
            // Collect unrecognized keys to throw an error.
            if (!f[key]) {
                unrecognizedKeys.push(key);
                continue;
            }
            
            // Execute the configuration function.
            var args = config[key];
            if (!(args instanceof Array))
                args = [ args ];
            f[key].apply(this, args);
        }
        
        // Throw an exception listing the unrecognized keys.
        if (unrecognizedKeys.length > 0)
            throw new MslInternalException("Could not initialize MSL for the following unrecognized options: " + unrecognizedKeys.join(", ") + ".");
    };
    
    // Export keys.
    module.exports.KEY_BASE64 = KEY_BASE64;
    module.exports.KEY_COMPRESSION = KEY_COMPRESSION;
    module.exports.KEY_RANDOM = KEY_RANDOM;
    module.exports.KEY_CRYPTO = KEY_CRYPTO;
    module.exports.KEY_PROMISE = KEY_PROMISE;
    
    // Export functions.
    module.exports.setBase64 = f[KEY_BASE64];
    module.exports.setCompression = f[KEY_COMPRESSION];
    module.exports.setRandom = f[KEY_RANDOM];
    module.exports.setCrypto = f[KEY_CRYPTO];
    module.exports.setPromise = f[KEY_PROMISE];
    module.exports.initialize = initialize;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslInit'));
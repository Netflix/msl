/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
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
    
    var Class = require('../util/Class.js');
    var Base64 = require('../util/Base64.js');
    var MslCompression = require('../util/MslCompression.js');
    var TextEncoding = require('../util/TextEncoding.js');
    var Random = require('../util/Random.js');
    var MslCrypto = require('../crypto/MslCrypto.js');
    var MslInternalException = require('../MslInternalException.js');
    var PromiseFactory = require('../util/PromiseFactory.js');
    
    /**
     * <p>Setup provider.</p>
     * 
     * <p>Each option is marked as either required or optional. Any option that
     * returns {@code null} or {@code undefined} will be ignored.</p>
     */
    var MslSetup = module.exports = Class.create({
       /**
        * <p>Provides the Base64 implementation.</p>
        * 
        * <p><b>required</b></p>
        * 
        * @return {?Base64Impl} a Base64 implementation.
        */
        getBase64Impl: function() {},
        
        /**
         * <p>Provides the set of compression algorithm implementations. An
         * implementation value of {@code null} will remove any implementation
         * currently registered for that algorithm.</p>
         * 
         * <p><b>optional</b>: default is no registered implementations</p>
         * 
         * @return {?object<CompressionAlgorithm,CompressionImpl>} a map of
         *         compression algorithm implementations to register or remove.
         */
        getCompressionImpls: function() {},
        
        /**
         * <p>Provides the maximum deflate ratio.</p>
         * 
         * <p><b>optional</b>: default maximum deflate ratio will be used</p>
         *
         * @return {?number} the maximum deflate ratio.
         */
        getMaxDeflateRatio: function() {},
        
        /**
         * <p>Provides the TextEncoding implementation.</p>
         * 
         * <p><b>required</b></p>
         * 
         * @return {?TextEncodingImpl} a TextEncoding implementation.
         */
        getTextEncodingImpl: function() {},
        
        /**
         * <p>Provides the object used to access the {@code getRandomValues()}
         * function. This is typically an instance of the crypto interface.</p>
         * 
         * <p><b>optional</b>: default is the window.crypto interface</p>
         * 
         * @return {?object} the random function object.
         */
        getRandomInterface: function() {},
        
        /**
         * <p>Provides the Web Crypto version.</p>
         * 
         * <p><b>optional</b>: default will attempt to detect the version</p>
         * 
         * @return {?WebCryptoVersion} Web Crypto version to use.
         */
        getWebCryptoVersion: function() {},
        
        /**
         * <p>Provides the Web Crypto API subtle interface.</p>
         * 
         * <p><b>optional</b>: default will attempt to detect the interface</p>
         * 
         * @return {?object} the crypto subtle to use.
         */
        getWebCryptoApi: function() {},
        
        /**
         * <p>Provides the Promise class definition.</p>
         * 
         * <p><b>optional</b>: default is the built-in Promise global</p>
         * 
         * @return {?function} the Promise class definition.
         */
        getPromiseClass: function() {},
    });
    
    /**
     * <p>Execute the provided MSL setup.</p>
     * 
     * @param {MslSetup} setup the MSL setup.
     */
    var execute = function execute(setup) {
        // Base64.
        var base64Impl = setup.getBase64Impl();
        if (base64Impl)
            Base64.setImpl(base64Impl);
        
        // Compression.
        var compressionImpls = setup.getCompressionImpls();
        if (compressionImpls) {
            for (var algo in compressionImpls) {
                var impl = compressionImpls[algo];
                MslCompression.register(algo, impl);
            }
        }
        var maxDeflateRatio = setup.getMaxDeflateRatio();
        if (maxDeflateRatio)
            MslCompression.setMaxDeflateRatio(maxDeflateRatio);
        
        // Text encoding.
        var textEncodingImpl = setup.getTextEncodingImpl();
        if (textEncodingImpl)
            TextEncoding.setImpl(textEncodingImpl);
        
        // Random.
        var randomInterface = setup.getRandomInterface();
        if (randomInterface)
            Random.setRandom(randomInterface);
        
        // Crypto version.
        var cryptoVersion = setup.getWebCryptoVersion();
        if (cryptoVersion !== null && cryptoVersion !== undefined)
            MslCrypto.setWebCryptoVersion(cryptoVersion);
        
        // Crypto API.
        var cryptoApi = setup.getWebCryptoApi();
        if (cryptoApi)
            MslCrypto.setCryptoSubtle(cryptoApi);
        
        // Promise.
        var promiseClass = setup.getPromiseClass();
        if (promiseClass)
            PromiseFactory.setImpl(promiseClass);
    };
    
    // Exports.
    module.exports.execute = execute;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslSetup'));
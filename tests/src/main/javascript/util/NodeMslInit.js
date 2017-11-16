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
 * <p>Initializes MSL for use in a Node.js environment.</p>
 */
var Base64Secure = require('msl-core/util/Base64Secure.js');
var NodeRandom = require('../crypto/NodeRandom.js');
var MslCrypto = require('msl-core/crypto/MslCrypto.js');
var NodeCrypto = require('../crypto/NodeCrypto.js');
var LzwCompression = require('msl-core/util/LzwCompression.js');
var NodeGzipCompression = require('../util/NodeGzipCompression.js');
var MslConstants = require('msl-core/MslConstants.js');

var MslInit = require('msl-core/util/MslInit.js');

var NodeConfiguration = MslInit.Configuration.extend({
    init: function init() {
        var base64Impl = new Base64Secure();
        var compressionImpls = {};
        compressionImpls[MslConstants.CompressionAlgorithm.LZW] = new LzwCompression();
        compressionImpls[MslConstants.CompressionAlgorithm.GZIP] = new NodeGzipCompression();
        
        // The properties.
        var props = {
            _base64Impl: { value: base64Impl, writable: false, enumerable: false, configurable: false },
            _compressionImpls: { value: compressionImpls, writable: false, enumerable: false, configurable: false },
            _randomInterface: { value: NodeRandom, writable: false, enumerable: false, configurable: false },
            _webCryptoVerson: { value: MslCrypto.WebCryptoVersion.LATEST, writable: false, enumerable: false, configurable: false },
            _webCryptoApi: { value: NodeCrypto, writable: false, enumerable: false, configurable: false },
        };
        Object.defineProperties(this, props);
    },
    
    /** @inheritDoc */
    getBase64Impl: function getBase64Impl() {
        return this._base64Impl;
    },
    
    /** @inheritDoc */
    getCompressionImpls: function getCompressionImpls() {
        return this._compressionImpls;
    },
    
    /** @inheritDoc */
    getRandomInterface: function getRandomInterface() {
        return this._randomInterface;
    },
    
    /** @inheritDoc */
    getWebCryptoVersion: function getWebCryptoVersion() {
        return this._webCryptoVersion;
    },
    
    /** @inheritDoc */
    getWebCryptoApi: function getWebCryptoApi() {
        return this._webCryptoApi;
    },
});

var config = new NodeConfiguration();
MslInit.initialize(config);
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

var config = {};
config[MslInit.KEY_BASE64] = new Base64Secure();
config[MslInit.KEY_RANDOM] = NodeRandom;
config[MslInit.KEY_CRYPTO] = [MslCrypto.WebCryptoVersion.LATEST, NodeCrypto];
config[MslInit.KEY_COMPRESSION] = {};
config[MslInit.KEY_COMPRESSION][MslConstants.CompressionAlgorithm.LZW] = new LzwCompression();
config[MslInit.KEY_COMPRESSION][MslConstants.CompressionAlgorithm.GZIP] = new NodeGzipCompression();

MslInit.initialize(config);
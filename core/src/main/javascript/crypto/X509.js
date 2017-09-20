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
 * <p>A module wrapper around the X509 type from 'jsrsasign'. This is necessary
 * because jsrsasign does not export the type in a way compatible with module
 * expectations.</p>
 */
(function(require, module) {
    "use strict";
    
    var X509 = module.exports = require('jsrsasign').X509;
})(require, (typeof module !== 'undefined') ? module : mkmodule('X509'));
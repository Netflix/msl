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
(function(require, module) {
    "use strict";

    /**
     * <p>Key Format constants.</p>
     */
    var KeyFormat = module.exports = {
        RAW : "raw",
        JWK : "jwk",
        SPKI: "spki",
        PKCS8: "pkcs8",
    };
})(require, (typeof module !== 'undefined') ? module : mkmodule('KeyFormat'));

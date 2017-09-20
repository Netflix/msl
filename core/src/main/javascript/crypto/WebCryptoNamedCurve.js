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

    /**
     * MSL named curves mapped onto Web Crypto named curves.
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var WebCryptoNamedCurve = module.exports = {
        /** secp256r1 */
        P_256: 'P-256',
        /** secp384r1 */
        P_384: 'P-384',
        /** secp521r1 */
        P_521: 'P-521',
    };
    Object.freeze(WebCryptoNamedCurve);
})(require, (typeof module !== 'undefined') ? module : mkmodule('WebCryptoNamedCurve'));
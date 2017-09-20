/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
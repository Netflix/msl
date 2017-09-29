/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 * <p>X.509 asymmetric keys entity authentication data.</p>
 *
 * <p>The X.509 certificate should be used to enumerate any entity
 * properties. The certificate subject canonical name is considered the device
 * identity. X.509 authentication data is considered equal based on the device
 * identity.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "x509certificate" ],
 *   "x509certificate" : "string"
 * }} where:
 * <ul>
 * <li>{@code x509certificate} is the Base64-encoded X.509 certificate</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var EntityAuthenticationData = require('../entityauth/EntityAuthenticationData.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require("../util/AsyncExecutor.js");
    var MslEncoderException = require('../io/MslEncoderException.js');
    var MslEncodingException = require('../MslEncodingException.js');
    var MslCryptoException = require('../MslCryptoException.js');
    var MslError = require('../MslError.js');
    var X509 = require('../crypto/X509.js');
    
    var hex2b64 = require('jsrsasign').hex2b64;
    
    /**
     * Key entity X.509 certificate.
     * @const
     * @type {string}
     */
    var KEY_X509_CERT = "x509certificate";
    
    /** X.509 PEM header. */
    var PEM_HEADER = "-----BEGIN CERTIFICATE-----\n";
    /** X.509 PEM footer. */
    var PEM_FOOTER = "\n-----END CERTIFICATE-----";

    var X509AuthenticationData = module.exports = EntityAuthenticationData.extend({
        /**
         * <p>Construct a new X.509 asymmetric keys authentication data instance from
         * the provided X.509 certificate.</p>
         *
         * @param {X509} x509cert entity X.509 certificate.
         * @throws MslCryptoException if the X.509 certificate data cannot be
         *         parsed.
         */
        init: function init(x509cert) {
            init.base.call(this, EntityAuthenticationScheme.X509);

            var identity = x509cert.getSubjectString();

            // The properties.
            var props = {
                identity: { value: identity, writable: false, configurable: false },
                x509cert: { value: x509cert, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getIdentity: function getIdentity() {
            return this.identity;
        },

        /** @inheritDoc */
        getAuthData: function getAuthData(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                // Base64 encode the X.509 certificate.
                var certHex = this.x509cert.hex;
                var certB64 = hex2b64(certHex);

                // Return the authentication data.
                var mo = encoder.createObject();
                mo.put(KEY_X509_CERT, certB64);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof X509AuthenticationData)) return false;
            return (equals.base.call(this, that) && this.identity == that.identity);
        },
    });

    /**
     * Construct a new RSA asymmetric keys authentication data instance from the
     * provided MSL object.
     *
     * @param {MslObject} x509AuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    var X509AuthenticationData$parse = function X509AuthenticationData$parse(x509AuthMo) {
        var certB64;
        try {
            certB64 = x509AuthMo.getString(KEY_X509_CERT);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "X.509 authdata" + x509AuthMo);
            throw e;
        }

        // Convert to X.509 certificate.
        var x509 = new X509();
        try {
            // Add certificate header and footer if necessary.
            certB64 = certB64.trim();
            if (!certB64.startsWith(PEM_HEADER))
                certB64 = PEM_HEADER + certB64;
            if (!certB64.endsWith(PEM_FOOTER))
                certB64 = certB64 + PEM_FOOTER;
            x509.readCertPEM(certB64);
        } catch (e) {
            throw new MslCryptoException(MslError.X509CERT_PARSE_ERROR, certB64, e);
        }
        return new X509AuthenticationData(x509);
    };
    
    // Exports.
    module.exports.parse = X509AuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('X509AuthenticationData'));
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
 * <p>The X.509 certificate store provides X.509 certificate validation against
 * the stored trusted certificates and certificate chains.</p>
 */
(function(require, module) {
    "use strict";
    
    const Class = require('../util/Class.js');
    const X509 = require('../crypto/X509.js');
    
    var X509Store = module.exports = Class.create({
        init: function init() {
            /**
             * Map of subject names onto trusted X.509 certificates.
             * @type {Object.<string,X509>}
             */
            var x509certs = {};
    
            // The properties.
            var props = {
                x509certs: { value: x509certs, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },
    
        /**
         * Adds an X.509 CA certificate to the list of trusted certificates.
         *
         * @param {X509|string} x509data X.509 certificate or PEM string.
         */
        addCert: function addCert(x509data) {
            var x509;
            if (x509data instanceof X509) {
                x509 = x509data;
            } else if (typeof x509data === 'string') {
                x509 = new X509();
                x509.readCertPEM(x509data);
            } else {
                throw new TypeError('X.509 data must be an X509 instance or a PEM string.');
            }
            this.x509certs[x509.getSubjectString()] = x509;
        },
    
        /**
         * Adds an ordered chain of X.509 CA certificates to the list of
         * trusted certificates. The first certificate in the chain must be
         * self-signed.
         *
         * @param {Array.<X509|string>} x509data X.509 certificates or PEM
         *        strings.
         */
        addChain: function addChain(x509data) {
            if (!(x509data instanceof Array))
                throw new TypeError('X.509 data must be an array of X509 instances or PEM strings.');
            x509data.forEach(function(certData) {
                this.addCert(certData);
            }, this);
        },
    
        /**
         * Verify an X.509 certificate against the trusted CA certificates.
         *
         * @param {X509} cert X.509 certificate to verify.
         * @return {boolean} true if the certificate is trusted.
         */
        verify: function verify(cert) {
            if (!(cert instanceof X509))
                throw new TypeError('Certificate must be an X509 instance.');
            var issuer = cert.getIssuerString();
            if (!issuer)
                return false;
            var issuerCert = this.x509certs[issuer];
            if (!issuerCert)
                return false;
            var issuerPublicKey = issuerCert.subjectPublicKeyRSA;
            // FIXME verify the certificate somehow.
    //		issuerPublicKey.verify(uint8array msg, uint8array signature);
            return false;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('X509Store'));
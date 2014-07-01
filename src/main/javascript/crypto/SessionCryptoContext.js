/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
 * This is a convenience class for constructing a symmetric crypto context from
 * a MSL session master token.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var SessionCryptoContext = SymmetricCryptoContext.extend({
    /**
     * Construct a new session crypto context from the provided master token.
     *
     * If an identity, encryption key, and HMAC key are provided then they are
     * assumed to be the same as what is inside the master token, which may be
     * untrusted.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MasterToken} masterToken the master token. May be untrusted if
     *        the identity, encryption key, and HMAC key are provided.
     * @param {string=} identity entity identity.
     * @param {CipherKey=} encryptionKey encryption key.
     * @param {CipherKey=} hmacKey HMAC key.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslCryptoException if the encryption key length is unsupported.
     */
    init: function init(ctx, masterToken, identity, encryptionKey, hmacKey) {
        if (identity || encryptionKey || hmacKey) {
            init.base.call(this, ctx, identity + '_' + masterToken.sequenceNumber, encryptionKey, hmacKey, null);
        } else {
            if (!masterToken.isDecrypted())
                throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
            init.base.call(this, ctx, masterToken.identity + '_' + masterToken.sequenceNumber, masterToken.encryptionKey, masterToken.hmacKey, null);
        }
    },
});

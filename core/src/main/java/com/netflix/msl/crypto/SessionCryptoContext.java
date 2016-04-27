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
package com.netflix.msl.crypto;

import javax.crypto.SecretKey;

import com.netflix.msl.MslError;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;

/**
 * This is a convenience class for constructing a symmetric crypto context from
 * a MSL session master token.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SessionCryptoContext extends SymmetricCryptoContext {
    /**
     * <p>Construct a new session crypto context from the provided master
     * token.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken the master token.
     * @throws MslMasterTokenException if the master token is not trusted.
     */
    public SessionCryptoContext(final MslContext ctx, final MasterToken masterToken) throws MslMasterTokenException {
        this(ctx, masterToken, masterToken.getIdentity(), masterToken.getEncryptionKey(), masterToken.getSignatureKey());
        if (!masterToken.isDecrypted())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
    }
    
    /**
     * <p>Construct a new session crypto context from the provided master token.
     * The entity identity and keys are assumed to be the same as what is
     * inside the master token, which may be untrusted.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken master token. May be untrusted.
     * @param identity entity identity. May be {@code null}.
     * @param encryptionKey encryption key.
     * @param hmacKey HMAC key.
     */
    public SessionCryptoContext(final MslContext ctx, final MasterToken masterToken, final String identity, final SecretKey encryptionKey, final SecretKey hmacKey) {
        super(ctx, (identity != null) ? identity + "_" + masterToken.getSequenceNumber() : Long.toString(masterToken.getSequenceNumber()), encryptionKey, hmacKey, null);
    }
}

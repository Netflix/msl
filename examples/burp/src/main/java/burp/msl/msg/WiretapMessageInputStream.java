/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package burp.msl.msg;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * User: skommidi
 * Date: 9/24/14
 */
public class WiretapMessageInputStream extends MessageInputStream {
    /** Key payload. */
    private static final String KEY_PAYLOAD = "payload";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";

    /**
     * <p>Construct a new message input stream. The header is parsed.</p>
     * 
     * <p>If key request data is provided and a matching key response data is
     * found in the message header the key exchange will be performed to
     * process the message payloads.</p>
     * 
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explcitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     * 
     * @param ctx MSL context.
     * @param source MSL input stream.
     * @param keyRequestData key request data to use when processing key
     *        response data.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @throws IOException if there is a problem reading from the input stream.
     * @throws MslEncodingException if there is an error parsing the message.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the message payload crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be or if it has been revoked.
     * @throws MslUserIdTokenException if the user ID token has been revoked.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token.
     */
    public WiretapMessageInputStream(final MslContext ctx, final InputStream source, final Set<KeyRequestData> keyRequestData, final Map<String, ICryptoContext> cryptoContexts) throws IOException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslUserIdTokenException, MslMessageException, MslException {
        super(ctx, source, keyRequestData, cryptoContexts);
        this.ctx = ctx;
    }
    
    /**
     * <p>Retrieve the next payload chunk as a decrypted MSL object.</p>
     * 
     * @return the next payload chunk or {@code null} if none remaining.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the payload verification failed.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     */
    public MslObject nextPayload() throws MslEncodingException, MslMessageException, MslCryptoException {
        // Grab the next payload chunk MSL object.
        final MslObject payloadChunk = nextMslObject();
        if (payloadChunk == null)
            return null;
        
        // Verify the payload chunk and pull the payload ciphertext.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final ICryptoContext cryptoContext = getPayloadCryptoContext();
        byte[] payload;
        try {
            payload = payloadChunk.getBytes(KEY_PAYLOAD);
            final byte[] signature = payloadChunk.getBytes(KEY_SIGNATURE);
            if (!cryptoContext.verify(payload, signature, encoder))
                throw new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payload chunk " + payloadChunk.toString(), e);
        }

        // Decrypt the payload.
        final byte[] plaintext = cryptoContext.decrypt(payload, encoder);
        
        // Parse the decrypted payload.
        try {
            final MslObject payloadMo = encoder.parseObject(plaintext);
            return payloadMo;
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payload chunk payload " + Base64.encode(plaintext), e);
        }
    }

    /** MSL context. */
    private final MslContext ctx;
}

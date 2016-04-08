/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.Set;

import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslConstants;
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
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * User: skommidi
 * Date: 9/24/14
 */
public class WiretapMessageInputStream extends MessageInputStream {
    /** JSON key payload. */
    private static final String KEY_PAYLOAD = "payload";
    /** JSON key signature. */
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
     * @param charset input stream character set encoding.
     * @param keyRequestData key request data to use when processing key
     *        response data.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
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
    public WiretapMessageInputStream(final MslContext ctx, final InputStream source, final Charset charset, final Set<KeyRequestData> keyRequestData, final Map<String, ICryptoContext> cryptoContexts) throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslUserIdTokenException, MslMessageException, MslException {
        super(ctx, source, charset, keyRequestData, cryptoContexts);
    }
    
    /**
     * <p>Retrieve the next payload chunk as a decrypted JSON object.</p>
     * 
     * @return the next payload chunk or {@code null} if none remaining.
     * @throws MslEncodingException if there is a problem parsing the JSON.
     * @throws MslMessageException if the payload verification failed.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     */
    public JSONObject nextPayload() throws MslEncodingException, MslMessageException, MslCryptoException {
        // Grab the next payload chunk JSON object.
        final JSONObject payloadChunk = nextJsonObject();
        if (payloadChunk == null)
            return null;
        
        // Verify the payload chunk and pull the payload ciphertext.
        final ICryptoContext cryptoContext = getPayloadCryptoContext();
        byte[] payload;
        try {
            try {
                payload = Base64.decode(payloadChunk.getString(KEY_PAYLOAD));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.PAYLOAD_INVALID, "payload chunk " + payloadChunk.toString(), e);
            }
            final byte[] signature;
            try {
                signature = Base64.decode(payloadChunk.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.PAYLOAD_SIGNATURE_INVALID, "payload chunk " + payloadChunk.toString(), e);
            }
            if (!cryptoContext.verify(payload, signature))
                throw new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk " + payloadChunk.toString(), e);
        }

        // Decrypt the payload.
        final byte[] plaintext = cryptoContext.decrypt(payload);
        
        // Parse the decrypted payload as JSON.
        final String payloadJson = new String(plaintext, MslConstants.DEFAULT_CHARSET);
        try {
            final JSONObject payloadJO = new JSONObject(payloadJson);
            return payloadJO;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk payload " + payloadJson, e);
        }
    }
}

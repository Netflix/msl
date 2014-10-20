package burp.msl.msg;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.Header;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.xml.bind.DatatypeConverter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * User: skommidi
 * Date: 9/24/14
 */
public class WiretapMessageInputStream {
    /** JSON key payload. */
    private static final String KEY_PAYLOAD = "payload";
    /** JSON key signature. */
    private static final String KEY_SIGNATURE = "signature";

    /**
     * <p>Construct a new message input stream. The header is parsed.</p>
     * <p/>
     * <p>If key request data is provided and a matching key response data is
     * found in the message header the key exchange will be performed to
     * process the message payloads.</p>
     * <p/>
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explcitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param ctx            MSL context.
     * @param source         MSL input stream.
     * @param charset        input stream character set encoding.
     * @param keyRequestData key request data to use when processing key
     *                       response data.
     * @param cryptoContexts the map of service token names onto crypto
     *                       contexts used to decrypt and verify service tokens.
     * @throws com.netflix.msl.MslEncodingException
     *                                      if there is an error parsing the message.
     * @throws com.netflix.msl.MslCryptoException
     *                                      if there is an error decrypting or verifying
     *                                      the header or creating the message payload crypto context.
     * @throws com.netflix.msl.MslEntityAuthException
     *                                      if unable to create the entity
     *                                      authentication data.
     * @throws com.netflix.msl.MslUserAuthException
     *                                      if unable to create the user authentication
     *                                      data.
     * @throws com.netflix.msl.MslMessageException
     *                                      if the message master token is expired and
     *                                      the message is not renewable.
     * @throws com.netflix.msl.MslMasterTokenException
     *                                      if the master token is not trusted and
     *                                      needs to be or if it has been revoked.
     * @throws com.netflix.msl.MslUserIdTokenException
     *                                      if the user ID token has been revoked.
     * @throws com.netflix.msl.MslKeyExchangeException
     *                                      if there is an error with the key
     *                                      request data or key response data or the key exchange scheme is
     *                                      not supported.
     * @throws com.netflix.msl.MslMessageException
     *                                      if the message master token is expired and
     *                                      the message is not renewable.
     * @throws com.netflix.msl.MslException if the message does not contain an entity
     *                                      authentication data or a master token, or a token is improperly
     *                                      bound to another token.
     */
    public WiretapMessageInputStream(MslContext ctx, InputStream source, Charset charset, Set<KeyRequestData> keyRequestData, Map<String, ICryptoContext> cryptoContexts) throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslUserIdTokenException, MslMessageException, MslException {
        // Parse the header.
        this.source = source;
        this.tokener = new JSONTokener(new InputStreamReader(source, charset));
        final JSONObject jo;
        try {
            if (!this.tokener.more())
                throw new MslEncodingException(MslError.MESSAGE_DATA_MISSING);
            final Object o = this.tokener.nextValue();
            if (!(o instanceof JSONObject))
                throw new MslEncodingException(MslError.MESSAGE_FORMAT_ERROR);
            jo = (JSONObject)o;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "header", e);
        }
        this.header = Header.parseHeader(ctx, jo, cryptoContexts);

        try {
            // For error messages there are no key exchange or payload crypto
            // contexts.
            if (this.header instanceof ErrorHeader) {
                this.keyxCryptoContext = null;
                this.cryptoContext = null;
                return;
            }

            // Grab the key exchange crypto context, if any.
            final MessageHeader messageHeader = (MessageHeader)this.header;
            this.keyxCryptoContext = getKeyxCryptoContext(ctx, messageHeader, keyRequestData);

            // In peer-to-peer mode or in trusted network mode with no key
            // exchange the payload crypto context equals the header crypto
            // context.
            if (ctx.isPeerToPeer() || this.keyxCryptoContext == null)
                this.cryptoContext = messageHeader.getCryptoContext();

                // Otherwise the payload crypto context equals the key exchange
                // crypto context.
            else
                this.cryptoContext = this.keyxCryptoContext;

            // If this is a handshake message but it is not renewable or does
            // not contain key request data then reject the message.
            if (messageHeader.isHandshake() &&
                    (!messageHeader.isRenewable() || messageHeader.getKeyRequestData().isEmpty()))
            {
                throw new MslMessageException(MslError.HANDSHAKE_DATA_MISSING, messageHeader.toJSONString());
            }

            // If I am in peer-to-peer mode or the master token is verified
            // (i.e. issued by the local entity which is therefore a trusted
            // network server) then perform the master token checks.
            final MasterToken masterToken = messageHeader.getMasterToken();
            if (masterToken != null && (ctx.isPeerToPeer() || masterToken.isVerified())) {
                // If the master token has been revoked then reject the
                // message.
                final TokenFactory factory = ctx.getTokenFactory();
                final MslError revoked = factory.isMasterTokenRevoked(ctx, masterToken);
                if (revoked != null)
                    throw new MslMasterTokenException(revoked, masterToken);

                // If the user ID token has been revoked then reject the
                // message. We know the master token is not null and that it is
                // verified so we assume the user ID token is as well.
                final UserIdToken userIdToken = messageHeader.getUserIdToken();
                if (userIdToken != null) {
                    final MslError uitRevoked = factory.isUserIdTokenRevoked(ctx, masterToken, userIdToken);
                    if (uitRevoked != null)
                        throw new MslUserIdTokenException(uitRevoked, userIdToken);
                }

                // If the master token is expired...
                if (masterToken.isExpired(null)) {
                    // If the message is not renewable or does not contain key
                    // request data then reject the message.
                    if (!messageHeader.isRenewable() || messageHeader.getKeyRequestData().isEmpty())
                        throw new MslMessageException(MslError.MESSAGE_EXPIRED, messageHeader.toJSONString());

                    // If the master token will not be renewed by the token
                    // factory then reject the message.
                    //
                    // This throws an exception if the master token is not
                    // renewable.
                    final MslError notRenewable = factory.isMasterTokenRenewable(ctx, masterToken);
                    if (notRenewable != null)
                        throw new MslMessageException(notRenewable, "Master token is expired and not renewable.");
                }
            }

            // TODO: This is the old non-replayable logic for backwards
            // compatibility. It should be removed once all MSL stacks have
            // migrated to the newer non-replayable ID logic.
            //
            // If the message is non-replayable (it is not from a trusted
            // network server).
            if (messageHeader.isNonReplayable()) {
                // ...and not also renewable with key request data and a
                // master token then reject the message.
                if (!messageHeader.isRenewable() ||
                        messageHeader.getKeyRequestData().isEmpty() ||
                        masterToken == null)
                {
                    throw new MslMessageException(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE, messageHeader.toJSONString());
                }

                // If the message does not have the newest master token
                // then notify the sender.
                final TokenFactory factory = ctx.getTokenFactory();
                if (!factory.isNewestMasterToken(ctx, masterToken))
                    throw new MslMessageException(MslError.MESSAGE_REPLAYED, messageHeader.toJSONString());
            }

            // If the message is non-replayable (it is not from a trusted
            // network server).
            final Long nonReplayableId = messageHeader.getNonReplayableId();
            if (nonReplayableId != null) {
                // ...and does not include a master token then reject the
                // message.
                if (masterToken == null)
                    throw new MslMessageException(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE, messageHeader.toJSONString());

                // If the non-replayable ID is not accepted then notify the
                // sender.
                final TokenFactory factory = ctx.getTokenFactory();
                MslError replayed = factory.acceptNonReplayableId(ctx, masterToken, nonReplayableId);
                if (replayed != null)
                    throw new MslMessageException(MslError.MESSAGE_REPLAYED, messageHeader.toJSONString());
            }
        } catch (final MslException e) {
            if (this.header instanceof MessageHeader) {
                final MessageHeader messageHeader = (MessageHeader)this.header;
                e.setEntity(messageHeader.getMasterToken());
                e.setEntity(messageHeader.getEntityAuthenticationData());
                e.setUser(messageHeader.getUserIdToken());
                e.setUser(messageHeader.getUserAuthenticationData());
                e.setMessageId(messageHeader.getMessageId());
            } else {
                final ErrorHeader errorHeader = (ErrorHeader)this.header;
                e.setEntity(errorHeader.getEntityAuthenticationData());
                e.setMessageId(errorHeader.getMessageId());
            }
            throw e;
        }
    }

    public JSONObject nextData() throws MslCryptoException, MslEncodingException, MslMessageException, MslInternalException, MslException {
        // Make sure this message is allowed to have payload chunks.
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            throw new MslInternalException("Read attempted with error message.");

        // If we previously reached the end of the message, don't try to read
        // more.
        if (eom)
            return null;

        // Otherwise read the next payload.
        final JSONObject jo;
        try {
            if (!tokener.more()) {
                eom = true;
                return null;
            }
            final Object o = tokener.nextValue();
            if (!(o instanceof JSONObject))
                throw new MslEncodingException(MslError.MESSAGE_FORMAT_ERROR);
            jo = (JSONObject)o;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payloadchunk", e);
        }
        return getPayload(jo, cryptoContext);//new PayloadChunk(jo, cryptoContext);
    }

    private JSONObject getPayload(JSONObject payloadChunkJO, ICryptoContext cryptoContext) throws MslMessageException, MslCryptoException, MslEncodingException {

        byte[] payload;
        byte[] signature;
        // Verify the JSON representation.
        try {
            try {
                payload = DatatypeConverter.parseBase64Binary(payloadChunkJO.getString(KEY_PAYLOAD));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.PAYLOAD_INVALID, "payload chunk " + payloadChunkJO.toString(), e);
            }
            try {
                signature = DatatypeConverter.parseBase64Binary(payloadChunkJO.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.PAYLOAD_SIGNATURE_INVALID, "payload chunk " + payloadChunkJO.toString(), e);
            }
            if (!cryptoContext.verify(payload, signature))
                throw new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk " + payloadChunkJO.toString(), e);
        }

        // Pull the payload data.
        final byte[] plaintext = cryptoContext.decrypt(payload);
        final String payloadJson = new String(plaintext, MslConstants.DEFAULT_CHARSET);

        try {
            final JSONObject payloadJO = new JSONObject(payloadJson);
            return payloadJO;
        } catch (JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk payload " + payloadJson, e);
        }
    }

    private ICryptoContext getKeyxCryptoContext(MslContext ctx, MessageHeader Header, Set<KeyRequestData> keyRequestData) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
        // Pull the header data.
        final MessageHeader messageHeader = (MessageHeader)header;
        final MasterToken masterToken = messageHeader.getMasterToken();
        final KeyResponseData keyResponse = messageHeader.getKeyResponseData();

        // If there is no key response data then return null.
        if (keyResponse == null)
            return null;

        // Perform the key exchange.
        final KeyExchangeScheme responseScheme = keyResponse.getKeyExchangeScheme();
        final KeyExchangeFactory factory = ctx.getKeyExchangeFactory(responseScheme);
        if (factory == null)
            throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, responseScheme.name());

        // Attempt the key exchange but if it fails then try with the next
        // key request data before giving up.
        MslException keyxException = null;
        final Iterator<KeyRequestData> keyRequests = keyRequestData.iterator();
        while (keyRequests.hasNext()) {
            final KeyRequestData keyRequest = keyRequests.next();
            final KeyExchangeScheme requestScheme = keyRequest.getKeyExchangeScheme();

            // Skip incompatible key request data.
            if (!responseScheme.equals(requestScheme))
                continue;

            try {
                return factory.getCryptoContext(ctx, keyRequest, keyResponse, masterToken);
            } catch (final MslKeyExchangeException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            } catch (final MslEncodingException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            } catch (final MslMasterTokenException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            } catch (final MslEntityAuthException e) {
                if (!keyRequests.hasNext()) throw e;
                keyxException = e;
            }
        }

        // We did not perform a successful key exchange. If we caught an
        // exception then throw that exception now.
        if (keyxException != null) {
            if (keyxException instanceof MslKeyExchangeException)
                throw (MslKeyExchangeException)keyxException;
            if (keyxException instanceof MslEncodingException)
                throw (MslEncodingException)keyxException;
            if (keyxException instanceof MslMasterTokenException)
                throw (MslMasterTokenException)keyxException;
            if (keyxException instanceof MslEntityAuthException)
                throw (MslEntityAuthException)keyxException;
            throw new MslInternalException("Unexpected exception caught during key exchange.", keyxException);
        }

        // If we did not perform a successful key exchange then the
        // payloads will not decrypt properly. Throw an exception.
        throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, Arrays.toString(keyRequestData.toArray()));


    }

    public ICryptoContext getKeyxCryptoContext() {
        return keyxCryptoContext;
    }

    public ICryptoContext getCryptoContext() {
        return cryptoContext;
    }

    public ErrorHeader getErrorHeader() {
        if (header instanceof ErrorHeader)
            return (ErrorHeader)header;
        return null;
    }

    public MessageHeader getMessageHeader() {
        if (header instanceof MessageHeader)
            return (MessageHeader)header;
        return null;
    }

    private final InputStream source;
    private final JSONTokener tokener;
    private final Header header;
    private final ICryptoContext keyxCryptoContext;
    private final ICryptoContext cryptoContext;
    private boolean eom = false;
}

/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
 */
package server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslUtils;

import io.netty.channel.ChannelHandlerContext;
import io.netty.util.Attribute;
import server.msg.PushMessageContext;

/**
 * <p>Push a MSL message to a WebSocket client.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PushMslMessage {
    /**
     * <p>Create a new message input stream that is identical to the provided
     * message input stream but with a different randomly chosen message
     * ID.</p>
     *
     * <p>Several of the listed exceptions should never be thrown.</p>
     *
     * @param ctx MSL context.
     * @param mis original message input stream.
     * @return the new message input stream.
     * @throws MslEncodingException if there is an error encoding or parsing
     *         the message.
     * @throws MslCryptoException if there is an error encrypting/decrypting or
     *         signing/verifying the header, or creating the message payload
     *         crypto context.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header, or if the
     *         master token has been revoked.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data or if it cannot be created.
     * @throws MslEncoderException if there is an error encoding the message
     *         header.
     * @throws IOException if there is a problem reading from the input stream.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
     * @throws MslUserIdTokenException if the user ID token has been revoked.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token.
     * @throws MslInternalException if the provided message input stream is for
     *         an error message.
     */
    private static MessageInputStream createMessageInputStream(final MslContext ctx, final MessageInputStream mis) throws MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, IOException, MslException {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();

        // This is a hack to generate a new random message input stream
        // until a formal send() function is created.
        final long messageId = MslUtils.getRandomLong(ctx);
        final MessageHeader original = mis.getMessageHeader();
        if (original == null)
            throw new MslInternalException("Cannot generate a message input stream from an error message.");
        final EntityAuthenticationData entityAuthData = original.getEntityAuthenticationData();
        final MasterToken masterToken = original.getMasterToken();
        final HeaderData headerData = new HeaderData(
            original.getRecipient(),
            messageId,
            original.getNonReplayableId(),
            original.isRenewable(),
            original.isHandshake(),
            original.getMessageCapabilities(),
            original.getKeyRequestData(),
            original.getKeyResponseData(),
            original.getUserAuthenticationData(),
            original.getUserIdToken(),
            original.getServiceTokens()
        );
        final HeaderPeerData peerData = new HeaderPeerData(
            original.getPeerMasterToken(),
            original.getPeerUserIdToken(),
            original.getPeerServiceTokens()
        );
        final MessageHeader header = new MessageHeader(ctx, entityAuthData, masterToken, headerData, peerData);

        // Build a message input stream from the new header.
        final byte[] encoding = header.toMslEncoding(encoder, MslEncoderFormat.JSON);
        final InputStream in = new ByteArrayInputStream(encoding);
        final Set<KeyRequestData> keyRequestData = Collections.emptySet();
        final Map<String,ICryptoContext> cryptoContexts = Collections.emptyMap();
        return new MessageInputStream(ctx, in, keyRequestData, cryptoContexts);
    }

    /**
     * <p>Create a new push MSL message with the given
     * {@link MslControl} and {@link MslContext}.</p>
     *
     * @param mslCtrl MSL control. May be shared.
     * @param mslCtx MSL context. May be shared.
     */
    public PushMslMessage(final MslControl mslCtrl, final MslContext mslCtx) {
        this.mslCtrl = mslCtrl;
        this.mslCtx = mslCtx;
    }

    /**
     * <p>Sends a new MSL message with a single payload chunk containing the
     * provided data out over the given channel.</p>
     *
     * @param ctx channel context.
     * @param data application data to send.
     */
    public void send(final ChannelHandlerContext ctx, final byte[] data) {
        // Grab the original message input stream.
        final Attribute<MessageInputStream> misAttr = ctx.attr(PushConstants.ATTR_KEY_MIS);
        final Object o = misAttr.get();
        if (o == null || !(o instanceof MessageInputStream))
            throw new MslInternalException("Cannot send MSL data without having first initialized MSL communication.");
        final MessageInputStream original = (MessageInputStream)o;

        // Generate a fake request with a random message ID.
        final MessageInputStream random;
        try {
            random = createMessageInputStream(mslCtx, original);
        } catch (final MslException | IOException | MslEncoderException e) {
            e.printStackTrace(System.err);
            return;
        }

        // Send the "response" MSL message.
        final MessageContext msgCtx = new PushMessageContext(data);
        final InputStream in = new ByteArrayInputStream(new byte[0]);
        final OutputStream out = new ChannelOutputStream(ctx.channel());
        final Future<MslChannel> resp = mslCtrl.respond(mslCtx, msgCtx, in, out, random, PushConstants.TIMEOUT_MS);
        try {
            resp.get();
        } catch (final ExecutionException | InterruptedException e) {
            e.printStackTrace(System.err);
            return;
        }
    }

    /** MSL control. */
    private final MslControl mslCtrl;
    /** MSL context. */
    private final MslContext mslCtx;
}

/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
 */
package server;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.netflix.msl.MslInternalException;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.util.MslContext;

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
        final MessageInputStream mis = (MessageInputStream)o;

        // Push out a MSL message based on the message input stream.
        final MessageContext msgCtx = new PushMessageContext(data);
        final InputStream in = new ByteArrayInputStream(new byte[0]);
        final OutputStream out = new ChannelOutputStream(ctx.channel());
        final Future<MslChannel> resp = mslCtrl.push(mslCtx, msgCtx, in, out, mis, PushConstants.TIMEOUT_MS);
        final MslChannel channel;
        try {
            channel = resp.get();
        } catch (final ExecutionException | InterruptedException e) {
            e.printStackTrace(System.err);
            return;
        }

        // If the channel is null, something went wrong.
        if (channel == null)
            System.err.println("Push MSL channel was unexpectedly null.");
    }

    /** MSL control. */
    private final MslControl mslCtrl;
    /** MSL context. */
    private final MslContext mslCtx;
}

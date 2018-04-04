/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
package server;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.util.MslContext;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.util.Attribute;
import server.msg.PushMessageContext;

/**
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PushMslInitHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
    /** UTF-8 character set. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    /** Acknowledgement payload. */
    private static final byte[] ACK = "ack".getBytes(UTF_8);

    /**
     * <p>Create a new MSL initialization handler with the given
     * {@link MslControl} and {@link MslContext}.</p>
     *
     * @param mslCtrl MSL control. May be shared.
     * @param mslCtx MSL context. May be shared.
     */
    public PushMslInitHandler(final MslControl mslCtrl, final MslContext mslCtx) {
        this.mslCtrl = mslCtrl;
        this.mslCtx = mslCtx;
    }

    @Override
    protected void messageReceived(final ChannelHandlerContext ctx, final WebSocketFrame msg) throws Exception {
        // Grab the frame data.
        final ByteBuf frame = msg.content();
        final byte[] framedata = frame.array();
        final InputStream in = new ByteArrayInputStream(framedata);

        // Create the output stream.
        final ChannelOutputStream out = new ChannelOutputStream(ctx.channel());

        // Receive the initial request.
        final MessageContext msgCtx = new PushMessageContext(ACK);
        final Future<MessageInputStream> recv = mslCtrl.receive(mslCtx, msgCtx, in, out, PushConstants.TIMEOUT_MS);
        final MessageInputStream mis;
        try {
            mis = recv.get();
        } catch (final ExecutionException | InterruptedException e) {
            e.printStackTrace(System.err);
            return;
        }

        // If the message input stream is null, a response was probably
        // automatically sent (i.e. a handshake is being performed). That
        // should not occur, since we're not set up to perform authentication
        // or token issuance, but regardless we are done.
        if (mis == null)
            return;

        // Save the message input stream for this channel.
        final Attribute<MessageInputStream> misAttr = ctx.attr(PushConstants.ATTR_KEY_MIS);
        misAttr.set(mis);
    }

    /** MSL control. */
    private final MslControl mslCtrl;
    /** MSL context. */
    private final MslContext mslCtx;
}

/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
 */
package server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;

/**
 * <p>Output stream backed by a channel.</p>
 *
 * <p>All data will be buffered until the output stream is closed, at which
 * point a single {@link BinaryWebSocketFrame} will be created to output the
 * data over the backing channel.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ChannelOutputStream extends OutputStream {
    /**
     * Create a new output stream backed by the provided channel.
     *
     * @param channel the channel.
     */
    public ChannelOutputStream(final Channel channel) {
        this.channel = channel;
    }

    @Override
    public void write(final byte[] b) {
        write(b, 0, b.length);
    }

    @Override
    public void write(final byte[] b, final int off, final int len) {
        // If we flush after writing, then we rely upon the caller to write
        // data in chunks appropriate for each frame. Instead, buffer the data
        // and send it as a single frame when flushed or closed.
        buffer.write(b, off, len);
    }

    @Override
    public void flush() {
        // Do nothing, as MSL will attempt to flush each header and payload
        // chunk, but we don't want the recipient to receive partial MSL
        // messages.
    }

    @Override
    public void close() throws IOException {
        // Close will be called when the MSL message is complete. Write it out
        // to the channel.
        final ByteBuf data = Unpooled.wrappedBuffer(buffer.toByteArray());
        final WebSocketFrame frame = new BinaryWebSocketFrame(data);
        final ChannelFuture future = channel.writeAndFlush(frame);

        // Wait for the write to complete so we know everything worked.
        future.awaitUninterruptibly();
        if (future.isCancelled()) {
            // Do nothing if we were cancelled.
            return;
        } else if (!future.isSuccess()) {
            final Throwable cause = future.cause();
            throw new IOException("Error writing MSL message to the channel.", cause);
        }
        // Success.
    }

    @Override
    public void write(final int b) {
        buffer.write(b);
    }

    /** Channel. */
    private final Channel channel;
    /** Write buffer. */
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
}

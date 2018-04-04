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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.websocket.server.ServerEndpoint;

import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.WebSocketFrameAggregator;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.handler.codec.http.websocketx.extensions.compression.WebSocketServerCompressionHandler;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import server.entityauth.PushRsaStore;
import server.util.PushMslContext;

/**
 * <p>An example WebSocket server that listens for an initial request from a
 * a client, sends an initial response, and then will periodically send
 * additional responses over the same WebSocket that the client may
 * receive.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@ServerEndpoint("/push")
public class PushServer {
    /** Server port number. */
    private static final int PORT = 8080;

    /**
     * <p>This channel initializer sets up the channel pipeline for MSL
     * communication over WebSocket.</p>
     */
    private static class WebSocketServerInitializer extends ChannelInitializer<SocketChannel> {
        /** WebSocket URL path. */
        private static final String WEBSOCKET_PATH = "/websocket";
        /** Maximum content length in bytes. */
        private static final int MAX_CONTENT_LENGTH = 10 * 1024 * 1024;

        /**
         * <p>Create a WebSocket channel initializer that uses the provided MSL
         * control and MSL context.</p>
         *
         * @param ctrl MSL control.
         * @param ctx MSL context.
         */
        public WebSocketServerInitializer(final MslControl ctrl, final MslContext ctx) {
            this.ctrl = ctrl;
            this.ctx = ctx;
        }

        @Override
        public void initChannel(final SocketChannel ch) throws Exception {
            final ChannelPipeline pipeline = ch.pipeline();
            pipeline.addLast(new HttpServerCodec());
            pipeline.addLast(new HttpObjectAggregator(MAX_CONTENT_LENGTH));
            pipeline.addLast(new WebSocketServerCompressionHandler());
            pipeline.addLast(new WebSocketServerProtocolHandler(WEBSOCKET_PATH));
            pipeline.addLast(new WebSocketFrameAggregator(MAX_CONTENT_LENGTH));
            pipeline.addLast(new PushMslInitHandler(ctrl, ctx));
        }

        /** MSL control. */
        private final MslControl ctrl;
        /** MSL context. */
        private final MslContext ctx;
    }

    public static void main(final String[] args) throws Exception {
        // Create the RSA key store.
        final RsaStore rsaStore;
        try {
            final byte[] privKeyEncoded = Base64.decode(PushConstants.RSA_PRIVKEY_B64);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            final PrivateKey privKey = rsaKeyFactory.generatePrivate(privKeySpec);
            rsaStore = new PushRsaStore(PushConstants.SERVER_ID, null, privKey);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new RuntimeException("Invalid RSA private key.", e);
        }

        // Set up the MSL context.
        final MslContext ctx = new PushMslContext(PushConstants.SERVER_ID, rsaStore);

        // Create the MSL control.
        //
        // Since this is an example process all requests on the calling thread.
        final MslControl ctrl = new MslControl(0);
        ctrl.setFilterFactory(new ConsoleFilterStreamFactory());

        // Start listening for connections.
        final EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        final EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            final ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .handler(new LoggingHandler(LogLevel.INFO))
                .childHandler(new WebSocketServerInitializer(ctrl, ctx));

            final Channel ch = b.bind(PORT).sync().channel();

            System.out.println("Open your web browser and navigate to http://127.0.0.1:" + PORT + '/');

            ch.closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
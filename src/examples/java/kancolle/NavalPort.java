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
package kancolle;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;

import kancolle.kc.KanColleServer;
import kancolle.msg.AckMessageContext;
import kancolle.msg.ErrorMessageContext;
import kancolle.msg.Message;
import kancolle.msg.Message.Type;
import kancolle.msg.MessageProcessor;
import kancolle.msg.OrderResponseMessageContext;
import kancolle.msg.ReceiveMessageContext;
import kancolle.util.ConsoleManager;
import kancolle.util.NavalPortMslContext;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.util.MslContext;

/**
 * <p>KanColle naval port.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NavalPort extends Thread implements KanColleServer {
    /**
     * Connection struct.
     */
    private static class Connection {
        /**
         * @param in input stream from remote entity.
         * @param out output stream to remote entity.
         */
        public Connection(final InputStream in, final OutputStream out) {
            this.in = in;
            this.out = out;
        }
        
        /** Input stream from remote entity. */
        public final InputStream in;
        /** Output stream to remote entity. */
        public final OutputStream out;
    }
    
    /**
     * <p>Create a new naval port.</p>
     * 
     * @param ctx this naval port's MSL context.
     * @param console the console manager.
     * @throws MslCryptoException if there is an error getting the naval port
     *         identity from the MSL context.
     */
    NavalPort(final NavalPortMslContext ctx, final ConsoleManager console) throws MslCryptoException {
        this.ctx = ctx;
        this.identity = ctx.getEntityAuthenticationData(null).getIdentity();
        this.console = console;
        this.ctrl = new MslControl(0);
    }
    
    /**
     * @return the naval port callsign.
     */
    @Override
    public String getIdentity() {
        return identity;
    }
    
    /**
     * <p>Accept a connection from a remote entity.</p>
     * 
     * @param in input stream from remote entity.
     * @param out output stream to remote entity.
     * @throws IOException if the connection cannot be established.
     */
    @Override
    public void connect(final InputStream in, final OutputStream out) throws IOException {
        try {
            final Connection c = new Connection(in, out);
            queue.put(c);
        } catch (final InterruptedException e) {
            throw new IOException("Failed to place connection onto the queue.", e);
        }
    }
    
    @Override
    public void run() {
        // Wait for a connection.
        while (true) try {
            final Connection c = queue.take();
            
            // Receive the message.
            final MessageContext rcvCtx = new ReceiveMessageContext();
            final Future<MessageInputStream> requestFuture = ctrl.receive(ctx, rcvCtx, c.in, c.out, 0);
            final MessageInputStream request;
            try {
                request = requestFuture.get();
            } catch (final ExecutionException e) {
                e.printStackTrace(System.err);
                continue;
            }
            if (request == null)
                continue;
            
            // Log errors.
            final ErrorHeader error = request.getErrorHeader();
            if (error != null) {
                console.error(identity, error);
                continue;
            }
            
            // Read message.
            final Message message;
            try {
                message = MessageProcessor.parse(request);
            } catch (final MslMessageException e) {
                e.printStackTrace(System.err);
                continue;
            } catch (final IOException e) {
                e.printStackTrace(System.err);
                continue;
            }
            console.message(identity, message);
            
            // If requesting orders prompt for order entry.
            MessageContext respCtx;
            if (message.getType() == Type.ORDER_REQUEST) {
                try {
                    final String requestor = request.getIdentity();
                    final String orders = console.in(identity, "Orders for " + requestor);
                    respCtx = new OrderResponseMessageContext(orders);
                } catch (final MslCryptoException e) {
                    e.printStackTrace(System.err);
                    respCtx = new ErrorMessageContext(e.getMessage());
                }
            }
            
            // Otherwise simply acknowledge the message.
            else {
                respCtx = new AckMessageContext();
            }
            
            // Send the response.
            final Future<MslChannel> respondFuture = ctrl.respond(ctx, respCtx, c.in, c.out, request, 0);
            try {
                respondFuture.get();
            } catch (final ExecutionException e) {
                e.printStackTrace(System.err);
                continue;
            }
        } catch (final InterruptedException e) {
            e.printStackTrace(System.err);
            break;
        }
    }
    
    /** MSL context. */
    private final MslContext ctx;
    /** Naval port identity. */
    private final String identity;
    /** Console manager. */
    private final ConsoleManager console;
    /** MSL control. */
    private final MslControl ctrl;
    
    /** Input/Output connection queue. */
    private final BlockingQueue<Connection> queue = new LinkedBlockingQueue<Connection>();
}

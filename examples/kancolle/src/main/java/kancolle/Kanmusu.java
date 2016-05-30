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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import kancolle.keyx.DiffieHellmanManager;
import kancolle.keyx.KanColleDiffieHellmanParameters;
import kancolle.msg.CriticalMessageContext;
import kancolle.msg.Message;
import kancolle.msg.Message.Type;
import kancolle.msg.MessageProcessor;
import kancolle.msg.OrderRequestMessageContext;
import kancolle.msg.PingMessageContext;
import kancolle.msg.ReportMessageContext;
import kancolle.util.ConsoleManager;
import kancolle.util.KanmusuMslContext;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.io.JavaUrl;
import com.netflix.msl.io.Url;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.util.MslContext;

/**
 * <p>KanColle Kanmusu ship.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Kanmusu extends Thread {
    /** Ping interval in milliseconds. */
    private static final long PING_INTERVAL = 10000;
    
    /**
     * Request container struct.
     */
    private static class Request {
        /**
         * @param msgCtx request message context.
         * @param responseType expected response message type.
         */
        public Request(final MessageContext msgCtx, final Type responseType) {
            this.msgCtx = msgCtx;
            this.responseType = responseType;
        }
        
        /** Request message context. */
        public final MessageContext msgCtx;
        /** Expected response type. */
        public final Type responseType;
    }
    
    /**
     * <p>Create a new Kanmusu ship.</p>
     * 
     * @param ctx Kanmusu MSL context.
     * @param name officer name.
     * @param fingerprint officer fingerprint.
     * @param port port of origin.
     * @param console the console manager.
     * @throws MslCryptoException if there is an error getting the Kanmusu ship
     *         identity from the MSL context.
     */
    Kanmusu(final KanmusuMslContext ctx, final String name, final byte[] fingerprint, final NavalPort port, final ConsoleManager console) throws MslCryptoException {
        this.ctx = ctx;
        this.identity = ctx.getEntityAuthenticationData(null).getIdentity();
        this.name = name;
        this.fingerprint = fingerprint;
        this.port = port;
        this.console = console;
        this.ctrl = new MslControl(0);
        
        final KanColleDiffieHellmanParameters parameters = new KanColleDiffieHellmanParameters();
        this.keyxManager = new DiffieHellmanManager(parameters, KanColleDiffieHellmanParameters.PARAM_ID);
    }
    
    /**
     * <p>Change the origin naval port for this ship.</p>
     * 
     * @param port the new port of origin.
     */
    public void changeOriginPort(final NavalPort port) {
        dataLock.lock();
        try {
            this.port = port;
        } finally {
            dataLock.unlock();
        }
    }
    
    /**
     * <p>Send a report to the port of origin.</p>
     * 
     * @param records report records.
     * @throws InterruptedException if interrupted while attempting to queue
     *         the request.
     */
    public void report(final List<String> records) throws InterruptedException {
        final MessageContext msgCtx = new ReportMessageContext(name, fingerprint, records, keyxManager);
        final Request request = new Request(msgCtx, Type.ACK);
        requests.put(request);
    }

    /**
     * <p>Send a critical report to the port of origin.</p>
     * 
     * @param records report records.
     * @throws InterruptedException if interrupted while attempting to queue
     *         the request.
     */
    public void critical(final List<String> records) throws InterruptedException {
        final String callsign = port.getIdentity();
        final MessageContext msgCtx = new CriticalMessageContext(name, fingerprint, callsign, records, keyxManager);
        final Request request = new Request(msgCtx, Type.ACK);
        requests.put(request);
    }

    /**
     * <p>Request orders from the port of origin.</p>
     * 
     * @throws InterruptedException if interrupted while attempting to queue
     *         the request.
     */
    public void requestOrders() throws InterruptedException {
        final MessageContext msgCtx = new OrderRequestMessageContext(name, fingerprint, keyxManager);
        final Request request = new Request(msgCtx, Type.ORDER_RESPONSE);
        requests.put(request);
    }
    
    @Override
    public void run() {
        while (true) try {
            // Construct the port URL.
            final Url portUrl = new JavaUrl(new URL("kc://" + port.getIdentity() + "/"));
            
            // Wait for a request or send a ping if the ping interval has
            // elapsed.
            final Request request;
            final long now = System.currentTimeMillis();
            if (now >= lastPing + PING_INTERVAL) {
                final MessageContext msgCtx = new PingMessageContext();
                request = new Request(msgCtx, Type.ACK);
            } else {
                request = requests.poll(PING_INTERVAL, TimeUnit.MILLISECONDS);
                if (request == null)
                    continue;
            }
            
            // Send the request.
            final Future<MslChannel> future = ctrl.request(ctx, request.msgCtx, portUrl, 0);
            final MslChannel channel;
            try {
                channel = future.get();
            } catch (final ExecutionException e) {
                e.printStackTrace(System.err);
                continue;
            } catch (final InterruptedException e) {
                e.printStackTrace(System.err);
                continue;
            }
            
            // Check for cancellation or interruption.
            if (channel == null)
                continue;
            
            // Check for an error.
            final MessageInputStream mis = channel.input;
            final ErrorHeader error = mis.getErrorHeader();
            if (error != null) {
                console.error(identity, error);
                continue;
            }
            
            // Parse the response.
            final Message response;
            try {
                response = MessageProcessor.parse(mis);
            } catch (final MslMessageException e) {
                e.printStackTrace(System.err);
                continue;
            } catch (final IOException e) {
                e.printStackTrace(System.err);
                continue;
            }
            
            // Verify the response.
            final Type type = response.getType();
            if (!request.responseType.equals(type)) {
                console.out(identity, "Expected response type " + request.responseType + "; received response type " + type + ".");
                continue;
            }
            
            // Output the response.
            console.message(identity, response);
        } catch (final MalformedURLException e) {
            e.printStackTrace(System.err);
            break;
        } catch (final InterruptedException e) {
            e.printStackTrace(System.err);
            break;
        }
    }
    
    /** MSL context. */
    private final MslContext ctx;
    /** Kanmusu ship identity. */
    private final String identity;
    /** Console manager. */
    private final ConsoleManager console;
    /** MSL control. */
    private final MslControl ctrl;
    /** Key exchange manager. */
    private final DiffieHellmanManager keyxManager;
    
    /** Officer name. */
    private String name;
    /** Officer fingerprint. */
    private byte[] fingerprint;
    
    /** Default naval port. */
    private NavalPort port;
    /** Time of last ping. */
    private long lastPing = 0;
    
    /** Queued requests. */
    private final BlockingQueue<Request> requests = new LinkedBlockingQueue<Request>();
    
    /** Data lock. */
    private final Lock dataLock = new ReentrantLock();
}

/**
 * Copyright (c) 2015-2018 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.netflix.msl.msg.MessageFactory;
import rx.Observable;
import rx.Observable.OnSubscribe;
import rx.Subscriber;
import rx.functions.Action1;

import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.msg.ErrorMessageRegistry;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.msg.ReceiveMessageContext;
import com.netflix.msl.msg.RespondMessageContext;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.util.FailoverMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.ProxyMslContext;

/**
 * <p>A MSL proxy that first attempts to process messages locally, then
 * forwards them for external processing if unable to do so, and finally
 * attempts to accept and respond if unable to communicate with the external
 * processor.</p>
 * 
 * <p>The {@link #receive(ICryptoContext, ByteBuffer, ByteBuffer, int, MessageDebugContext)}
 * method is used to process an incoming MSL message. If the message is
 * processed successfully, the resulting {@link MessageInputStream} will be
 * returned. If unsuccessful, any data written into the output stream must be
 * delivered to the remote entity.</p>
 * 
 * <p>The {@link #respond(ICryptoContext, Response, ByteBuffer, MessageInputStream, int, MessageDebugContext)}
 * method is used to create a response to a previous MSL message. If the
 * response is generated successfully and the application data will be sent,
 * {@link Boolean#TRUE} is returned. If the application data will not be sent
 * due to an inability to satisfy the application's security and message
 * requirements, {@link Boolean#FALSE} is returned. In all cases any data
 * written into the output stream must be delivered to the remote entity.</p>
 * 
 * <p>The methods {@link #receiveExternally(ByteBuffer, ByteBuffer)}
 * {@link #respondExternally(MessageInputStream, Response, ByteBuffer)}
 * be implemented to perform any external message processing. These methods
 * will be called when the proxy is unable to process a message locally.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class Proxy {
    /**
     * An {@link InputStream} wrapper around a {@link ByteBuffer}.
     */
    private static class ByteBufferInputStream extends InputStream {
        /**
         * <p>Create a new byte buffer input stream with the provided backing
         * byte buffer.</p>
         * 
         * @param buffer backing byte buffer.
         */
        public ByteBufferInputStream(final ByteBuffer buffer) {
            this.buffer = buffer;
        }
        
        /* (non-Javadoc)
         * @see java.io.InputStream#read()
         */
        @Override
        public int read() throws IOException {
            if (available() == 0) return -1;
            return buffer.get();
        }

        /* (non-Javadoc)
         * @see java.io.InputStream#read(byte[], int, int)
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            final int available = available();
            if (available == 0)
                return -1;
            final int count = Math.min(len - off, available);
            buffer.get(b, 0, count);
            return count;
        }

        /* (non-Javadoc)
         * @see java.io.InputStream#skip(long)
         */
        @Override
        public long skip(final long n) throws IOException {
            if (n < 0) return 0;
            final int count = Math.min((int)n, available());
            buffer.position(buffer.position() + count);
            return count;
        }

        /* (non-Javadoc)
         * @see java.io.InputStream#available()
         */
        @Override
        public int available() throws IOException {
            return buffer.remaining();
        }

        /* (non-Javadoc)
         * @see java.io.InputStream#mark(int)
         */
        @Override
        public synchronized void mark(final int readlimit) {
            buffer.mark();
        }

        /* (non-Javadoc)
         * @see java.io.InputStream#reset()
         */
        @Override
        public synchronized void reset() throws IOException {
            buffer.reset();
        }

        /* (non-Javadoc)
         * @see java.io.InputStream#markSupported()
         */
        @Override
        public boolean markSupported() {
            return true;
        }

        /** Backing byte buffer. */
        private final ByteBuffer buffer;
    }

    /**
     * An {@link OutputStream} wrapper around a {@link ByteBuffer}.
     */
    private static class ByteBufferOutputStream extends OutputStream {
        /**
         * <p>Create a new byte buffer output stream with the provided backing
         * byte buffer.</p>
         * 
         * @param buffer backing byte buffer.
         */
        public ByteBufferOutputStream(final ByteBuffer buffer) {
            this.buffer = buffer;
        }

        /* (non-Javadoc)
         * @see java.io.OutputStream#write(int)
         */
        @Override
        public void write(final int b) throws IOException {
            try {
                buffer.put((byte)(b & 0xff));
            } catch (final BufferOverflowException | ReadOnlyBufferException e) {
                throw new IOException(e);
            }
        }

        /* (non-Javadoc)
         * @see java.io.OutputStream#write(byte[], int, int)
         */
        @Override
        public void write(final byte[] b, final int off, final int len) throws IOException {
            if (off < 0 || len < 0 || off + len > b.length)
                throw new IndexOutOfBoundsException();
            try {
                buffer.put(b, off, len);
            } catch (final BufferOverflowException | ReadOnlyBufferException e) {
                throw new IOException(e);
            }
        }

        /** Backing byte buffer. */
        private final ByteBuffer buffer;
    }
    
    /**
     * <p>A response data container.</p>
     */
    public static class Response {
        /**
         * <p>Construct a new response data container with the provided
         * data.</p>
         * 
         * @param appdata the application data to include in the response. May
         *        be empty.
         * @param entityServiceTokens entity-associated service token
         *        name/value pairs. May be empty.
         * @param userServiceTokens user-associated service token name/value
         *        pairs. May be empty.
         * @param user a user to attach to the response. May be {@code null}.
         */
        public Response(final byte[] appdata, final Map<String,byte[]> entityServiceTokens, final Map<String,byte[]> userServiceTokens, final MslUser user) {
            this.appdata = appdata;
            this.entityServiceTokens = Collections.unmodifiableMap(entityServiceTokens);
            this.userServiceTokens = Collections.unmodifiableMap(userServiceTokens);
            this.user = user;
        }
        
        /** Application data. */
        public byte[] appdata;
        /** Entity service tokens. */
        public Map<String,byte[]> entityServiceTokens;
        /** User service tokens. */
        public Map<String,byte[]> userServiceTokens;
        /** MSL user. May be {@code null}. */
        public MslUser user;
    }
    
    /**
     * <p>Create a new proxy.</p>
     * 
     * <p>The local entity authentication data and factory will be used to
     * authenticate the local identity when generating responses.</p>
     * 
     * <p>The MSL token crypto context will be used to verify and decrypt the
     * MSL tokens of received messages.</p>
     * 
     * @param messageFactory message factory.
     * @param registry MSL error message registry.
     * @param entityAuthData local entity authentication data.
     * @param entityAuthFactory local entity authentication factory.
     * @param mslCryptoContext MSL token crypto context.
     */
    public Proxy(final MessageFactory messageFactory, final ErrorMessageRegistry registry, final EntityAuthenticationData entityAuthData, final EntityAuthenticationFactory entityAuthFactory, final ICryptoContext mslCryptoContext) {
        mslCtrl = new MslControl(0, messageFactory, registry);
        proxyMslCtx = new ProxyMslContext(entityAuthData, entityAuthFactory, mslCryptoContext);
        failoverMslCtx = new FailoverMslContext(entityAuthData, entityAuthFactory, mslCryptoContext);
    }
    
    /**
     * <p>This observable receives a request from the remote entity and attempts
     * to process it in the following order:
     * <ol>
     * <li>Locally if the message does not require authentication, key exchange,
     *     or other external dependencies.</li>
     * <li>Through the external service being proxied.</li>
     * <li>With failover behaviors if the external service cannot be accessed
     *     and the message does not require authentication to occur.</li>
     * </ol>
     */
    private class ReceiveObservable implements OnSubscribe<MessageInputStream> {
        /**
         * <p>Create a new receive observable.</p>
         * 
         * <p> The input stream must contain the entire request data, which
         * will be read before any attempt is made to process it.</p>
         * 
         * @param tokenCryptoContext service token crypto context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param timeout renewal lock acquisition timeout.
         * @param dbgCtx message debug context.
         */
        public ReceiveObservable(final ICryptoContext tokenCryptoContext, final ByteBuffer in, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
            this.tokenCryptoContext = tokenCryptoContext;
            this.in = in;
            this.out = out;
            this.timeout = timeout;
            this.dbgCtx = dbgCtx;
        }
        
        /**
         * <p>Receive a request over the provided byte buffer.</p>
         * 
         * <p>If {@link MessageInputStream} is returned then the MSL message
         * was successfully processed and the MSL header and application data
         * can be accessed directly.</p>
         * 
         * <p>If {@code null} is returned then the MSL message does not contain
         * any application data. Any MSL error and handshake responses will
         * have been written into the provided output stream and must be
         * delivered to the remote entity.</p>
         * 
         * <p>If an exception is thrown any MSL error and handshake responses
         * will have been written into the provided output stream and must be
         * delivered to the remote entity.</p>
         * 
         * <p>The following checked exceptions may be thrown:
         * <ul>
         * <li>{@link IOException} if there is an error reading from the input
         *     or writing to the output stream.</li>
         * <li>{@link InterruptedException} if the thread was interrupted while
         *     processing the message.</li>
         * <li>{@link ProxyMslException} if the message cannot be processed due
         *     to a MSL exception.</li>
         * <li>{@link ProxyException} if the message cannot be processed due to
         *     a non-MSL reason.</li>
         * </ul></p>
         * 
         * @param observer the event observer.
         */
        @Override
        public void call(final Subscriber<? super MessageInputStream> observer) {
            try {
                // Mark the byte buffers so their positions can be reset.
                in.mark();
                out.mark();
                
                // First attempt to proxy the request.
                final Observable<MessageInputStream> local = receiveLocally(tokenCryptoContext, in, out, timeout, dbgCtx);
                local.subscribe(new Action1<MessageInputStream>() {
                    @Override
                    public void call(final MessageInputStream mis) {
                        observer.onNext(mis);
                        observer.onCompleted();
                        return;
                    }
                }, new Action1<Throwable>() {
                    @Override
                    public void call(final Throwable t) {
                        // A MslException indicates external processing is
                        // required.
                        if (t instanceof MslException) {
                            callExternal(observer);
                            return;
                        }
                        observer.onError(t);
                        return;
                    }
                });
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }
        
        /**
         * This method has the same behavior as {@link #call(Subscriber)}.
         */
        private void callExternal(final Subscriber<? super MessageInputStream> observer) {
            try {
                // Reset the byte buffers.
                in.reset();
                out.reset();
                
                // Second attempt to process externally.
                final Observable<MessageInputStream> ext = receiveExternally(in, out);
                ext.subscribe(new Action1<MessageInputStream>() {
                    @Override
                    public void call(final MessageInputStream mis) {
                        observer.onNext(mis);
                        observer.onCompleted();
                        return;
                    }
                }, new Action1<Throwable>() {
                    @Override
                    public void call(final Throwable t) {
                        // If there was a problem communicating with or a
                        // transient failure at the external service, failover
                        // processing is required.
                        if (t instanceof ProxyIoException || t instanceof ProxyTransientException) {
                            callFailover(observer);
                            return;
                        }
                        observer.onError(t);
                        return;
                    }
                });
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }

        /**
         * This method has the same behavior as {@link #call(Subscriber)}.
         */
        private void callFailover(final Subscriber<? super MessageInputStream> observer) {
            try {
                // Reset the byte buffers.
                in.reset();
                out.reset();
                
                // Third attempt to process in failover mode.
                final Observable<MessageInputStream> failover = receiveFailover(tokenCryptoContext, in, out, timeout, dbgCtx);
                failover.subscribe(observer);
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }
        
        /** Service token crypto context. */
        final ICryptoContext tokenCryptoContext;
        /** Remote entity input stream. */
        final ByteBuffer in;
        /** Remote entity output stream. */
        final ByteBuffer out;
        /** Renewal lock acquisition timeout in milliseconds. */ 
        final int timeout;
        /** Message debug context. */
        final MessageDebugContext dbgCtx;
    }

    /**
     * <p>This observable receives a request from the remote entity and attempts
     * to process it locally.</p>
     */
    private class ReceiveLocallyObservable implements OnSubscribe<MessageInputStream> {
        /**
         * <p>Create a new receive locally observable.</p>
         * 
         * <p> The input stream must contain the entire request data, which
         * will be read before any attempt is made to process it.</p>
         * 
         * @param tokenCryptoContext service token crypto context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param timeout renewal lock acquisition timeout.
         * @param dbgCtx message debug context.
         */
        public ReceiveLocallyObservable(final ICryptoContext tokenCryptoContext, final ByteBuffer in, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
            this.tokenCryptoContext = tokenCryptoContext;
            this.in = in;
            this.out = out;
            this.timeout = timeout;
            this.dbgCtx = dbgCtx;
        }

        /**
         * <p>Receive and locally process a request over the provided byte
         * buffer.</p>
         * 
         * <p>If {@link MessageInputStream} is returned then the MSL message
         * was successfully processed and the MSL header and application data
         * can be accessed directly.</p>
         * 
         * <p>If {@code null} is returned then the MSL message does not contain
         * any application data. Any MSL error and handshake responses will
         * have been written into the provided output stream and must be
         * delivered to the remote entity.</p>
         * 
         * <p>If an exception is thrown any MSL error and handshake responses will
         * have been written into the provided output byte buffer. If external
         * processing is not indicated then any such data must be delivered to the
         * remote entity.</p>
         * 
         * <p>The following checked exceptions may be thrown:
         * <ul>
         * <li>{@link IOException} if there is an error reading from the input
         *     or writing to the output stream.</li>
         * <li>{@link CancellationException} if the operation was cancelled.
         * <li>{@link InterruptedException} if the thread was interrupted while
         *     processing the message.</li>
         * <li>{@link ProxyMslException} if the message cannot be processed due
         *     to a MSL exception.</li>
         * <li>{@link ProxyException} if the message cannot be processed due to
         *      a non-MSL reason.</li>
         * <li>{@link MslException} if the message must be processed
         *     externally.<li>
         * </ul></p>
         * 
         * @param observer the event observer.
         */
        @Override
        public void call(Subscriber<? super MessageInputStream> observer) {
            // Attempt to proxy the request.
            try {
                final MessageContext msgCtx = new ReceiveMessageContext(tokenCryptoContext, dbgCtx);
                final ByteBufferInputStream bbis = new ByteBufferInputStream(in);
                final ByteBufferOutputStream bbos = new ByteBufferOutputStream(out);
                final Future<MessageInputStream> proxyFuture = mslCtrl.receive(proxyMslCtx, msgCtx, bbis, bbos, timeout);
                final MessageInputStream mis = proxyFuture.get();
                observer.onNext(mis);
                observer.onCompleted();
                return;
            } catch (final InterruptedException e) {
                observer.onError(e);
                return;
            } catch (final ExecutionException e) {
                // Throw the exception if it is not a MSL exception indicating
                // external processing.
                final Throwable cause = e.getCause();
                if (!(cause instanceof MslException)) {
                    observer.onError(new ProxyException("Unexpected exception thrown by proxied MslControl.receive().", cause));
                    return;
                }
                final MslException mslCause = (MslException)cause;
                if (!ProxyMslError.isExternalProcessingRequired(mslCause.getError())) {
                    observer.onError(new ProxyMslException("MSL exception thrown by proxied MslControl.receive().", mslCause));
                    return;
                }
                
                // External processing is required. Throw the original cause.
                observer.onError(mslCause);
                return;
            } catch (Throwable t) {
                observer.onError(t);
                return;
            }
        }
        
        /** Service token crypto context. */
        final ICryptoContext tokenCryptoContext;
        /** Remote entity input stream. */
        final ByteBuffer in;
        /** Remote entity output stream. */
        final ByteBuffer out;
        /** Renewal lock acquisition timeout in milliseconds. */ 
        final int timeout;
        /** Message debug context. */
        final MessageDebugContext dbgCtx;
    }

    /**
     * <p>This observable receives a request from the remote entity and attempts
     * to process it in failover mode.</p>
     */
    private class ReceiveFailoverObservable implements OnSubscribe<MessageInputStream> {
        /**
         * <p>Create a new receive failover observable.</p>
         * 
         * <p> The input stream must contain the entire request data, which
         * will be read before any attempt is made to process it.</p>
         * 
         * @param tokenCryptoContext service token crypto context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param timeout renewal lock acquisition timeout.
         * @param dbgCtx message debug context.
         */
        public ReceiveFailoverObservable(final ICryptoContext tokenCryptoContext, final ByteBuffer in, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
            this.tokenCryptoContext = tokenCryptoContext;
            this.in = in;
            this.out = out;
            this.timeout = timeout;
            this.dbgCtx = dbgCtx;
        }

        /**
         * <p>Receive and locally process in failover mode a request over the
         * provided byte buffer.</p>
         * 
         * <p>If {@link MessageInputStream} is returned then the MSL message
         * was successfully processed and the MSL header and application data
         * can be accessed directly.</p>
         * 
         * <p>If {@code null} is returned then the MSL message does not contain
         * any application data. Any MSL error and handshake responses will
         * have been written into the provided output stream and must be
         * delivered to the remote entity.</p>
         * 
         * <p>If an exception is thrown any MSL error and handshake responses
         * will have been written into the provided output stream and must be
         * delivered to the remote entity.</p>
         * 
         * <p>The following checked exceptions may be thrown:
         * <ul>
         * <li>{@link IOException} if there is an error reading from the input
         *     or writing to the output stream.</li>
         * <li>{@link InterruptedException} if the thread was interrupted while
         *     processing the message.</li>
         * <li>{@link ProxyMslException} if the message cannot be processed due
         *     to a MSL exception.</li>
         * <li>{@link ProxyException} if the message cannot be processed due to
         *     a non-MSL reason.</li>
         * </ul></p>
         * 
         * @param observer the event observer.
         */
        @Override
        public void call(Subscriber<? super MessageInputStream> observer) {
            // Attempt to process the request in failover mode.
            try {
                final MessageContext msgCtx = new ReceiveMessageContext(tokenCryptoContext, dbgCtx);
                final ByteBufferInputStream bbis = new ByteBufferInputStream(in);
                final ByteBufferOutputStream bbos = new ByteBufferOutputStream(out);
                final Future<MessageInputStream> failoverFuture = mslCtrl.receive(failoverMslCtx, msgCtx, bbis, bbos, timeout);
                final MessageInputStream mis = failoverFuture.get();
                observer.onNext(mis);
                observer.onCompleted();
                return;
            } catch (final InterruptedException e) {
                observer.onError(e);
                return;
            } catch (final ExecutionException e) {
                // Throw the exception.
                final Throwable cause = e.getCause();
                if (!(cause instanceof MslException)) {
                    observer.onError(new ProxyException("Unexpected exception thrown by failover MslControl.receive().", cause));
                    return;
                }
                final MslException mslCause = (MslException)cause;
                observer.onError(new ProxyMslException("MSL exception thrown by failover MslControl.recieve().", mslCause));
                return;
            } catch (Throwable t) {
                observer.onError(t);
                return;
            }
        }
        
        /** Service token crypto context. */
        final ICryptoContext tokenCryptoContext;
        /** Remote entity input stream. */
        final ByteBuffer in;
        /** Remote entity output stream. */
        final ByteBuffer out;
        /** Renewal lock acquisition timeout in milliseconds. */ 
        final int timeout;
        /** Message debug context. */
        final MessageDebugContext dbgCtx;
    }
    
    /**
     * <p>Process a request over the provided input byte buffer. The byte
     * buffer must contain the entire request data, which will be read before
     * any attempt is made to process it.</p>
     * 
     * <p>The returned {@link Observable} will return the received
     * {@link MessageInputStream} if the MSL message was successfully
     * processed. The MSL header and application data can then be accessed
     * directly.</p>
     * 
     * <p>If the {@link Observable} returns {@code null} then the received MSL
     * message does not have any application data. Any MSL error and handshake
     * responses will have been written into the provided output stream and
     * must be delivered to the remote entity.</p>
     * 
     * <p>If an exception is thrown any MSL error and handshake responses will
     * have been written into the provided output stream and must be delivered
     * to the remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link IOException} if there is an error reading from the input or
     *     writing to the output stream.</li>
     * <li>{@link CancellationException} if the operation was cancelled.
     * <li>{@link InterruptedException} if the thread was interrupted while
     *     processing the message.</li>
     * <li>{@link ProxyMslException} if the message cannot be processed due to
     *     a MSL exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed due to a
     *      non-MSL reason.</li>
     * </ul></p>
     * 
     * @param tokenCryptoContext service token crypto context.
     * @param in remote entity input byte buffer.
     * @param out remote entity output byte buffer.
     * @param timeout MSL renewal lock acquisition timeout in milliseconds.
     * @param dbgCtx message debug context.
     * @return an {@link Observable} for the message.
     */
    public Observable<MessageInputStream> receive(final ICryptoContext tokenCryptoContext, final ByteBuffer in, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
        return Observable.create(new ReceiveObservable(tokenCryptoContext, in, out, timeout,dbgCtx));
    }
    
    /**
     * <p>Locally process the request contained in the provided input byte
     * buffer.</p>
     * 
     * <p>The returned {@link Observable} will return the received
     * {@link MessageInputStream} if the MSL message was successfully
     * processed. The MSL header and application data can then be accessed
     * directly.</p>
     * 
     * <p>If the {@link Observable} returns {@code null} then the received MSL
     * message does not have any application data. Any MSL error and handshake
     * responses will have been written into the provided output stream and
     * must be delivered to the remote entity.</p>
     * 
     * <p>If an exception is thrown any MSL error and handshake responses will
     * have been written into the provided output byte buffer. If external
     * processing is not indicated then any such data must be delivered to the
     * remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link IOException} if there is an error reading from the input or
     *     writing to the output stream.</li>
     * <li>{@link CancellationException} if the operation was cancelled.
     * <li>{@link InterruptedException} if the thread was interrupted while
     *     processing the message.</li>
     * <li>{@link ProxyMslException} if the message cannot be processed due to
     *     a MSL exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed due to a
     *      non-MSL reason.</li>
     * <li>{@link MslException} if the message must be processed externally.<li>
     * </ul></p>
     * 
     * @param tokenCryptoContext service token crypto context.
     * @param in remote entity input byte buffer.
     * @param out remote entity output byte buffer.
     * @param timeout MSL renewal lock acquisition timeout in milliseconds.
     * @param dbgCtx message debug context.
     * @return an {@link Observable} for the message.
     */
    protected Observable<MessageInputStream> receiveLocally(final ICryptoContext tokenCryptoContext, final ByteBuffer in, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
        return Observable.create(new ReceiveLocallyObservable(tokenCryptoContext, in, out, timeout, dbgCtx));
    }
    
    /**
     * <p>Externally process the request contained in the provided input byte
     * buffer. The byte buffer must contain the entire request data, which will
     * be read before any attempt is made to process it.</p>
     * 
     * <p>If {@link MessageInputStream} is returned then the MSL message was
     * successfully processed and the MSL header and application data can be
     * accessed directly.</p>
     * 
     * <p>If {@code null} was returned then a reply was automatically sent or
     * the operation was cancelled or interrupted. Any MSL response (success or
     * error) will have been written into the provided output stream and must
     * be delivered to the remote entity. Reasons for a {@code null} return
     * value include:</p>
     * <ul>
     * <li>Automatic response to a handshake request.</li>
     * <li>An error response must be sent.</li>
     * </ul></p>
     * 
     * <p>If an exception is thrown any MSL error and handshake responses will
     * have been written into the provided output byte buffer. If failover
     * processing is not indicated then any such data must be delivered to the
     * remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link ProxyIoException} if there is an error communicating with the
     *     external service. This indicates the message should be processed
     *     in failover mode.</li>
     * <li>{@link ProxyTransientException} if there is a transient problem with
     *     the external service. This indicates the message should be processed
     *     in failover mode.</li>
     * <li>{@link ProxyMslException} if the external service throws a MSL
     *     exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed by the
     *     external service for a non-MSL reason.</li>
     * </ul></p>
     * 
     * <p>This function must not call {@link ByteBuffer#mark()} on either the
     * input or output byte buffers.</p>
     * 
     * @param in remote entity input byte buffer.
     * @param out remote entity output byte buffer.
     * @return an {@link Observable} for the message.
     */
    protected abstract Observable<MessageInputStream> receiveExternally(final ByteBuffer in, final ByteBuffer out);

    /**
     * <p>Locally process the request contained in the provided input byte
     * buffer in failover mode.</p>
     * 
     * <p>The returned {@link Observable} will return the received
     * {@link MessageInputStream} if the MSL message was successfully
     * processed. The MSL header and application data can then be accessed
     * directly.</p>
     * 
     * <p>If the {@link Observable} returns {@code null} then the received MSL
     * message does not have any application data. Any MSL error and handshake
     * responses will have been written into the provided output stream and
     * must be delivered to the remote entity.</p>
     * 
     * <p>If an exception is thrown any MSL error and handshake responses will
     * have been written into the provided output stream and must be delivered
     * to the remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link IOException} if there is an error reading from the input or
     *     writing to the output stream.</li>
     * <li>{@link CancellationException} if the operation was cancelled.
     * <li>{@link InterruptedException} if the thread was interrupted while
     *     processing the message.</li>
     * <li>{@link ProxyMslException} if the message cannot be processed due to
     *     a MSL exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed due to a
     *      non-MSL reason.</li>
     * </ul></p>
     * 
     * @param tokenCryptoContext service token crypto context.
     * @param in remote entity input byte buffer.
     * @param out remote entity output byte buffer.
     * @param timeout MSL renewal lock acquisition timeout in milliseconds.
     * @param dbgCtx message debug context.
     * @return an {@link Observable} for the message.
     */
    protected Observable<MessageInputStream> receiveFailover(final ICryptoContext tokenCryptoContext, final ByteBuffer in, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
        return Observable.create(new ReceiveFailoverObservable(tokenCryptoContext, in, out, timeout, dbgCtx));
    }
    
    /**
     * <p>This observable sends a response to the remote entity and attempts to
     * generate the response in the following order:
     * <ol>
     * <li>Locally if the message does not require token renewal, key exchange,
     *     or other external dependencies.</li>
     * <li>Through the external service being proxied.</li>
     * <li>With failover behaviors if the external service cannot be
     *     accessed.</li>
     * </ol>
     */
    private class RespondObservable implements OnSubscribe<Boolean> {
        /**
         * <p>Create a new respond observable.</p>
         * 
         * <p>The provided response data will be used to generate the
         * response.</p>
         * 
         * @param request original request to respond to.
         * @param responseData application response data.
         * @param tokenCryptoContext service token crypto context.
         * @param out remote entity output stream.
         * @param timeout renewal lock acquisition timeout.
         * @param dbgCtx message debug context.
         */
        public RespondObservable(final MessageInputStream request, final Response responseData, final ICryptoContext tokenCryptoContext, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
            this.request = request;
            this.responseData = responseData;
            this.tokenCryptoContext = tokenCryptoContext;
            this.out = out;
            this.timeout = timeout;
            this.dbgCtx = dbgCtx;
        }
        
        /**
         * <p>Send a response over the provided byte buffer.</p>
         * 
         * <p>If {@link Boolean#TRUE} was returned then the response was
         * successfully created and written into the provided output stream and
         * must be delivered to the remote entity.</p>
         * 
         * <p>If {@link Boolean#FALSE} was returned then the provided response
         * data could not be sent and a MSL error response will have been
         * written into the provided output stream and must be delivered to the
         * remote entity. Reasons for an error response include:
         * <ul>
         * <li>The response could not be sent with encryption or integrity
         * protection when it is required.</li>
         * <li>A user cannot be attached to the response due to the lack of a
         * master token.</li>
         * </ul></p>
         * 
         * <p>If an exception is thrown any MSL error response will have been
         * written into the provided output stream and must be delivered to the
         * remote entity.</p>
         * 
         * <p>The following checked exceptions may be thrown:
         * <ul>
         * <li>{@link InterruptedException} if the thread was interrupted while processing the message.</li>
         * <li>{@link IOException} if there is an error writing to the output stream.</li>
         * <li>{@link ProxyMslException} if the message cannot be processed due to a MSL exception.</li>
         * <li>{@link ProxyException} if the message cannot be processed due to a non-MSL reason.</li>
         * </ul></p>
         * 
         * @param observer the event observer.
         */
        @Override
        public void call(final Subscriber<? super Boolean> observer) {
            try {
                // Mark the byte buffer so its position can be reset.
                out.mark();
                
                // First attempt to proxy the operation.
                final Observable<Boolean> local = respondLocally(tokenCryptoContext, responseData, out, request, timeout, dbgCtx);
                local.subscribe(new Action1<Boolean>() {
                    @Override
                    public void call(final Boolean b) {
                        observer.onNext(b);
                        observer.onCompleted();
                        return;
                    }
                }, new Action1<Throwable>() {
                    @Override
                    public void call(final Throwable t) {
                        // A MslException indicates external processing is
                        // required.
                        if (t instanceof MslException) {
                            callExternal(observer);
                            return;
                        }
                        observer.onError(t);
                        return;
                    }
                });
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }

        /**
         * This method has the same behavior as {@link #call(Subscriber)}.
         */
        private void callExternal(final Subscriber<? super Boolean> observer) {
            try {
                // Reset the byte buffer.
                out.reset();
                
                // Second attempt to process externally.
                final Observable<Boolean> ext = respondExternally(request, responseData, out);
                ext.subscribe(new Action1<Boolean>() {
                    @Override
                    public void call(final Boolean b) {
                        observer.onNext(b);
                        observer.onCompleted();
                        return;
                    }
                }, new Action1<Throwable>() {
                    @Override
                    public void call(final Throwable t) {
                        // If there was a problem communicating with or a
                        // transient failure at the external service, failover
                        // processing is required.
                        if (t instanceof ProxyIoException || t instanceof ProxyTransientException) {
                            callFailover(observer);
                            return;
                        }
                        observer.onError(t);
                        return;
                    }
                });
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }
        
        /**
         * This method has the same behavior as {@link #call(Subscriber)}.
         */
        private void callFailover(final Subscriber<? super Boolean> observer) {
            try {
                // Reset the byte buffer.
                out.reset();
                
                // Third attempt to process in failover mode.
                final Observable<Boolean> failover = respondFailover(tokenCryptoContext, responseData, out, request, timeout, dbgCtx);
                failover.subscribe(observer);
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }

        /** Original request. */
        private final MessageInputStream request;
        /** Response data. */
        final Response responseData;
        /** Service token crypto context. */
        final ICryptoContext tokenCryptoContext;
        /** Remote entity output stream. */
        final ByteBuffer out;
        /** Renewal lock acquisition timeout in milliseconds. */ 
        final int timeout;
        /** Message debug context. */
        final MessageDebugContext dbgCtx;
    }

    /**
     * <p>This observable sends a response to the remote entity and attempts to
     * generate the response locally.</p>
     */
    private class RespondLocallyObservable implements OnSubscribe<Boolean> {
        /**
         * <p>Create a new respond locally observable.</p>
         * 
         * <p>The provided response data will be used to generate the
         * response.</p>
         * 
         * @param request original request to respond to.
         * @param responseData application response data.
         * @param tokenCryptoContext service token crypto context.
         * @param out remote entity output stream.
         * @param timeout renewal lock acquisition timeout.
         * @param dbgCtx message debug context.
         */
        public RespondLocallyObservable(final MessageInputStream request, final Response responseData, final ICryptoContext tokenCryptoContext, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
            this.request = request;
            this.responseData = responseData;
            this.tokenCryptoContext = tokenCryptoContext;
            this.out = out;
            this.timeout = timeout;
            this.dbgCtx = dbgCtx;
        }
        
        /**
         * <p>Locally send a response over the provided output stream. The
         * provided response data will be used to generate the response.</p>
         * 
         * <p>If {@link Boolean#TRUE} is returned the response was successfully
         * created and written into the provided output stream. The data in the
         * output stream must be delivered to the remote entity.</p>
         * 
         * <p>If {@link Boolean#FALSE} is returned then the provided response
         * data could not be sent and a MSL error response will have been
         * written into the provided output stream and must be delivered to the
         * remote entity. Reasons for an error response include:
         * <ul>
         * <li>The response could not be sent with encryption or integrity
         * protection when it is required.</li>
         * <li>A user cannot be attached to the response due to the lack of a
         * master token.</li>
         * </ul></p>
         *
         * <p>If an exception is thrown any MSL error and handshake responses
         * will have been written into the provided output byte buffer. If
         * external processing is not indicated then any such data must be
         * delivered to the remote entity.</p>
         * 
         * <p>The following checked exceptions may be thrown:
         * <ul>
         * <li>{@link IOException} if there is an error reading from the input or
         *     writing to the output stream.</li>
         * <li>{@link CancellationException} if the operation was cancelled.
         * <li>{@link InterruptedException} if the thread was interrupted while
         *     processing the message.</li>
         * <li>{@link ProxyMslException} if the message cannot be processed due to
         *     a MSL exception.</li>
         * <li>{@link ProxyException} if the message cannot be processed due to a
         *      non-MSL reason.</li>
         * <li>{@link MslException} if the message must be processed externally.<li>
         * </ul></p>
         * 
         * @param observer the event observer.
         */
        @Override
        public void call(Subscriber<? super Boolean> observer) {
            // Attempt to proxy the operation.
            try {
                final MessageContext msgCtx = new RespondMessageContext(responseData.appdata, responseData.entityServiceTokens, responseData.userServiceTokens, tokenCryptoContext, responseData.user, dbgCtx);
                final ByteArrayInputStream nullInput = new ByteArrayInputStream(new byte[0]);
                final ByteBufferOutputStream bbos = new ByteBufferOutputStream(out);
                final Future<MslChannel> proxyFuture = mslCtrl.respond(proxyMslCtx, msgCtx, nullInput, bbos, request, timeout);
                final MslChannel channel = proxyFuture.get();
                observer.onNext(channel != null && channel.output != null);
                observer.onCompleted();
                return;
            } catch (final InterruptedException e) {
                observer.onError(e);
                return;
            } catch (final ExecutionException e) {
                // Throw the exception if it is not a MSL exception indicating
                // external processing.
                final Throwable cause = e.getCause();
                if (!(cause instanceof MslException)) {
                    observer.onError(new ProxyException("Unexpected exception thrown by proxied MslControl.respond().", cause));
                    return;
                }
                final MslException mslCause = (MslException)cause;
                if (!ProxyMslError.isExternalProcessingRequired(mslCause.getError())) {
                    observer.onError(new ProxyMslException("MSL exception thrown by proxied MslControl.respond().", mslCause));
                    return;
                }
                
                // External processing is required. Throw the original cause.
                observer.onError(mslCause);
                return;
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }

        /** Original request. */
        private final MessageInputStream request;
        /** Response data. */
        final Response responseData;
        /** Service token crypto context. */
        final ICryptoContext tokenCryptoContext;
        /** Remote entity output stream. */
        final ByteBuffer out;
        /** Renewal lock acquisition timeout in milliseconds. */ 
        final int timeout;
        /** Message debug context. */
        final MessageDebugContext dbgCtx;
    }

    /**
     * <p>This observable sends a response to the remote entity and attempts to
     * generate the response in failover mode.</p>
     */
    private class RespondFailoverObservable implements OnSubscribe<Boolean> {
        /**
         * <p>Create a new respond failover observable.</p>
         * 
         * <p>The provided response data will be used to generate the
         * response.</p>
         * 
         * @param request original request to respond to.
         * @param responseData application response data.
         * @param tokenCryptoContext service token crypto context.
         * @param out remote entity output stream.
         * @param timeout renewal lock acquisition timeout.
         * @param dbgCtx message debug context.
         */
        public RespondFailoverObservable(final MessageInputStream request, final Response responseData, final ICryptoContext tokenCryptoContext, final ByteBuffer out, final int timeout, final MessageDebugContext dbgCtx) {
            this.request = request;
            this.responseData = responseData;
            this.tokenCryptoContext = tokenCryptoContext;
            this.out = out;
            this.timeout = timeout;
            this.dbgCtx = dbgCtx;
        }

        /**
         * <p>Locally send a response over the provided input stream in
         * failover mode. The provided response data will be used to generate
         * the response.</p>
         * 
         * <p>If {@link Boolean#TRUE} is returned the response was successfully
         * created and written into the provided output stream. The data in the
         * output stream must be delivered to the remote entity.</p>
         * 
         * <p>If {@link Boolean#FALSE} is returned then the provided response
         * data could not be sent and a MSL error response will have been
         * written into the provided output stream and must be delivered to the
         * remote entity. Reasons for an error response include:
         * <ul>
         * <li>The response could not be sent with encryption or integrity
         * protection when it is required.</li>
         * <li>A user cannot be attached to the response due to the lack of a
         * master token.</li>
         * </ul></p>
         *
         * <p>If an exception is thrown any MSL error and handshake responses will
         * have been written into the provided output stream and must be delivered
         * to the remote entity.</p>
         * 
         * <p>The following checked exceptions may be thrown:
         * <ul>
         * <li>{@link IOException} if there is an error reading from the input or
         *     writing to the output stream.</li>
         * <li>{@link CancellationException} if the operation was cancelled.
         * <li>{@link InterruptedException} if the thread was interrupted while
         *     processing the message.</li>
         * <li>{@link ProxyMslException} if the message cannot be processed due to
         *     a MSL exception.</li>
         * <li>{@link ProxyException} if the message cannot be processed due to a
         *      non-MSL reason.</li>
         * </ul></p>
         * 
         * @param observer the event observer.
         */
        @Override
        public void call(Subscriber<? super Boolean> observer) {
            // Attempt to process the operation in failover mode.
            try {
                final MessageContext msgCtx = new RespondMessageContext(responseData.appdata, responseData.entityServiceTokens, responseData.userServiceTokens, tokenCryptoContext, responseData.user, dbgCtx);
                final ByteArrayInputStream nullInput = new ByteArrayInputStream(new byte[0]);
                final ByteBufferOutputStream bbos = new ByteBufferOutputStream(out);
                final Future<MslChannel> failoverFuture = mslCtrl.respond(failoverMslCtx, msgCtx, nullInput, bbos, request, timeout);
                final MslChannel channel = failoverFuture.get();
                observer.onNext(channel != null && channel.output != null);
                return;
            } catch (final InterruptedException e) {
                observer.onError(e);
                return;
            } catch (final ExecutionException e) {
                // Throw the exception.
                final Throwable cause = e.getCause();
                if (!(cause instanceof MslException)) {
                    observer.onError(new ProxyException("Unexpected exception thrown by failover MslControl.respond().", cause));
                    return;
                }
                final MslException mslCause = (MslException)cause;
                observer.onError(new ProxyMslException("MSL exception thrown by failover MslControl.respond().", mslCause));
                return;
            } catch (final Throwable t) {
                observer.onError(t);
                return;
            }
        }

        /** Original request. */
        private final MessageInputStream request;
        /** Response data. */
        final Response responseData;
        /** Service token crypto context. */
        final ICryptoContext tokenCryptoContext;
        /** Remote entity output stream. */
        final ByteBuffer out;
        /** Renewal lock acquisition timeout in milliseconds. */ 
        final int timeout;
        /** Message debug context. */
        final MessageDebugContext dbgCtx;
    }
    
    /**
     * <p>Send a response over the provided output stream. The provided
     * response data will be used to generate the response.</p>
     * 
     * <p>The returned {@link Observable} will return {@link Boolean#TRUE} the
     * response was successfully created and written into the provided output
     * stream. The data in the output stream must be delivered to the remote
     * entity.</p>
     * 
     * <p>If the {@link Observable} returns {@link Boolean#FALSE} then the
     * provided response data could not be sent and a MSL error response will
     * have been written into the provided output stream and must be delivered
     * to the remote entity. Reasons for an error response include:
     * <ul>
     * <li>The response could not be sent with encryption or integrity
     * protection when it is required.</li>
     * <li>A user cannot be attached to the response due to the lack of a
     * master token.</li>
     * </ul></p>
     *
     * <p>If an exception is thrown any MSL error response will have been
     * written into the provided output stream and must be delivered to the
     * remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link IOException} if there is an error reading from the input or
     *     writing to the output stream.</li>
     * <li>{@link CancellationException} if the operation was cancelled.
     * <li>{@link InterruptedException} if the thread was interrupted while
     *     processing the message.</li>
     * <li>{@link ProxyMslException} if the message cannot be processed due to
     *     a MSL exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed due to a
     *      non-MSL reason.</li>
     * </ul></p>
     * 
     * @param tokenCryptoContext service token crypto context.
     * @param responseData application response data.
     * @param out remote entity output stream.
     * @param request original request to respond to.
     * @param timeout MSL renewal lock acquisition timeout in milliseconds.
     * @param dbgCtx message debug context.
     * @return an {@link Observable} for the response operation.
     */
    public Observable<Boolean> respond(final ICryptoContext tokenCryptoContext, final Response responseData, final ByteBuffer out, final MessageInputStream request, final int timeout, final MessageDebugContext dbgCtx) {
        return Observable.create(new RespondObservable(request, responseData, tokenCryptoContext, out, timeout, dbgCtx));
    }

    /**
     * <p>Locally send a response over the provided output stream. The provided
     * response data will be used to generate the response.</p>
     * 
     * <p>The returned {@link Observable} will return {@link Boolean#TRUE} the
     * response was successfully created and written into the provided output
     * stream. The data in the output stream must be delivered to the remote
     * entity.</p>
     * 
     * <p>If the {@link Observable} returns {@link Boolean#FALSE} then the
     * provided response data could not be sent and a MSL error response will
     * have been written into the provided output stream and must be delivered
     * to the remote entity. Reasons for an error response include:
     * <ul>
     * <li>The response could not be sent with encryption or integrity
     * protection when it is required.</li>
     * <li>A user cannot be attached to the response due to the lack of a
     * master token.</li>
     * </ul></p>
     *
     * <p>If an exception is thrown any MSL error and handshake responses will
     * have been written into the provided output byte buffer. If external
     * processing is not indicated then any such data must be delivered to the
     * remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link IOException} if there is an error reading from the input or
     *     writing to the output stream.</li>
     * <li>{@link CancellationException} if the operation was cancelled.
     * <li>{@link InterruptedException} if the thread was interrupted while
     *     processing the message.</li>
     * <li>{@link ProxyMslException} if the message cannot be processed due to
     *     a MSL exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed due to a
     *      non-MSL reason.</li>
     * <li>{@link MslException} if the message must be processed externally.<li>
     * </ul></p>
     * 
     * @param tokenCryptoContext service token crypto context.
     * @param responseData application response data.
     * @param out remote entity output stream.
     * @param request original request to respond to.
     * @param timeout MSL renewal lock acquisition timeout in milliseconds.
     * @param dbgCtx message debug context.
     * @return an {@link Observable} for the response operation.
     */
    protected Observable<Boolean> respondLocally(final ICryptoContext tokenCryptoContext, final Response responseData, final ByteBuffer out, final MessageInputStream request, final int timeout, final MessageDebugContext dbgCtx) {
        return Observable.create(new RespondLocallyObservable(request, responseData, tokenCryptoContext, out, timeout, dbgCtx));
    }
    
    /**
     * <p>Externally send a response over the provided input stream. The
     * provided response data will be used to generate the response.</p>
     * 
     * <p>The returned {@link Observable} will return {@link Boolean#TRUE} the
     * response was successfully created and written into the provided output
     * stream. The data in the output stream must be delivered to the remote
     * entity.</p>
     * 
     * <p>If the {@link Observable} returns {@link Boolean#FALSE} then the
     * provided response data could not be sent and a MSL error response will
     * have been written into the provided output stream and must be delivered
     * to the remote entity. Reasons for an error response include:
     * <ul>
     * <li>The response could not be sent with encryption or integrity
     * protection when it is required.</li>
     * <li>A user cannot be attached to the response due to the lack of a
     * master token.</li>
     * </ul></p>
     *
     * <p>If an exception is thrown any MSL error and handshake responses will
     * have been written into the provided output byte buffer. If failover
     * processing is not indicated then any such data must be delivered to the
     * remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link ProxyIoException} if there is an error communicating with the
     *     external service. This indicates the message should be processed
     *     in failover mode.</li>
     * <li>{@link ProxyTransientException} if there is a transient problem with
     *     the external service. This indicates the message should be processed
     *     in failover mode.</li>
     * <li>{@link ProxyMslException} if the external service throws a MSL
     *     exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed by the
     *     external service for a non-MSL reason.</li>
     * </ul></p>
     * 
     * <p>This function must not call {@link ByteBuffer#mark()} on either the
     * input or output byte buffers.</p>
     * 
     * @param request original request to respond to.
     * @param responseData application response data.
     * @param out remote entity output byte buffer.
     * @return an {@link Observable} for the response operation.
     */
    protected abstract Observable<Boolean> respondExternally(final MessageInputStream request, final Response responseData, final ByteBuffer out);
    
    /**
     * <p>Locally send a response over the provided input stream in failover
     * mode. The provided response data will be used to generate the
     * response.</p>
     * 
     * <p>The returned {@link Observable} will return {@link Boolean#TRUE} the
     * response was successfully created and written into the provided output
     * stream. The data in the output stream must be delivered to the remote
     * entity.</p>
     * 
     * <p>If the {@link Observable} returns {@link Boolean#FALSE} then the
     * provided response data could not be sent and a MSL error response will
     * have been written into the provided output stream and must be delivered
     * to the remote entity. Reasons for an error response include:
     * <ul>
     * <li>The response could not be sent with encryption or integrity
     * protection when it is required.</li>
     * <li>A user cannot be attached to the response due to the lack of a
     * master token.</li>
     * </ul></p>
     *
     * <p>If an exception is thrown any MSL error and handshake responses will
     * have been written into the provided output stream and must be delivered
     * to the remote entity.</p>
     * 
     * <p>The {@link Observable} may throw any of the following exceptions:
     * <ul>
     * <li>{@link IOException} if there is an error reading from the input or
     *     writing to the output stream.</li>
     * <li>{@link CancellationException} if the operation was cancelled.
     * <li>{@link InterruptedException} if the thread was interrupted while
     *     processing the message.</li>
     * <li>{@link ProxyMslException} if the message cannot be processed due to
     *     a MSL exception.</li>
     * <li>{@link ProxyException} if the message cannot be processed due to a
     *      non-MSL reason.</li>
     * </ul></p>
     * 
     * @param tokenCryptoContext service token crypto context.
     * @param responseData application response data.
     * @param out remote entity output stream.
     * @param request original request to respond to.
     * @param timeout MSL renewal lock acquisition timeout in milliseconds.
     * @param dbgCtx message debug context.
     * @return an {@link Observable} for the response operation.
     */
    protected Observable<Boolean> respondFailover(final ICryptoContext tokenCryptoContext, final Response responseData, final ByteBuffer out, final MessageInputStream request, final int timeout, final MessageDebugContext dbgCtx) {
        return Observable.create(new RespondFailoverObservable(request, responseData, tokenCryptoContext, out, timeout, dbgCtx));
    }
    
    /** MSL control. */
    private final MslControl mslCtrl;
    /** Proxy MSL context. */
    private final MslContext proxyMslCtx;
    /** Failover MSL context. */
    private final MslContext failoverMslCtx;
}

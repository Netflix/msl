/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.FileLockInterruptionException;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslErrorResponseException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.io.MslTokenizer;
import com.netflix.msl.io.Url;
import com.netflix.msl.io.Url.Connection;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.MslUtils;
import com.netflix.msl.util.NullMslStore;

/**
 * <p>Message Security Layer control provides the base operational MSL logic of
 * sending and receiving messages with an optional thread pool. An application
 * should only use one instance of {@code MslControl} for all MSL
 * communication. This class is thread-safe.</p>
 *
 * <p>This class provides methods for sending and receiving messages for all
 * types of entities in both trusted network and peer-to-peer network types.
 * Refer to the documentation for each method to determine which methods should
 * be used based on the entity's role and network type.</p>
 *
 * <h3>Error Handling</h3>
 *
 * <dl>
 *  <dt>{@link ResponseCode#FAIL}</dt>
 *  <dd>The caller is notified of the failure.</dd>
 *
 *  <dt>{@link ResponseCode#TRANSIENT_FAILURE}</dt>
 *  <dd>The caller is notified of the failure. MSL will not automatically
 *      retry.</dd>
 *
 *  <dt>{@link ResponseCode#ENTITY_REAUTH}</dt>
 *  <dd>MSL will attempt to resend the message using the entity authentication
 *      data. The previous master token and master token-bound service tokens
 *      will be discarded if successful.</dd>
 *
 *  <dt>{@link ResponseCode#USER_REAUTH}</dt>
 *  <dd>MSL will attempt to resend the message using the user authentication
 *      data if made available by the message context. Otherwise request fails.
 *      The previous user ID token-bound service tokens will be discarded if
 *      successful.</dd>
 *
 *  <dt>{@link ResponseCode#KEYX_REQUIRED}</dt>
 *  <dd>MSL will attempt to perform key exchange to establish session keys and
 *      then resend the message.</dd>
 *
 *  <dt>{@link ResponseCode#ENTITYDATA_REAUTH}</dt>
 *  <dd>MSL will attempt to resend the message using new entity authentication
 *      data. The previous master token and master token-bound service tokens
 *      will be discarded if successful.</dd>
 *
 *  <dt>{@link ResponseCode#USERDATA_REAUTH}</dt>
 *  <dd>MSL will attempt to resend the message using new user authentication
 *      data if made available by the message context. Otherwise request fails.
 *      The previous user ID token-bound service tokens will be discarded if
 *      successful.</dd>
 *
 *  <dt>{@link ResponseCode#EXPIRED}</dt>
 *  <dd>MSL will attempt to resend the message with the renewable flag set or
 *      after receiving a new master token.</dd>
 *
 *  <dt>{@link ResponseCode#REPLAYED}</dt>
 *  <dd>MSL will attempt to resend the message after renewing the master token
 *      or receiving a new master token.</dd>
 *
 *  <dt>{@link ResponseCode#SSOTOKEN_REJECTED}</dt>
 *  <dd>Identical to {@link ResponseCode#USERDATA_REAUTH}.</dd>
 * </dl>
 *
 * <h3>Anti-Replay</h3>
 *
 * <p>Requests marked as non-replayable will include a non-replayable ID.</p>
 *
 * <p>Responses must always reply with the message ID of the request
 * incremented by 1. When the request message ID equals 2<sup>63</sup>-1 the
 * response message ID must be 0. If the response message ID does not equal the
 * expected value it is rejected and the caller is notified.</p>
 *
 * <h3>Renewal Synchronization</h3>
 *
 * <p>For a given MSL context there will be at most one renewable request with
 * a master token and key request data in process. This prevents excessive
 * master token renewal and potential renewal race conditions.</p>
 *
 * <p>Requests will be marked renewable if any of the following is true:
 * <ul>
 * <li>The master token renewal window has been entered.</li>
 * <li>The user ID token renewal window has been entered.</li>
 * <li>The application requests or requires establishment of session keys.</li>
 * </ul>
 * </p>
 *
 * <h3>MSL Handshake</h3>
 *
 * <p>Whenever requested or possible application data is encrypted and
 * integrity-protected while in transit. If the MSL context entity
 * authentication scheme does not support encryption or integrity protection
 * when requested an initial handshake will be performed to establish session
 * keys. This handshake occurs silently without the application's
 * knowledge.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslControl {
    /**
     * Application level errors that may translate into MSL level errors.
     */
    public static enum ApplicationError {
        /** The entity identity is no longer accepted by the application. */
        ENTITY_REJECTED,
        /** The user identity is no longer accepted by the application. */
        USER_REJECTED,
    }

    /**
     * A {@link MessageInputStream} and {@link MessageOutputStream} pair
     * representing a single MSL communication channel established between
     * the local and remote entities.
     */
    public static class MslChannel {
        /**
         * Create a new MSL channel with the provided input and output streams.
         *
         * @param input message input stream to read from the remote entity.
         * @param output message output stream to write to the remote entity.
         */
        protected MslChannel(final MessageInputStream input, final MessageOutputStream output) {
            this.input = input;
            this.output = output;
        }

        /** Message input stream to read from the remote entity. */
        public final MessageInputStream input;
        /** Message output stream to write to the remote entity. */
        public final MessageOutputStream output;
    }

    /**
     * A map key based off a MSL context and master token pair.
     */
    private static class MslContextMasterTokenKey {
        /**
         * Create a new MSL context and master token map key.
         *
         * @param ctx MSL context.
         * @param masterToken master token.
         */
        public MslContextMasterTokenKey(final MslContext ctx, final MasterToken masterToken) {
            this.ctx = ctx;
            this.masterToken = masterToken;
        }

        /* (non-Javadoc)
         * @see java.lang.Object#hashCode()
         */
        @Override
        public int hashCode() {
            return this.ctx.hashCode() ^ this.masterToken.hashCode();
        }

        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals(final Object obj) {
            if (obj == this) return true;
            if (!(obj instanceof MslContextMasterTokenKey)) return false;
            final MslContextMasterTokenKey that = (MslContextMasterTokenKey)obj;
            return this.ctx.equals(that.ctx) && this.masterToken.equals(that.masterToken);
        }

        /** MSL context. */
        private final MslContext ctx;
        /** Master token. */
        private final MasterToken masterToken;
    }

    /**
     * This class executes all tasks synchronously on the calling thread.
     */
    private static class SynchronousExecutor extends AbstractExecutorService {
        /* (non-Javadoc)
         * @see java.util.concurrent.Executor#execute(java.lang.Runnable)
         */
        @Override
        public void execute(final Runnable command) {
            // All the AbstractExecutorService methods eventually end up here
            // so checking for shutdown and executing on the caller should be
            // okay for this implementation.
            if (shutdown)
                throw new RejectedExecutionException("Synchronous executor already shut down.");
            command.run();
        }

        /* (non-Javadoc)
         * @see java.util.concurrent.ExecutorService#awaitTermination(long, java.util.concurrent.TimeUnit)
         */
        @Override
        public boolean awaitTermination(final long timeout, final TimeUnit unit) {
            return false;
        }

        /* (non-Javadoc)
         * @see java.util.concurrent.ExecutorService#isShutdown()
         */
        @Override
        public boolean isShutdown() {
            return shutdown;
        }

        /* (non-Javadoc)
         * @see java.util.concurrent.ExecutorService#isTerminated()
         */
        @Override
        public boolean isTerminated() {
            return shutdown;
        }

        /* (non-Javadoc)
         * @see java.util.concurrent.ExecutorService#shutdown()
         */
        @Override
        public void shutdown() {
            shutdown = true;
        }

        /* (non-Javadoc)
         * @see java.util.concurrent.ExecutorService#shutdownNow()
         */
        @Override
        public List<Runnable> shutdownNow() {
            shutdown = true;
            return Collections.emptyList();
        }

        /** Shutdown? */
        private boolean shutdown = false;
    }

    /**
     * A dummy MSL context only used for our dummy
     * {@link MslControl#NULL_MASTER_TOKEN}.
     */
    private static class DummyMslContext extends MslContext {
        /** A dummy MSL encoder factory. */
        private static class DummyMslEncoderFactory extends MslEncoderFactory {
            @Override
            public MslEncoderFormat getPreferredFormat(final Set<MslEncoderFormat> formats) {
                return MslEncoderFormat.JSON;
            }

            @Override
            protected MslTokenizer generateTokenizer(final InputStream source, final MslEncoderFormat format) {
                throw new MslInternalException("DummyMslEncoderFactory.generateTokenizer() not supported.");
            }

            @Override
            public MslObject parseObject(final byte[] encoding) {
                throw new MslInternalException("DummyMslEncoderFactory.parseObject() not supported.");
            }

            @Override
            public byte[] encodeObject(final MslObject object, final MslEncoderFormat format) {
                throw new MslInternalException("DummyMslEncoderFactory.encodeObject() not supported.");
            }
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getTime()
         */
        @Override
        public long getTime() {
            return System.currentTimeMillis();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getRandom()
         */
        @Override
        public Random getRandom() {
            return new Random();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#isPeerToPeer()
         */
        @Override
        public boolean isPeerToPeer() {
            return false;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getMessageCapabilities()
         */
        @Override
        public MessageCapabilities getMessageCapabilities() {
            return null;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getEntityAuthenticationData(com.netflix.msl.util.MslContext.ReauthCode)
         */
        @Override
        public EntityAuthenticationData getEntityAuthenticationData(final MslContext.ReauthCode reauth) {
            return new UnauthenticatedAuthenticationData("dummy");
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
         */
        @Override
        public ICryptoContext getMslCryptoContext() throws MslCryptoException {
            return new NullCryptoContext();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getEntityAuthenticationScheme(java.lang.String)
         */
        @Override
        public EntityAuthenticationScheme getEntityAuthenticationScheme(final String name) {
            return EntityAuthenticationScheme.getScheme(name);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getEntityAuthenticationFactory(com.netflix.msl.entityauth.EntityAuthenticationScheme)
         */
        @Override
        public EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
            return null;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getUserAuthenticationScheme(java.lang.String)
         */
        @Override
        public UserAuthenticationScheme getUserAuthenticationScheme(final String name) {
            return UserAuthenticationScheme.getScheme(name);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getUserAuthenticationFactory(com.netflix.msl.userauth.UserAuthenticationScheme)
         */
        @Override
        public UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
            return null;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getTokenFactory()
         */
        @Override
        public TokenFactory getTokenFactory() {
            throw new MslInternalException("Dummy token factory should never actually get used.");
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getKeyExchangeScheme(java.lang.String)
         */
        @Override
        public KeyExchangeScheme getKeyExchangeScheme(final String name) {
            return KeyExchangeScheme.getScheme(name);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getKeyExchangeFactory(com.netflix.msl.keyx.KeyExchangeScheme)
         */
        @Override
        public KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
            return null;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getKeyExchangeFactories()
         */
        @Override
        public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
            return new TreeSet<KeyExchangeFactory>();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getMslStore()
         */
        @Override
        public MslStore getMslStore() {
            return new NullMslStore();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslContext#getMslEncoderFactory()
         */
        @Override
        public MslEncoderFactory getMslEncoderFactory() {
            return new DummyMslEncoderFactory();
        }
    }

    /**
     * A dummy error message registry that always returns null for the user
     * message.
     */
    private static class DummyMessageRegistry implements ErrorMessageRegistry {
        /* (non-Javadoc)
         * @see com.netflix.msl.msg.ErrorMessageRegistry#getUserMessage(com.netflix.msl.MslError, java.util.List)
         */
        @Override
        public String getUserMessage(final MslError err, final List<String> languages) {
            return null;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.ErrorMessageRegistry#getUserMessage(java.lang.Throwable, java.util.List)
         */
        @Override
        public String getUserMessage(final Throwable err, final List<String> languages) {
            return null;
        }
    }

    /**
     * Base class for custom message contexts. All methods are passed through
     * to the backing message context.
     */
    private static class FilterMessageContext implements MessageContext {
        /**
         * Creates a message context that passes through calls to the backing
         * message context.
         *
         * @param appCtx the application's message context.
         */
        protected FilterMessageContext(final MessageContext appCtx) {
            this.appCtx = appCtx;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#getCryptoContexts()
         */
        @Override
        public Map<String, ICryptoContext> getCryptoContexts() {
            return appCtx.getCryptoContexts();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#getRemoteEntityIdentity()
         */
        @Override
        public String getRemoteEntityIdentity() {
            return appCtx.getRemoteEntityIdentity();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#isEncrypted()
         */
        @Override
        public boolean isEncrypted() {
            return appCtx.isEncrypted();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#isIntegrityProtected()
         */
        @Override
        public boolean isIntegrityProtected() {
            return appCtx.isIntegrityProtected();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#isNonReplayable()
         */
        @Override
        public boolean isNonReplayable() {
            return appCtx.isNonReplayable();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#isRequestingTokens()
         */
        @Override
        public boolean isRequestingTokens() {
            return appCtx.isRequestingTokens();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#getUserId()
         */
        @Override
        public String getUserId() {
            return appCtx.getUserId();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#getUserAuthData(com.netflix.msl.msg.MessageContext.ReauthCode, boolean, boolean)
         */
        @Override
        public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
            return appCtx.getUserAuthData(reauthCode, renewable, required);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#getUser()
         */
        @Override
        public MslUser getUser() {
            return appCtx.getUser();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#getKeyRequestData()
         */
        @Override
        public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
            return appCtx.getKeyRequestData();
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#updateServiceTokens(com.netflix.msl.msg.MessageServiceTokenBuilder, boolean)
         */
        @Override
        public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) throws MslMessageException, MslEncodingException, MslCryptoException, MslException {
            appCtx.updateServiceTokens(builder, handshake);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
         */
        @Override
        public void write(final MessageOutputStream output) throws IOException {
            appCtx.write(output);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#getDebugContext()
         */
        @Override
        public MessageDebugContext getDebugContext() {
            return appCtx.getDebugContext();
        }

        /** The backing application message context. */
        protected final MessageContext appCtx;
    }

    /**
     * This message context is used to re-send a message.
     */
    private static class ResendMessageContext extends FilterMessageContext {
        /**
         * Creates a message context used to re-send a message after an error
         * or handshake. If the payloads are null the application's message
         * context will be asked to write its data. Otherwise the provided
         * payloads will be used for the message's application data.
         *
         * @param payloads original request payload chunks. May be null.
         * @param appCtx the application's message context.
         */
        public ResendMessageContext(final List<PayloadChunk> payloads, final MessageContext appCtx) {
            super(appCtx);
            this.payloads = payloads;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MslControl.FilterMessageContext#write(com.netflix.msl.msg.MessageOutputStream)
         */
        @Override
        public void write(final MessageOutputStream output) throws IOException {
            // If there are no payloads ask the application message context to
            // write its data.
            if (payloads == null || payloads.isEmpty()) {
                appCtx.write(output);
                return;
            }

            // Rewrite the payloads one-by-one.
            for (final PayloadChunk chunk : payloads) {
                output.setCompressionAlgorithm(chunk.getCompressionAlgo());
                output.write(chunk.getData());
                if (chunk.isEndOfMessage())
                    output.close();
                else
                    output.flush();
            }
        }

        /** The application data to resend. */
        private final List<PayloadChunk> payloads;
    }

    /**
     * This message context is used to send messages that will not expect a
     * response.
     */
    private static class SendMessageContext extends FilterMessageContext {
        /**
         * Creates a message context used to send messages that do not expect a
         * response by ensuring that the message context conforms to those
         * expectations.
         *
         * @param appCtx the application's message context.
         */
        public SendMessageContext(final MessageContext appCtx) {
            super(appCtx);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MslControl.FilterMessageContext#isRequestingTokens()
         */
        @Override
        public boolean isRequestingTokens() {
            return false;
        }
    }

    /**
     * This message context is used to send a handshake response.
     */
    private static class KeyxResponseMessageContext extends FilterMessageContext {
        /**
         * Creates a message context used for automatically generated handshake
         * responses.
         *
         * @param appCtx the application's message context.
         */
        public KeyxResponseMessageContext(final MessageContext appCtx) {
            super(appCtx);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#isEncrypted()
         */
        @Override
        public boolean isEncrypted() {
            // Key exchange responses cannot require encryption otherwise key
            // exchange could never succeed in some cases.
            return false;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MslControl.FilterMessageContext#isIntegrityProtected()
         */
        @Override
        public boolean isIntegrityProtected() {
            // Key exchange responses cannot require integrity protection
            // otherwise key exchange could never succeed in some cases.
            return false;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MessageContext#isNonReplayable()
         */
        @Override
        public boolean isNonReplayable() {
            return false;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.msg.MslControl.FilterMessageContext#write(com.netflix.msl.msg.MessageOutputStream)
         */
        @Override
        public void write(final MessageOutputStream output) throws IOException {
            // No application data.
        }
    }

    /**
     * <p>Returns true if the current thread has been interrupted as indicated
     * by the {@code Thread#isInterrupted()} method or the type of caught
     * throwable.</p>
     *
     * <p>The following {@code Throwable} types are considered interruptions that the application
     * initiated or should otherwise be aware of:
     * <ul>
     * <li>{@link InterruptedException}</li>
     * <li>{@link InterruptedIOException} except for {@link SocketTimeoutException}</li>
     * <li>{@link FileLockInterruptionException}</li>
     * <li>{@link ClosedByInterruptException}</li>
     * </ul></p>
     *
     * @param t caught throwable. May be null.
     * @return true if this thread was interrupted or the exception indicates
     *         an operation was interrupted.
     */
    protected static boolean cancelled(Throwable t) {
        // Clear the interrupted state so we continue to be cancelled if the
        // thread is re-used.
        if (Thread.interrupted())
            return true;
        while (t != null) {
            if (t instanceof InterruptedException ||
                (t instanceof InterruptedIOException && !(t instanceof SocketTimeoutException)) ||
                t instanceof FileLockInterruptionException ||
                t instanceof ClosedByInterruptException)
            {
                return true;
            }
            t = t.getCause();
        }
        return false;
    }

    /**
     * Create a new instance of MSL control with the specified number of
     * threads. A thread count of zero will cause all operations to execute on
     * the calling thread.
     *
     * @param numThreads number of worker threads to create.
     */
    public MslControl(final int numThreads) {
        this(numThreads, null, null);
    }

    /**
     * Create a new instance of MSL control with the specified number of
     * threads and user error message registry. A thread count of zero will
     * cause all operations to execute on the calling thread.
     *
     * @param numThreads number of worker threads to create.
     * @param messageFactory message factory. May be {@code null}.
     * @param messageRegistry error message registry. May be {@code null}.
     */
    public MslControl(final int numThreads, final MessageFactory messageFactory, final ErrorMessageRegistry messageRegistry) {
        if (numThreads < 0)
            throw new IllegalArgumentException("Number of threads must be non-negative.");

        // Set the stream factory.
        this.messageFactory = (messageFactory != null) ? messageFactory : new MessageFactory();

        // Set the message registry.
        this.messageRegistry = (messageRegistry != null) ? messageRegistry : new DummyMessageRegistry();

        // Create the thread pool if requested.
        if (numThreads > 0)
            executor = Executors.newFixedThreadPool(numThreads);
        else
            executor = new SynchronousExecutor();

        // Create the dummy master token used as a special value when releasing
        // the renewal lock without a new master token.
        try {
            final MslContext ctx = new DummyMslContext();
            final MslObject dummy = ctx.getMslEncoderFactory().createObject();
            final byte[] keydata = new byte[16];
            final SecretKey encryptionKey = new SecretKeySpec(keydata, JcaAlgorithm.AES);
            final SecretKey hmacKey = new SecretKeySpec(keydata, JcaAlgorithm.HMAC_SHA256);
            NULL_MASTER_TOKEN = new MasterToken(ctx, new Date(), new Date(), 1L, 1L, dummy, "dummy", encryptionKey, hmacKey);
        } catch (final MslEncodingException e) {
            throw new MslInternalException("Unexpected exception when constructing dummy master token.", e);
        } catch (final MslCryptoException e) {
            throw new MslInternalException("Unexpected exception when constructing dummy master token.", e);
        }
    }

    /**
     * Assigns a filter stream factory that will be used to filter any incoming
     * or outgoing messages. The filters will be placed between the MSL message
     * and MSL control, meaning they will see the actual MSL message data as it
     * is being read from or written to the remote entity.
     *
     * @param factory filter stream factory. May be null.
     */
    public void setFilterFactory(final FilterStreamFactory factory) {
        filterFactory = factory;
    }

    /**
     * Gracefully shutdown the MSL control instance. No additional messages may
     * be processed. Any messages pending or in process will be completed.
     */
    public void shutdown() {
        executor.shutdown();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        executor.shutdownNow();
        super.finalize();
    }

    /**
     * <p>Returns the newest master token from the MSL store and acquires the
     * master token's read lock.</p>
     *
     * <p>When the caller no longer requires the master token or its crypto
     * context to exist (i.e. it does not expect to receive a response that
     * uses the same master token) then it must release the lock.</p>
     *
     * @param ctx MSL context.
     * @return the newest master token or null if there is none.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to acquire the master token's read lock.
     * @see #releaseMasterToken(MasterToken)
     */
    private MasterToken getNewestMasterToken(final MslContext ctx) throws InterruptedException {
        do {
            // Get the newest master token. If there is none then immediately
            // return.
            final MslStore store = ctx.getMslStore();
            final MasterToken masterToken = store.getMasterToken();
            if (masterToken == null) return null;

            // Acquire the master token read lock, creating it if necessary.
            final MslContextMasterTokenKey key = new MslContextMasterTokenKey(ctx, masterToken);
            final ReadWriteLock newLock = new ReentrantReadWriteLock();
            final ReadWriteLock oldLock = masterTokenLocks.putIfAbsent(key, newLock);
            final ReadWriteLock finalLock = (oldLock != null) ? oldLock : newLock;
            finalLock.readLock().lockInterruptibly();

            // Now we have to be tricky and make sure the master token we just
            // acquired is still the newest master token. This is necessary
            // just in case the master token was deleted between grabbing it
            // from the MSL store and acquiring the read lock.
            final MasterToken newestMasterToken = store.getMasterToken();
            if (masterToken.equals(newestMasterToken))
                return masterToken;

            // If the master tokens are not the same then release the read
            // lock, acquire the write lock, and then delete the master token
            // lock (it may already be deleted). Then try again.
            finalLock.readLock().unlock();
            finalLock.writeLock().lockInterruptibly();
            masterTokenLocks.remove(key);
            finalLock.writeLock().unlock();
        } while (true);
    }

    /**
     * Deletes the provided master token from the MSL store. Doing so requires
     * acquiring the master token's write lock.
     *
     * @param ctx MSL context.
     * @param masterToken master token to delete. May be null.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to acquire the master token's write lock.
     */
    private void deleteMasterToken(final MslContext ctx, final MasterToken masterToken) throws InterruptedException {
        // Do nothing if the master token is null.
        if (masterToken == null)
            return;

        // Acquire the write lock and delete the master token from the store.
        //
        // TODO it would be nice to do this on another thread to avoid delaying
        // the application.
        final MslContextMasterTokenKey key = new MslContextMasterTokenKey(ctx, masterToken);
        final ReadWriteLock newLock = new ReentrantReadWriteLock();
        final ReadWriteLock oldLock = masterTokenLocks.putIfAbsent(key, newLock);

        // ReentrantReadWriteLock requires us to release the read lock if
        // we are holding it before acquiring the write lock. If there is
        // an old lock then we are already holding the read lock. Otherwise
        // no one is holding any locks.
        final Lock writeLock;
        if (oldLock != null) {
            oldLock.readLock().unlock();
            writeLock = oldLock.writeLock();
        } else {
            writeLock = newLock.writeLock();
        }
        writeLock.lockInterruptibly();
        try {
            ctx.getMslStore().removeCryptoContext(masterToken);
        } finally {
            // It should be okay to delete this read/write lock because no
            // one should be using the deleted master token anymore; a new
            // master token would have been received before deleting the
            // old one.
            masterTokenLocks.remove(key);
            writeLock.unlock();
        }
    }

    /**
     * Release the read lock of the provided master token. If no master token
     * is provided then this method is a no-op.
     *
     * @param ctx MSL context.
     * @param masterToken the master token. May be null.
     * @see #getNewestMasterToken(MslContext)
     */
    private void releaseMasterToken(final MslContext ctx, final MasterToken masterToken) {
        if (masterToken != null) {
            final MslContextMasterTokenKey key = new MslContextMasterTokenKey(ctx, masterToken);
            final ReadWriteLock lock = masterTokenLocks.get(key);

            // The lock may be null if the master token was deleted.
            if (lock != null)
                lock.readLock().unlock();
        }
    }

    /**
     * Update the MSL store crypto contexts with the crypto contexts of the
     * message being sent. Only crypto contexts for master tokens used by the
     * local entity for message authentication are saved.
     *
     * @param ctx MSL context.
     * @param messageHeader outgoing message header.
     * @param keyExchangeData outgoing message key exchange data.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to delete an old master token.
     */
    private void updateCryptoContexts(final MslContext ctx, final MessageHeader messageHeader, final KeyExchangeData keyExchangeData) throws InterruptedException {
        // In trusted network mode save the crypto context of the message's key
        // response data as an optimization.
        final MslStore store = ctx.getMslStore();
        if (!ctx.isPeerToPeer() && keyExchangeData != null) {
            final KeyResponseData keyResponseData = keyExchangeData.keyResponseData;
            final ICryptoContext keyxCryptoContext = keyExchangeData.cryptoContext;
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            store.setCryptoContext(keyxMasterToken, keyxCryptoContext);

            // Delete the old master token. Even if we receive future messages
            // with this master token we can reconstruct the crypto context.
            deleteMasterToken(ctx, messageHeader.getMasterToken());
        }
    }

    /**
     * Update the MSL store crypto contexts with the crypto contexts provided
     * by received message.
     *
     * @param ctx MSL context.
     * @param request previous message the response was received for.
     * @param response received message input stream.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to delete an old master token.
     */
    private void updateCryptoContexts(final MslContext ctx, final MessageHeader request, final MessageInputStream response) throws InterruptedException {
        // Do nothing for error messages.
        final MessageHeader messageHeader = response.getMessageHeader();
        if (messageHeader == null)
            return;

        // Save the crypto context of the message's key response data.
        final MslStore store = ctx.getMslStore();
        final KeyResponseData keyResponseData = messageHeader.getKeyResponseData();
        if (keyResponseData != null) {
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            store.setCryptoContext(keyxMasterToken, response.getKeyExchangeCryptoContext());

            // Delete the old master token. We won't use it anymore to build
            // messages.
            deleteMasterToken(ctx, request.getMasterToken());
        }
    }

    /**
     * Update the MSL store by removing any service tokens marked for deletion
     * and adding/replacing any other service tokens contained in the message
     * header.
     *
     * @param ctx MSL context.
     * @param masterToken master for the service tokens.
     * @param userIdToken user ID token for the service tokens.
     * @param serviceTokens the service tokens to update.
     * @throws MslException if a token cannot be removed or added/replaced
     *         because of a master token or user ID token mismatch.
     */
    private static void storeServiceTokens(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken, final Set<ServiceToken> serviceTokens) throws MslException {
        // Remove deleted service tokens from the store. Update stored
        // service tokens.
        final MslStore store = ctx.getMslStore();
        final Set<ServiceToken> storeTokens = new HashSet<ServiceToken>();
        for (final ServiceToken token : serviceTokens) {
            // Skip service tokens that are bound to a master token if the
            // local entity issued the master token.
            if (token.isBoundTo(masterToken) && masterToken.isVerified())
                continue;
            final byte[] data = token.getData();
            if (data != null && data.length == 0)
                store.removeServiceTokens(token.getName(), token.isMasterTokenBound() ? masterToken : null, token.isUserIdTokenBound() ? userIdToken : null);
            else
                storeTokens.add(token);
        }
        store.addServiceTokens(storeTokens);
    }

    /**
     * <p>Create a new message builder that will craft a new message.</p>
     *
     * <p>If a master token is available it will be used to build the new
     * message and its read lock will be acquired. The caller must release the
     * read lock after it has either received a response to the built request
     * or after sending the message if no response is expected.</p>
     *
     * <p>If a master token is available and a user ID is provided by the
     * message context the user ID token for that user ID will be used to build
     * the message if the user ID token is bound to the master token.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @return the message builder.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to acquire the master token's read lock.
     */
    private MessageBuilder buildRequest(final MslContext ctx, final MessageContext msgCtx) throws InterruptedException {
        final MslStore store = ctx.getMslStore();

        // Grab the newest master token.
        final MasterToken masterToken = getNewestMasterToken(ctx);
        try {
            final UserIdToken userIdToken;
            if (masterToken != null) {
                // Grab the user ID token for the message's user. It may not be bound
                // to the newest master token if the newest master token invalidated
                // it.
                final String userId = msgCtx.getUserId();
                final UserIdToken storedUserIdToken = (userId != null) ? store.getUserIdToken(userId) : null;
                userIdToken = (storedUserIdToken != null && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
            } else {
                userIdToken = null;
            }

            final MessageBuilder builder = messageFactory.createRequest(ctx, masterToken, userIdToken);
            builder.setNonReplayable(msgCtx.isNonReplayable());
            return builder;
        } catch (final MslException e) {
            // Release the master token lock.
            releaseMasterToken(ctx, masterToken);
            throw new MslInternalException("User ID token not bound to master token despite internal check.", e);
        } catch (final RuntimeException re) {
            // Release the master token lock.
            releaseMasterToken(ctx, masterToken);
            throw re;
        }
    }

    /**
     * <p>Create a new message builder that will craft a new message in
     * response to another message. The constructed message may be used as a
     * request.</p>
     *
     * <p>In peer-to-peer mode if the response does not have a primary master
     * token and a master token is available then it will be used to build the
     * new message and its read lock will be acquired. The caller must release
     * the read lock after it has either received a response to the built
     * request or after sending the message if no response is expected.</p>
     *
     * <p>In peer-to-peer mode if a master token is being used to build the new
     * message and a user ID is provided by the message context, the user ID
     * token for that user ID will be used to build the message if the user ID
     * token is bound to the master token.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param request message header to respond to.
     * @return the message builder.
     * @throws MslMasterTokenException if the provided message's master token
     *         is not trusted.
     * @throws MslCryptoException if the crypto context from a key exchange
     *         cannot be created.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslUserAuthException if there is an error with the user
     *         authentication data or the user ID token cannot be created.
     * @throws MslException if a user ID token in the message header is not
     *         bound to its corresponding master token.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to acquire the master token's read lock. (Only applicable in
     *         peer-to-peer mode.)
     */
    private MessageBuilder buildResponse(final MslContext ctx, final MessageContext msgCtx, final MessageHeader request) throws MslKeyExchangeException, MslCryptoException, MslMasterTokenException, MslUserAuthException, MslException, InterruptedException {
        // Create the response.
        final MessageBuilder builder = messageFactory.createResponse(ctx, request);
        builder.setNonReplayable(msgCtx.isNonReplayable());

        // Trusted network clients should use the newest master token. Trusted
        // network servers must not use a newer master token. This method is
        // only called by trusted network clients after a handshake response is
        // received so if the request does not contain key response data then
        // we know the local entity is a trusted network server and should
        // return immediately.
        if (!ctx.isPeerToPeer() && request.getKeyResponseData() == null)
            return builder;

        // In peer-to-peer mode the primary master token may no longer be known
        // if it was renewed between calls to receive() and respond()
        // (otherwise we would have held a lock). In this case, we need to
        // use the newest primary authentication tokens.
        //
        // Likewise, if the primary authentication tokens are not already set
        // then use what we have received.
        //
        // Either way we should be able to use the newest master token,
        // acquiring the read lock at the same time which we definitely want.
        final MasterToken masterToken = getNewestMasterToken(ctx);
        try {
            final UserIdToken userIdToken;
            if (masterToken != null) {
                // Grab the user ID token for the message's user. It may not be
                // bound to the newest master token if the newest master token
                // invalidated it.
                final String userId = msgCtx.getUserId();
                final MslStore store = ctx.getMslStore();
                final UserIdToken storedUserIdToken = (userId != null) ? store.getUserIdToken(userId) : null;
                userIdToken = (storedUserIdToken != null && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
            } else {
                userIdToken = null;
            }
    
            // Set the authentication tokens.
            builder.setAuthTokens(masterToken, userIdToken);
            return builder;
        } catch (final RuntimeException e) {
            // Release the master token lock.
            releaseMasterToken(ctx, masterToken);
            throw e;
        }
    }

    /**
     * <p>Create a new message builder that will craft a new message based on
     * another message. The constructed message will have a randomly assigned
     * message ID, thus detaching it from the message being responded to, and
     * may be used as a request.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param request message header to respond to.
     * @return the message builder.
     * @throws MslCryptoException if there is an error accessing the remote
     *         entity identity.
     * @throws MslException if any of the request's user ID tokens is not bound
     *         to its master token.
     */
    private MessageBuilder buildDetachedResponse(final MslContext ctx, final MessageContext msgCtx, final MessageHeader request) throws MslCryptoException, MslException {
        // Create an idempotent response. Assign a random message ID.
        final MessageBuilder builder = messageFactory.createIdempotentResponse(ctx, request);
        builder.setNonReplayable(msgCtx.isNonReplayable());
        builder.setMessageId(MslUtils.getRandomLong(ctx));
        return builder;
    }

    /**
     * The result of building an error response.
     */
    private static class ErrorResult {
        /**
         * Create a new result with the provided request builder and message
         * context.
         *
         * @param builder
         * @param msgCtx
         */
        public ErrorResult(final MessageBuilder builder, final MessageContext msgCtx) {
            this.builder = builder;
            this.msgCtx = msgCtx;
        }

        /** The new request to send. */
        public final MessageBuilder builder;
        /** The new message context to use. */
        public final MessageContext msgCtx;
    }

    /**
     * Creates a message builder and message context appropriate for re-sending
     * the original message in response to the received error.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param sent result of original sent message.
     * @param errorHeader received error header.
     * @return the message builder and message context that should be used to
     *         re-send the original request in response to the received error
     *         or null if the error cannot be handled (i.e. should be returned
     *         to the application).
     * @throws MslException if there is an error creating the message.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to acquire the master token lock (user re-authentication only).
     */
    private ErrorResult buildErrorResponse(final MslContext ctx, final MessageContext msgCtx, final SendResult sent, final ErrorHeader errorHeader) throws MslException, InterruptedException {
        // Handle the error.
        final MessageHeader requestHeader = sent.request.getMessageHeader();
        final List<PayloadChunk> payloads = sent.request.getPayloads();
        final MslConstants.ResponseCode errorCode = errorHeader.getErrorCode();
        switch (errorCode) {
            case ENTITYDATA_REAUTH:
            case ENTITY_REAUTH:
            {
                // If the MSL context cannot provide new entity authentication
                // data then return null. This function should never return
                // null.
                try {
                    final MslContext.ReauthCode reauthCode = MslContext.ReauthCode.valueOf(errorCode);
                    if (ctx.getEntityAuthenticationData(reauthCode) == null)
                        return null;
                } catch (final IllegalArgumentException e) {
                    throw new MslInternalException("Unsupported response code mapping onto entity re-authentication codes.", e);
                }

                // Resend the request without a master token or user ID token.
                // Make sure the use the error header message ID + 1.
                final long messageId = MessageBuilder.incrementMessageId(errorHeader.getMessageId());
                final MessageContext resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, null, null, messageId);
                if (ctx.isPeerToPeer()) {
                    final MasterToken peerMasterToken = requestHeader.getPeerMasterToken();
                    final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                }
                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                return new ErrorResult(requestBuilder, resendMsgCtx);
            }
            case USERDATA_REAUTH:
            case SSOTOKEN_REJECTED:
            {
                // If the message context cannot provide user authentication
                // data then return null.
                try {
                    final MessageContext.ReauthCode reauthCode = MessageContext.ReauthCode.valueOf(errorCode);
                    if (msgCtx.getUserAuthData(reauthCode, false, true) == null)
                        return null;
                } catch (final IllegalArgumentException e) {
                    throw new MslInternalException("Unsupported response code mapping onto user re-authentication codes.", e);
                }

                // Otherwise we have now triggered the need for new user
                // authentication data. Fall through.
            }
            case USER_REAUTH:
            {
                // Grab the newest master token and its read lock.
                final MasterToken masterToken = getNewestMasterToken(ctx);

                // Resend the request without a user ID token.
                // Make sure the use the error header message ID + 1.
                final long messageId = MessageBuilder.incrementMessageId(errorHeader.getMessageId());
                final MessageContext resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, masterToken, null, messageId);
                if (ctx.isPeerToPeer()) {
                    final MasterToken peerMasterToken = requestHeader.getPeerMasterToken();
                    final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                }
                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                return new ErrorResult(requestBuilder, resendMsgCtx);
            }
            case KEYX_REQUIRED:
            {
                // This error will only be received by trusted network clients
                // and peer-to-peer entities that do not have a master token.
                // Make sure the use the error header message ID + 1.
                final long messageId = MessageBuilder.incrementMessageId(errorHeader.getMessageId());
                final MessageContext resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, null, null, messageId);
                if (ctx.isPeerToPeer()) {
                    final MasterToken peerMasterToken = requestHeader.getPeerMasterToken();
                    final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                }
                // Mark the message as renewable to make sure the response can
                // be encrypted. During renewal lock acquisition we will either
                // block until we acquire the renewal lock or receive a master
                // token.
                requestBuilder.setRenewable(true);
                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                return new ErrorResult(requestBuilder, resendMsgCtx);
            }
            case EXPIRED:
            {
                // Grab the newest master token and its read lock.
                final MasterToken masterToken = getNewestMasterToken(ctx);
                final UserIdToken userIdToken;
                if (masterToken != null) {
                    // Grab the user ID token for the message's user. It may not be bound
                    // to the newest master token if the newest master token invalidated
                    // it.
                    final String userId = msgCtx.getUserId();
                    final MslStore store = ctx.getMslStore();
                    final UserIdToken storedUserIdToken = (userId != null) ? store.getUserIdToken(userId) : null;
                    userIdToken = (storedUserIdToken != null && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                } else {
                    userIdToken = null;
                }

                // Resend the request.
                final long messageId = MessageBuilder.incrementMessageId(errorHeader.getMessageId());
                final MessageContext resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, masterToken, userIdToken, messageId);
                if (ctx.isPeerToPeer()) {
                    final MasterToken peerMasterToken = requestHeader.getPeerMasterToken();
                    final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                }
                // If the newest master token is equal to the previous
                // request's master token then mark this message as renewable.
                // During renewal lock acquisition we will either block until
                // we acquire the renewal lock or receive a master token.
                //
                // Check for a missing master token in case the remote entity
                // returned an incorrect error code.
                final MasterToken requestMasterToken = requestHeader.getMasterToken();
                if (requestMasterToken == null || requestMasterToken.equals(masterToken))
                    requestBuilder.setRenewable(true);
                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                return new ErrorResult(requestBuilder, resendMsgCtx);
            }
            case REPLAYED:
            {
                // This error will be received if the previous request's non-
                // replayable ID is not accepted by the remote entity. In this
                // situation simply try again.
                //
                // Grab the newest master token and its read lock.
                final MasterToken masterToken = getNewestMasterToken(ctx);
                final UserIdToken userIdToken;
                if (masterToken != null) {
                    // Grab the user ID token for the message's user. It may not be bound
                    // to the newest master token if the newest master token invalidated
                    // it.
                    final String userId = msgCtx.getUserId();
                    final MslStore store = ctx.getMslStore();
                    final UserIdToken storedUserIdToken = (userId != null) ? store.getUserIdToken(userId) : null;
                    userIdToken = (storedUserIdToken != null && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                } else {
                    userIdToken = null;
                }

                // Resend the request.
                final long messageId = MessageBuilder.incrementMessageId(errorHeader.getMessageId());
                final MessageContext resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, masterToken, userIdToken, messageId);
                if (ctx.isPeerToPeer()) {
                    final MasterToken peerMasterToken = requestHeader.getPeerMasterToken();
                    final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                }

                // Mark the message as replayable or not as dictated by the
                // message context.
                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                return new ErrorResult(requestBuilder, resendMsgCtx);
            }
            default:
                // Nothing to do. Return null.
                return null;
        }
    }

    /**
     * Called after successfully handling an error message to delete the old
     * invalid crypto contexts and bound service tokens associated with the
     * invalid master token or user ID token.
     *
     * @param ctx MSL context.
     * @param requestHeader initial request that generated the error.
     * @param errorHeader error response received and successfully handled.
     * @throws MslException if the user ID token is not bound to the master
     *         token. (This should not happen.)
     * @throws InterruptedException if the thread is interrupted while trying
     *         to delete the old master token.
     */
    private void cleanupContext(final MslContext ctx, final MessageHeader requestHeader, final ErrorHeader errorHeader) throws MslException, InterruptedException {
    	// The data-reauth error codes also delete tokens in case those errors
    	// are returned when a token does exist.
        switch (errorHeader.getErrorCode()) {
            case ENTITY_REAUTH:
            case ENTITYDATA_REAUTH:
            {
                // The old master token is invalid. Delete the old
                // crypto context and any bound service tokens.
                deleteMasterToken(ctx, requestHeader.getMasterToken());
                break;
            }
            case USER_REAUTH:
            case USERDATA_REAUTH:
            {
                // The old user ID token is invalid. Delete the old user ID
                // token and any bound service tokens. It is okay to stomp on
                // other requests when doing this because automatically
                // generated messages and replies to outstanding requests that
                // use the user ID token and service tokens will work fine.
                //
                // This will be a no-op if we received a new user ID token that
                // overwrote the old one.
                final MasterToken masterToken = requestHeader.getMasterToken();
                final UserIdToken userIdToken = requestHeader.getUserIdToken();
                if (masterToken != null && userIdToken != null) {
                    final MslStore store = ctx.getMslStore();
                    store.removeUserIdToken(userIdToken);
                }
                break;
            }
            default:
                // No cleanup required.
                break;
        }
    }

    /**
     * The result of sending a message.
     */
    private static class SendResult {
        /**
         * Create a new result with the provided message output stream
         * containing the cached application data (which was not sent if the
         * message was a handshake).
         *
         * @param request request message output stream.
         * @param handshake true if a handshake message was sent and the
         *        application data was not sent.
         */
        private SendResult(final MessageOutputStream request, final boolean handshake) {
            this.request = request;
            this.handshake = handshake;
        }

        /** The request message output stream. */
        public final MessageOutputStream request;
        /** True if the message was a handshake (application data was not sent). */
        public final boolean handshake;
    }

    /**
     * <p>Send a message. The message context will be used to build the message.
     * If the message will be sent then the stored master token crypto contexts
     * and service tokens will be updated just prior to sending.</p>
     *
     * <p>If the application data must be encrypted but the message does not
     * support payload encryption then a handshake message will be sent. This
     * will be indicated by the returned result.</p>
     *
     * <p>N.B. The message builder must be set renewable and non-replayable
     * before calling this method. If the application data must be delayed then
     * this specific message will be sent replayable regardless of the builder
     * non-replayable value.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param out remote entity output stream.
     * @param builder message builder.
     * @param closeDestination true if the remote entity output stream must
     *        be closed when the constructed message output stream is closed.
     * @return a result containing the sent message header and a copy of the
     *         application data.
     * @throws IOException if there is an error writing the message.
     * @throws MslMessageException if there is an error building the request.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslKeyExchangeException if there is an error generating the key
     *         request data.
     * @throws MslException if there was an error updating the service tokens
     *         or building the message header.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to delete an old master token the sent message is replacing.
     */
    private SendResult send(final MslContext ctx, final MessageContext msgCtx, final OutputStream out, final MessageBuilder builder, final boolean closeDestination) throws IOException, MslMessageException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslException, InterruptedException {
        final MasterToken masterToken = builder.getMasterToken();
        UserIdToken userIdToken = builder.getUserIdToken();
        final UserIdToken peerUserIdToken = builder.getPeerUserIdToken();

        // Ask the message context for user authentication data.
        boolean userAuthDataDelayed = false;
        final String userId = msgCtx.getUserId();
        if (userId != null) {
            // If we are not including a user ID token, the user authentication
            // data is required.
            final boolean required = (userIdToken == null);
            final UserAuthenticationData userAuthData = msgCtx.getUserAuthData(null, builder.isRenewable(), required);
            if (userAuthData != null) {
                // We can only include user authentication data if the message
                // header will be encrypted and integrity protected.
                if (builder.willEncryptHeader() && builder.willIntegrityProtectHeader())
                    builder.setUserAuthenticationData(userAuthData);

                // If the message should include user authentication data but
                // cannot at this time then we also cannot send the application
                // data as it may be user-specific. There is also no user ID token
                // otherwise the header will be encrypted.
                else
                    userAuthDataDelayed = true;
            }

            // If user authentication data is required but was not provided
            // then this message may be associated with a user but not have any
            // user authentication data. For example upon user creation.
        }

        // If there is no user ID token for the remote user then check if a
        // user ID token should be created and attached.
        if (!ctx.isPeerToPeer() && userIdToken == null ||
            ctx.isPeerToPeer() && peerUserIdToken == null)
        {
            final MslUser user = msgCtx.getUser();
            if (user != null) {
                builder.setUser(user);

                // The user ID token may have changed and we need the latest one to
                // store the service tokens below.
                userIdToken = builder.getUserIdToken();
            }
        }

        // If we have not delayed the user authentication data, and the message
        // payloads either do not need to be encrypted or can be encrypted with
        // this message, and the message payloads either do not need to be
        // integrity protected or can be integrity protected with this message,
        // and the message is either replayable or the message will be sent non-
        // replayable and has a master token, then we can write the application
        // data now.
        final boolean writeData = !userAuthDataDelayed &&
            (!msgCtx.isEncrypted() || builder.willEncryptPayloads()) &&
            (!msgCtx.isIntegrityProtected() || builder.willIntegrityProtectPayloads()) &&
            (!msgCtx.isNonReplayable() || (builder.isNonReplayable() && masterToken != null));
        final boolean handshake = !writeData;

        // Set the message handshake flag.
        builder.setHandshake(handshake);

        // If this message is renewable...
        final Set<KeyRequestData> keyRequests = new HashSet<KeyRequestData>();
        if (builder.isRenewable()) {
            // Ask for key request data if we are using entity authentication
            // data or if the master token needs renewing or if the message is
            // non-replayable.
            final Date now = ctx.getRemoteTime();
            if (masterToken == null || masterToken.isRenewable(now) || msgCtx.isNonReplayable()) {
                keyRequests.addAll(msgCtx.getKeyRequestData());
                for (final KeyRequestData keyRequest : keyRequests)
                    builder.addKeyRequestData(keyRequest);
            }
        }

        // Ask the caller to perform any final modifications to the
        // message and then build the message.
        final MessageServiceTokenBuilder serviceTokenBuilder = new MessageServiceTokenBuilder(ctx, msgCtx, builder);
        msgCtx.updateServiceTokens(serviceTokenBuilder, handshake);
        final MessageHeader requestHeader = builder.getHeader();

        // Deliver the header that will be sent to the debug context.
        final MessageDebugContext debugCtx = msgCtx.getDebugContext();
        if (debugCtx != null) debugCtx.sentHeader(requestHeader);

        // Update the stored crypto contexts just before sending the
        // message so we can receive new messages immediately after it is
        // sent.
        final KeyExchangeData keyExchangeData = builder.getKeyExchangeData();
        updateCryptoContexts(ctx, requestHeader, keyExchangeData);

        // Update the stored service tokens.
        final MasterToken tokenVerificationMasterToken = (keyExchangeData != null) ? keyExchangeData.keyResponseData.getMasterToken() : masterToken;
        final Set<ServiceToken> serviceTokens = requestHeader.getServiceTokens();
        storeServiceTokens(ctx, tokenVerificationMasterToken, userIdToken, serviceTokens);

        // We will either use the header crypto context or the key exchange
        // data crypto context in trusted network mode to process the message
        // payloads.
        final ICryptoContext payloadCryptoContext;
        if (!ctx.isPeerToPeer() && keyExchangeData != null)
            payloadCryptoContext = keyExchangeData.cryptoContext;
        else
            payloadCryptoContext = requestHeader.getCryptoContext();

        // Send the request.
        final OutputStream os = (filterFactory != null) ? filterFactory.getOutputStream(out) : out;
        final MessageOutputStream request = messageFactory.createOutputStream(ctx, os, requestHeader, payloadCryptoContext);
        request.closeDestination(closeDestination);

        // If it is okay to write the data then ask the application to write it
        // and return the real output stream. Otherwise it will be asked to do
        // so after the handshake is completed.
        if (!handshake)
            msgCtx.write(request);

        // Return the result.
        return new SendResult(request, handshake);
    }

    /**
     * <p>Receive a message.</p>
     *
     * <p>If a message is received the stored master tokens, crypto contexts,
     * user ID tokens, and service tokens will be updated.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param request message header of the previously sent message, if any,
     *        the received message is responding to. May be null.
     * @return the received message.
     * @throws IOException if there is a problem reading from the input stream.
     * @throws MslEncodingException if there is an error parsing the message.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the message payload crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token, or there is an error updating the
     *         service tokens.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token, or there is an error updating the
     *         service tokens, or the header data is missing or invalid, or the
     *         message ID is negative, or the message is not encrypted and
     *         contains user authentication data, or if the message master
     *         token is expired and the message is not renewable.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to delete an old master token the received message is replacing.
     */
    private MessageInputStream receive(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final MessageHeader request) throws IOException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslException, InterruptedException {
        // Grab the response.
        final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();
        if (request != null)
            keyRequestData.addAll(request.getKeyRequestData());
        final Map<String,ICryptoContext> cryptoContexts = msgCtx.getCryptoContexts();
        final InputStream is = (filterFactory != null) ? filterFactory.getInputStream(in) : in;
        final MessageInputStream response = messageFactory.createInputStream(ctx, is, keyRequestData, cryptoContexts);

        // Deliver the received header to the debug context.
        final MessageHeader responseHeader = response.getMessageHeader();
        final ErrorHeader errorHeader = response.getErrorHeader();
        final MessageDebugContext debugCtx = msgCtx.getDebugContext();
        if (debugCtx != null) debugCtx.receivedHeader((responseHeader != null) ? responseHeader : errorHeader);

        // Pull the response master token or entity authentication data and
        // user ID token or user authentication data to attach them to any
        // thrown exceptions.
        final MasterToken masterToken;
        final EntityAuthenticationData entityAuthData;
        final UserIdToken userIdToken;
        final UserAuthenticationData userAuthData;
        if (responseHeader != null) {
            masterToken = responseHeader.getMasterToken();
            entityAuthData = responseHeader.getEntityAuthenticationData();
            userIdToken = responseHeader.getUserIdToken();
            userAuthData = responseHeader.getUserAuthenticationData();
        } else {
            masterToken = null;
            entityAuthData = errorHeader.getEntityAuthenticationData();
            userIdToken = null;
            userAuthData = null;
        }

        try {
            // If there is a request make sure the response message ID equals
            // the request message ID + 1.
            if (request != null) {
                // Only enforce this for message headers and error headers that are
                // not entity re-authenticate or entity data re-authenticate (as in
                // those cases the remote entity is not always able to extract the
                // request message ID).
                final ResponseCode errorCode = (errorHeader != null) ? errorHeader.getErrorCode() : null;
                if (responseHeader != null ||
                    (errorCode != ResponseCode.FAIL && errorCode != ResponseCode.TRANSIENT_FAILURE && errorCode != ResponseCode.ENTITY_REAUTH && errorCode != ResponseCode.ENTITYDATA_REAUTH))
                {
                    final long responseMessageId = (responseHeader != null) ? responseHeader.getMessageId() : errorHeader.getMessageId();
                    final long expectedMessageId = MessageBuilder.incrementMessageId(request.getMessageId());
                    if (responseMessageId != expectedMessageId)
                        throw new MslMessageException(MslError.UNEXPECTED_RESPONSE_MESSAGE_ID, "expected " + expectedMessageId + "; received " + responseMessageId);
                }
            }

            // Verify expected identity if specified.
            final String expectedIdentity = msgCtx.getRemoteEntityIdentity();
            if (expectedIdentity != null) {
                // Reject if the remote entity identity is not equal to the
                // message entity authentication data identity.
                if (entityAuthData != null) {
                    final String entityAuthIdentity = entityAuthData.getIdentity();
                    if (entityAuthIdentity != null && !expectedIdentity.equals(entityAuthIdentity))
                        throw new MslMessageException(MslError.MESSAGE_SENDER_MISMATCH, "expected " + expectedIdentity + "; received " + entityAuthIdentity);
                }

                // Reject if in peer-to-peer mode and the message sender does
                // not match.
                if (ctx.isPeerToPeer()) {
                    final String sender = response.getIdentity();
                    if (sender != null && !expectedIdentity.equals(sender))
                        throw new MslMessageException(MslError.MESSAGE_SENDER_MISMATCH, "expected " + expectedIdentity + "; received " + sender);
                }
            }

            // Process the response.
            if (responseHeader != null) {
                // If there is a request update the stored crypto contexts.
                if (request != null)
                    updateCryptoContexts(ctx, request, response);

                // In trusted network mode the local tokens are the primary tokens.
                // In peer-to-peer mode they are the peer tokens. The master token
                // might be in the key response data.
                final KeyResponseData keyResponseData = responseHeader.getKeyResponseData();
                final MasterToken tokenVerificationMasterToken;
                final UserIdToken localUserIdToken;
                final Set<ServiceToken> serviceTokens;
                if (!ctx.isPeerToPeer()) {
                    tokenVerificationMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : responseHeader.getMasterToken();
                    localUserIdToken = responseHeader.getUserIdToken();
                    serviceTokens = responseHeader.getServiceTokens();
                } else {
                    tokenVerificationMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : responseHeader.getPeerMasterToken();
                    localUserIdToken = responseHeader.getPeerUserIdToken();
                    serviceTokens = responseHeader.getPeerServiceTokens();
                }

                // Save any returned user ID token if the local entity is not the
                // issuer of the user ID token.
                final String userId = msgCtx.getUserId();
                if (userId != null && localUserIdToken != null && !localUserIdToken.isVerified())
                    ctx.getMslStore().addUserIdToken(userId, localUserIdToken);

                // Update the stored service tokens.
                storeServiceTokens(ctx, tokenVerificationMasterToken, localUserIdToken, serviceTokens);
            }

            // Update the synchronized clock if we are a trusted network client
            // (there is a request) or peer-to-peer entity.
            final Date timestamp = (responseHeader != null) ? responseHeader.getTimestamp() : errorHeader.getTimestamp();
            if (timestamp != null && (request != null || ctx.isPeerToPeer()))
                ctx.updateRemoteTime(timestamp);
        } catch (final MslException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            e.setUserIdToken(userIdToken);
            e.setUserAuthenticationData(userAuthData);
            throw e;
        }

        // Return the result.
        return response;
    }

    /**
     * Indicates response expectations for a specific request.
     */
    private static enum Receive {
        /** A response is always expected. */
        ALWAYS,
        /** A response is only expected if tokens are being renewed. */
        RENEWING,
        /** A response is never expected. */
        NEVER
    }

    /**
     * The result of sending and receiving messages.
     */
    private static class SendReceiveResult extends SendResult {
        /**
         * Create a new result with the provided response and send result.
         *
         * @param response response message input stream. May be {@code null}.
         * @param sent sent message result.
         */
        public SendReceiveResult(final MessageInputStream response, final SendResult sent) {
            super(sent.request, sent.handshake);
            this.response = response;
        }

        /** The response message input stream. */
        public final MessageInputStream response;
    }

    /**
     * <p>Send the provided request and optionally receive a response from the
     * remote entity. The method will attempt to receive a response if one of
     * the following is met:
     * <ul>
     * <li>the caller indicates a response is expected</li>
     * <li>a handshake message was sent</li>
     * <li>key request data appears in the request</li>
     * <li>a renewable message with user authentication data was sent</li>
     * </ul></p>
     *
     * <p>This method is only used from trusted network clients and peer-to-
     * peer entities.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param builder request message builder.
     * @param receive indicates if a response should always be expected, should
     *        only be expected if the master token or user ID token will be
     *        renewed, or should never be expected.
     * @param closeStreams true if the remote entity input and output streams
     *        must be closed when the constructed message input and output
     *        streams are closed.
     * @param timeout renewal lock acquisition timeout in milliseconds.
     * @return the received message or {@code null} if cancelled or interrupted.
     * @throws IOException if there was an error reading or writing a
     *         message.
     * @throws MslEncodingException if there is an error parsing or encoding a
     *         message.
     * @throws MslCryptoException if there is an error encrypting/decrypting or
     *         signing/verifying a message header or creating the message
     *         payload crypto context.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable, if there is an error building the
     *         request, or if the response message ID does not equal the
     *         expected value, or the header data is missing or invalid, or the
     *         message ID is negative, or the message is not encrypted and
     *         contains user authentication data.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token, or there is an error updating the
     *         service tokens, or there was an error building the message
     *         header.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to delete an old master token the received message is replacing.
     * @throws TimeoutException if the thread timed out while trying to acquire
     *         a master token from a renewing thread.
     */
    private SendReceiveResult sendReceive(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final MessageBuilder builder, final Receive receive, final boolean closeStreams, final int timeout) throws IOException, MslEncodingException, MslCryptoException, MslEntityAuthException, MslUserAuthException, MslMessageException, MslMasterTokenException, MslKeyExchangeException, MslException, InterruptedException, TimeoutException {
        // Attempt to acquire the renewal lock.
        final BlockingQueue<MasterToken> renewalQueue = new ArrayBlockingQueue<MasterToken>(1, true);
        final boolean renewing;
        try {
            renewing = acquireRenewalLock(ctx, msgCtx, renewalQueue, builder, timeout);
        } catch (final InterruptedException e) {
            // Release the master token lock.
            releaseMasterToken(ctx, builder.getMasterToken());

            // This should only be if we were cancelled so return null.
            return null;
        } catch (final TimeoutException | RuntimeException e) {
            // Release the master token lock.
            releaseMasterToken(ctx, builder.getMasterToken());
            throw e;
        }

        // Send the request and receive the response.
        final SendResult sent;
        MessageInputStream response = null;
        try {
            // Send the request.
            builder.setRenewable(renewing);
            sent = send(ctx, msgCtx, out, builder, closeStreams);

            // Receive the response if expected, if we sent a handshake request,
            // or if we expect a response when renewing tokens and either key
            // request data was included or a master token and user
            // authentication data was included in a renewable message.
            final MessageHeader requestHeader = sent.request.getMessageHeader();
            final Set<KeyRequestData> keyRequestData = requestHeader.getKeyRequestData();
            if (receive == Receive.ALWAYS || sent.handshake ||
                (receive == Receive.RENEWING &&
                 (!keyRequestData.isEmpty() ||
                  (requestHeader.isRenewable() && requestHeader.getMasterToken() != null && requestHeader.getUserAuthenticationData() != null))))
            {
                response = receive(ctx, msgCtx, in, requestHeader);
                response.closeSource(closeStreams);

                // If we received an error response then cleanup.
                final ErrorHeader errorHeader = response.getErrorHeader();
                if (errorHeader != null)
                    cleanupContext(ctx, requestHeader, errorHeader);
            }
        } finally {
            // Release the renewal lock.
            if (renewing)
                releaseRenewalLock(ctx, renewalQueue, response);

            // Release the master token lock.
            releaseMasterToken(ctx, builder.getMasterToken());
        }

        // Return the response.
        return new SendReceiveResult(response, sent);
    }

    /**
     * <p>Attempt to acquire the renewal lock if the message will need it using
     * the given blocking queue.</p>
     *
     * <p>If anti-replay is required then this method will block until the
     * renewal lock is acquired.</p>
     *
     * <p>If the message has already been marked renewable then this method
     * will block until the renewal lock is acquired or a renewing thread
     * delivers a new master token to this builder.</p>
     *
     * <p>If encryption is required but the builder will not be able to encrypt
     * the message payloads, or if integrity protection is required but the
     * builder will not be able to integrity protect the message payloads, or
     * if the builder's master token is expired, or if there is no user ID
     * token but the message is associated with a user and the builder will not
     * be able to encrypt and integrity protect the message header, then this
     * method will block until the renewal lock is acquired or a renewing
     * thread delivers a master token to this builder.</p>
     *
     * <p>If the message is requesting tokens in response but there is no
     * master token, or there is no user ID token but the message is associated
     * with a user, then this method will block until the renewal lock is
     * acquired or a renewing thread delivers a master token to this builder
     * and a user ID token is also available if the message is associated with
     * a user.</p>
     *
     * <p>If there is no master token, or either the master token or the user
     * ID token is renewable, or there is no user ID token but the message is
     * associated with a user and the builder will be able to encrypt the
     * message header then this method will attempt to acquire the renewal
     * lock. If unable to do so, it returns null.</p>
     *
     * <p>If this method returns true, then the renewal lock must be released by
     * calling {@code releaseRenewalLock()}.</p>
     *
     * <p>This method is only used from trusted network clients and peer-to-
     * peer entities.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param queue caller's blocking queue.
     * @param builder message builder for the message to be sent.
     * @param timeout timeout in milliseconds for acquiring the renewal lock
     *        or receiving a master token.
     * @return true if the renewal lock was acquired, false if the builder's
     *         message is now capable of encryption or the renewal lock is not
     *         needed.
     * @throws InterruptedException if interrupted while waiting to acquire
     *         a master token from a renewing thread.
     * @throws TimeoutException if timed out while waiting to acquire a master
     *         token from a renewing thread.
     * @see #releaseRenewalLock(MslContext, BlockingQueue, MessageInputStream)
     */
    private boolean acquireRenewalLock(final MslContext ctx, final MessageContext msgCtx, final BlockingQueue<MasterToken> queue, final MessageBuilder builder, final long timeout) throws InterruptedException, TimeoutException {
        MasterToken masterToken = builder.getMasterToken();
        UserIdToken userIdToken = builder.getUserIdToken();
        final String userId = msgCtx.getUserId();

        // If the application data needs to be encrypted and the builder will
        // not encrypt payloads, or the application data needs to be integrity
        // protected and the builder will not integrity protect payloads, or if
        // the master token is expired, or if the message is to be sent with
        // user authentication data and the builder will not encrypt and
        // integrity protect the header, then we must either mark this message
        // as renewable to perform a handshake or get a master token from a
        // renewing thread.
        //
        // If the message has been marked renewable then we must either mark
        // this message as renewable or receive a new master token.
        //
        // If the message must be marked non-replayable and we do not have a
        // master token then we must mark this message as renewable to perform
        // a handshake or receive a new master token.
        final Date startTime = ctx.getRemoteTime();
        if ((msgCtx.isEncrypted() && !builder.willEncryptPayloads()) ||
            (msgCtx.isIntegrityProtected() && !builder.willIntegrityProtectPayloads()) ||
            builder.isRenewable() ||
            (masterToken == null && msgCtx.isNonReplayable()) ||
            (masterToken != null && masterToken.isExpired(startTime)) ||
            (userIdToken == null && userId != null && (!builder.willEncryptHeader() || !builder.willIntegrityProtectHeader())) ||
            (msgCtx.isRequestingTokens() && (masterToken == null || (userId != null && userIdToken == null))))
        {
            do {
                // We do not have a master token or this message is non-
                // replayable. Try to acquire the renewal lock on this MSL
                // context so we can send a handshake message.
                final BlockingQueue<MasterToken> ctxRenewingQueue = renewingContexts.putIfAbsent(ctx, queue);

                // If there is no one else already renewing then our queue has
                // acquired the renewal lock.
                if (ctxRenewingQueue == null)
                    return true;

                // Otherwise we need to wait for a master token from the
                // renewing request.
                final MasterToken newMasterToken = ctxRenewingQueue.poll(timeout, TimeUnit.MILLISECONDS);

                // If timed out throw an exception.
                if (newMasterToken == null)
                    throw new TimeoutException("acquireRenewalLock timed out.");

                // Put the same master token back on the renewing queue so
                // anyone else waiting can also proceed.
                ctxRenewingQueue.add(newMasterToken);

                // If the renewing request did not acquire a master token then
                // try again to acquire renewal ownership.
                if (newMasterToken == NULL_MASTER_TOKEN)
                    continue;

                // If the new master token is not equal to the previous master
                // token then release the previous master token and get the
                // newest master token.
                //
                // We cannot simply use the new master token directly since we
                // have not acquired its master token lock.
                final MasterToken previousMasterToken = masterToken;
                if (masterToken == null || !masterToken.equals(newMasterToken)) {
                    releaseMasterToken(ctx, masterToken);
                    masterToken = getNewestMasterToken(ctx);

                    // If there is no newest master token (it could have been
                    // deleted despite just being delivered to us) then try
                    // again to acquire renewal ownership.
                    if (masterToken == null)
                        continue;
                }

                // The renewing request may have acquired a new user ID token.
                // Attach it to this message if the message is associated with
                // a user and we do not already have a user ID token.
                //
                // Unless the previous master token was thrown out, any user ID
                // token should still be bound to this new master token. If the
                // master token serial number has changed then our user ID
                // token is no longer valid and the new one should be attached.
                if ((userId != null && userIdToken == null) ||
                    (userIdToken != null && !userIdToken.isBoundTo(masterToken)))
                {
                    final UserIdToken storedUserIdToken = ctx.getMslStore().getUserIdToken(userId);
                    userIdToken = (storedUserIdToken != null && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                }

                // Update the message's master token and user ID token.
                builder.setAuthTokens(masterToken, userIdToken);

                // If the new master token is still expired then try again to
                // acquire renewal ownership.
                final Date updateTime = ctx.getRemoteTime();
                if (masterToken.isExpired(updateTime))
                    continue;

                // If this message is already marked renewable and the received
                // master token is the same as the previous master token then
                // we must still attempt to acquire the renewal lock.
                if (builder.isRenewable() && masterToken.equals(previousMasterToken))
                    continue;

                // If this message is requesting tokens and is associated with
                // a user but there is no user ID token then we must still
                // attempt to acquire the renewal lock.
                if (msgCtx.isRequestingTokens() && userIdToken == null)
                    continue;

                // We may still want to renew, but it is not required. Fall
                // through.
                break;
            } while (true);
        }

        // If we do not have a master token or the master token should be
        // renewed, or we do not have a user ID token but the message is
        // associated with a user, or if the user ID token should be renewed,
        // then try to mark this message as renewable.
        final Date finalTime = ctx.getRemoteTime();
        if ((masterToken == null || masterToken.isRenewable(finalTime)) ||
            (userIdToken == null && msgCtx.getUserId() != null) ||
            (userIdToken != null && userIdToken.isRenewable(finalTime)))
        {
            // Try to acquire the renewal lock on this MSL context.
            final BlockingQueue<MasterToken> ctxRenewingQueue = renewingContexts.putIfAbsent(ctx, queue);

            // If there is no one else already renewing then our queue has
            // acquired the renewal lock.
            if (ctxRenewingQueue == null)
                return true;

            // Otherwise proceed without acquiring the lock.
            return false;
        }

        // Otherwise we do not need to acquire the renewal lock.
        return false;
    }

    /**
     * <p>Release the renewal lock.</p>
     *
     * <p>Delivers any received master token to the blocking queue. This may be
     * a null value if an error message was received or if the received message
     * does not contain a master token for the local entity.</p>
     *
     * <p>If no message was received a null master token will be delivered.</p>
     *
     * <p>This method is only used from trusted network clients and peer-to-
     * peer entities.</p>
     *
     * @param ctx MSL context.
     * @param queue caller's blocking queue.
     * @param message received message. May be null if no message was received.
     */
    private void releaseRenewalLock(final MslContext ctx, final BlockingQueue<MasterToken> queue, final MessageInputStream message) {
        // Sanity check.
        if (renewingContexts.get(ctx) != queue)
            throw new IllegalStateException("Attempt to release renewal lock that is not owned by this queue.");

        // If no message was received then deliver a null master token, release
        // the lock, and return immediately.
        if (message == null) {
            queue.add(NULL_MASTER_TOKEN);
            renewingContexts.remove(ctx);
            return;
        }

        // If we received an error message then deliver a null master token,
        // release the lock, and return immediately.
        final MessageHeader messageHeader = message.getMessageHeader();
        if (messageHeader == null) {
            queue.add(NULL_MASTER_TOKEN);
            renewingContexts.remove(ctx);
            return;
        }

        // If we performed key exchange then the renewed master token should be
        // delivered.
        final KeyResponseData keyResponseData = messageHeader.getKeyResponseData();
        if (keyResponseData != null) {
            queue.add(keyResponseData.getMasterToken());
        }

        // In trusted network mode deliver the header master token. This may be
        // null.
        else if (!ctx.isPeerToPeer()) {
            final MasterToken masterToken = messageHeader.getMasterToken();
            if (masterToken != null)
                queue.add(masterToken);
            else
                queue.add(NULL_MASTER_TOKEN);
        }

        // In peer-to-peer mode deliver the peer master token. This may be
        // null.
        else {
            final MasterToken masterToken = messageHeader.getPeerMasterToken();
            if (masterToken != null)
                queue.add(masterToken);
            else
                queue.add(NULL_MASTER_TOKEN);
        }

        // Release the lock.
        renewingContexts.remove(ctx);
    }

    /**
     * Send an error response over the provided output stream.
     *
     * @param ctx MSL context.
     * @param debugCtx message debug context.
     * @param requestHeader message the error is being sent in response to. May
     *        be {@code null}.
     * @param messageId request message ID. May be {@code null}.
     * @param error the MSL error.
     * @param userMessage localized user-consumable error message. May be
     *        {@code null}.
     * @param out message output stream.
     * @throws MslEncodingException if there is an error encoding the message.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data was
     *         returned by the MSL context.
     * @throws IOException if there is an error sending the error response.
     */
    private void sendError(final MslContext ctx, final MessageDebugContext debugCtx, final MessageHeader requestHeader, final Long messageId, final MslError error, final String userMessage, final OutputStream out) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslMessageException, IOException {
        // Create error header.
        final ErrorHeader errorHeader = messageFactory.createErrorResponse(ctx, messageId, error, userMessage);

        if (debugCtx != null) debugCtx.sentHeader(errorHeader);

        // Determine encoder format.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final MessageCapabilities capabilities = (requestHeader != null)
            ? MessageCapabilities.intersection(ctx.getMessageCapabilities(), requestHeader.getMessageCapabilities())
            : ctx.getMessageCapabilities();
        final Set<MslEncoderFormat> formats = (capabilities != null) ? capabilities.getEncoderFormats() : null;
        final MslEncoderFormat format = encoder.getPreferredFormat(formats);

        // Send error response.
        final MessageOutputStream response = messageFactory.createOutputStream(ctx, out, errorHeader, format);
        response.close();
    }

    /**
     * <p>This service receives a request from a remote entity, and either
     * returns the received message or automatically generates a reply (and
     * returns null).</p>
     *
     * <p>This class will only be used by trusted-network servers and peer-to-
     * peer servers.</p>
     */
    private class ReceiveService implements Callable<MessageInputStream> {
        /** MSL context. */
        private final MslContext ctx;
        /** Message context. */
        private final MessageContext msgCtx;
        /** Remote entity input stream. */
        private final InputStream in;
        /** Remote entity output stream. */
        private final OutputStream out;
        /** Read timeout in milliseconds. */
        private final int timeout;

        /**
         * Create a new message receive service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param timeout renewal lock aquisition timeout in milliseconds.
         */
        public ReceiveService(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final int timeout) {
            this.ctx = ctx;
            this.msgCtx = msgCtx;
            this.in = in;
            this.out = out;
            this.timeout = timeout;
        }

        /**
         * @return the received message or {@code null} if cancelled.
         * @throws MslException if there was an error with the received message
         *         or an error creating an automatically generated response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error reading or writing a
         *         message.
         * @throws TimeoutException if the thread timed out while trying to
         *         acquire the renewal lock.
         * @see java.util.concurrent.Callable#call()
         */
        @Override
        public MessageInputStream call() throws MslException, MslErrorResponseException, IOException, TimeoutException {
            final MessageDebugContext debugCtx = msgCtx.getDebugContext();

            // Read the incoming message.
            final MessageInputStream request;
            try {
                request = receive(ctx, msgCtx, in, null);
            } catch (final InterruptedException e) {
                // We were cancelled so return null.
                return null;
            } catch (final MslException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Try to send an error response.
                try {
                    final MslError error = e.getError();
                    final String userMessage = messageRegistry.getUserMessage(error, null);
                    sendError(ctx, debugCtx, null, e.getMessageId(), error, userMessage, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error receiving the message header.", rt, e);
                }
                throw e;
            } catch (final IOException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Maybe we can send an error response.
                try {
                    sendError(ctx, debugCtx, null, null, MslError.MSL_COMMS_FAILURE, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error receiving the message header.", rt, e);
                }
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return null.
                if (cancelled(t)) return null;

                // Try to send an error response.
                try {
                    sendError(ctx, debugCtx, null, null, MslError.INTERNAL_EXCEPTION, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error receiving the message header.", rt, t);
                }
                throw new MslInternalException("Error receiving the message header.", t);
            }

            // Return error headers to the caller.
            final MessageHeader requestHeader = request.getMessageHeader();
            if (requestHeader == null)
                return request;

            // If the message is not a handshake message deliver it to the
            // caller.
            try {
                if (!request.isHandshake())
                    return request;
            } catch (final MslException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Try to send an error response.
                try {
                    final MslError error = e.getError();
                    final String userMessage = messageRegistry.getUserMessage(error, null);
                    sendError(ctx, debugCtx, requestHeader, e.getMessageId(), error, userMessage, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error peeking into the message payloads.", rt, e);
                }
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return null.
                if (cancelled(t)) return null;

                // Try to send an error response.
                try {
                    final Long requestMessageId = requestHeader.getMessageId();
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.INTERNAL_EXCEPTION, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error peeking into the message payloads.", rt, t);
                }
                throw new MslInternalException("Error peeking into the message payloads.", t);
            }

            // This is a handshake request so automatically return a response.
            final MessageBuilder responseBuilder;
            try {
                // In peer-to-peer mode this will acquire the local entity's
                // master token read lock.
                responseBuilder = buildResponse(ctx, msgCtx, request.getMessageHeader());
            } catch (final InterruptedException e) {
                // We were cancelled so return null.
                return null;
            } catch (final MslException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Try to send an error response.
                try {
                    final MslError error = e.getError();
                    final MessageCapabilities caps = requestHeader.getMessageCapabilities();
                    final List<String> languages = (caps != null) ? caps.getLanguages() : null;
                    final String userMessage = messageRegistry.getUserMessage(error, languages);
                    sendError(ctx, debugCtx, requestHeader, e.getMessageId(), error, userMessage, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error creating an automatic handshake response.", rt, e);
                }
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return null.
                if (cancelled(t)) return null;

                // Try to send an error response.
                try {
                    final Long requestMessageId = requestHeader.getMessageId();
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.INTERNAL_EXCEPTION, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error creating an automatic handshake response.", rt, t);
                }
                throw new MslInternalException("Error creating an automatic handshake response.", t);
            } finally {
                try { request.close(); } catch (final IOException e) {}
            }

            // If we are in trusted services mode then no additional data is
            // expected. Send the handshake response and return null. The next
            // message from the remote entity can be retrieved by another call
            // to receive.
            final MessageContext keyxMsgCtx = new KeyxResponseMessageContext(msgCtx);
            if (!ctx.isPeerToPeer()) {
                try {
                    responseBuilder.setRenewable(false);
                    send(ctx, keyxMsgCtx, out, responseBuilder, false);
                    return null;
                } catch (final InterruptedException e) {
                    // We were cancelled so return null.
                    return null;
                } catch (final MslException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;

                    // Try to send an error response.
                    try {
                        final Long requestMessageId = requestHeader.getMessageId();
                        final MslError error = e.getError();
                        final MessageCapabilities caps = requestHeader.getMessageCapabilities();
                        final List<String> languages = (caps != null) ? caps.getLanguages() : null;
                        final String userMessage = messageRegistry.getUserMessage(error, languages);
                        sendError(ctx, debugCtx, requestHeader, requestMessageId, error, userMessage, out);
                    } catch (final Throwable rt) {
                        // If we were cancelled then return null.
                        if (cancelled(rt)) return null;

                        throw new MslErrorResponseException("Error sending an automatic handshake response.", rt, e);
                    }
                    throw e;
                } catch (final IOException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;

                    // Maybe we can send an error response.
                    try {
                        final Long requestMessageId = requestHeader.getMessageId();
                        sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.MSL_COMMS_FAILURE, null, out);
                    } catch (final Throwable rt) {
                        // If we were cancelled then return null.
                        if (cancelled(rt)) return null;

                        throw new MslErrorResponseException("Error sending an automatic handshake response.", rt, e);
                    }
                    throw e;
                } catch (final Throwable t) {
                    // If we were cancelled then return null.
                    if (cancelled(t)) return null;

                    // Try to send an error response.
                    try {
                        final Long requestMessageId = requestHeader.getMessageId();
                        sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.INTERNAL_EXCEPTION, null, out);
                    } catch (final Throwable rt) {
                        // If we were cancelled then return null.
                        if (cancelled(rt)) return null;

                        throw new MslErrorResponseException("Error sending an automatic handshake response.", rt, t);
                    }
                    throw new MslInternalException("Error sending an automatic handshake response.", t);
                }
            }

            // Since we are in peer-to-peer mode our response may contain key
            // request data. Therefore we may receive another request after the
            // remote entity's key exchange completes containing peer
            // authentication tokens for the local entity.
            //
            // The master token lock acquired from buildResponse() will be
            // released when the service executes.
            //
            // We have received one message.
            final RequestService service = new RequestService(ctx, keyxMsgCtx, in, out, responseBuilder, timeout, 1);
            final MslChannel channel = service.call();

            // The MSL channel message output stream can be discarded since it
            // only contained a handshake response.
            if (channel != null)
                return channel.input;
            return null;
        }
    }

    /**
     * <p>This service sends a response to the remote entity.</p>
     *
     * <p>This class will only be used trusted network servers and peer-to-peer
     * servers.</p>
     */
    private class RespondService implements Callable<MslChannel> {
        /** MSL context. */
        protected final MslContext ctx;
        /** Message context. */
        protected final MessageContext msgCtx;
        /** Request message input stream. */
        protected final MessageInputStream request;
        /** Remote entity input stream. */
        protected final InputStream in;
        /** Remote entity output stream. */
        protected final OutputStream out;
        /** Read timeout in milliseconds. */
        protected final int timeout;

        /**
         * Create a new message respond service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param request request message input stream.
         * @param timeout renewal lock acquisition timeout in milliseconds.
         */
        public RespondService(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final MessageInputStream request, final int timeout) {
            if (request.getErrorHeader() != null)
                throw new MslInternalException("Respond service created for an error message.");
            this.ctx = ctx;
            this.msgCtx = msgCtx;
            this.in = in;
            this.out = out;
            this.request = request;
            this.timeout = timeout;
        }

        /**
         * Send the response as a trusted network server.
         *
         * @param builder response message builder.
         * @param msgCount number of messages that have already been sent or
         *        received.
         * @return the MSL channel if the response was sent or null if
         *         cancelled, interrupted, if the response could not be sent
         *         encrypted or integrity protected when required, a user could
         *         not be attached due to lack of a master token, or if the
         *         maximum message count is hit.
         * @throws MslException if there was an error creating the response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         * @throws InterruptedException if the thread is interrupted while
         *         trying to delete an old master token the sent message is
         *         replacing.
         */
        protected MslChannel trustedNetworkExecute(final MessageBuilder builder, final int msgCount) throws MslException, MslErrorResponseException, IOException, InterruptedException {
            try {
                final MessageDebugContext debugCtx = msgCtx.getDebugContext();
                final MessageHeader requestHeader = request.getMessageHeader();

                // Do nothing if we cannot send one more message.
                if (msgCount + 1 > MslConstants.MAX_MESSAGES)
                    return null;

                // If the response must be encrypted or integrity protected but
                // cannot then send an error requesting it. The client must re-
                // initiate the transaction.
                final MslError securityRequired;
                if (msgCtx.isIntegrityProtected() && !builder.willIntegrityProtectPayloads())
                    securityRequired = MslError.RESPONSE_REQUIRES_INTEGRITY_PROTECTION;
                else if (msgCtx.isEncrypted() && !builder.willEncryptPayloads())
                    securityRequired = MslError.RESPONSE_REQUIRES_ENCRYPTION;
                else
                    securityRequired = null;
                if (securityRequired != null) {
                    // Try to send an error response.
                    try {
                        final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                        sendError(ctx, debugCtx, requestHeader, requestMessageId, securityRequired, null, out);
                        return null;
                    } catch (final Throwable rt) {
                        // If we were cancelled then return null.
                        if (cancelled(rt)) return null;

                        throw new MslErrorResponseException("Response requires encryption or integrity protection but cannot be protected: " + securityRequired, rt, null);
                    }
                }

                // If the response wishes to attach a user ID token but there is no
                // master token then send an error requesting the master token. The
                // client must re-initiate the transaction.
                if (msgCtx.getUser() != null && builder.getMasterToken() == null && builder.getKeyExchangeData() == null) {
                    // Try to send an error response.
                    try {
                        final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                        sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.RESPONSE_REQUIRES_MASTERTOKEN, null, out);
                        return null;
                    } catch (final Throwable rt) {
                        // If we were cancelled then return null.
                        if (cancelled(rt)) return null;

                        throw new MslErrorResponseException("Response wishes to attach a user ID token but there is no master token.", rt, null);
                    }
                }

                // Otherwise simply send the response.
                builder.setRenewable(false);
                final SendResult result = send(ctx, msgCtx, out, builder, false);
                return new MslChannel(request, result.request);
            } finally {
                // Release the master token lock.
                releaseMasterToken(ctx, builder.getMasterToken());
            }
        }

        /**
         * Send the response as a peer-to-peer entity.
         *
         * @param msgCtx message context.
         * @param builder response message builder.
         * @param msgCount number of messages sent or received so far.
         * @return a MSL channel if the response was sent or null if cancelled,
         *         interrupted, or if the response could not be sent encrypted
         *         or integrity protected when required, a user could not be
         *         attached due to lack of a master token, or if the maximum
         *         message count is hit.
         * @throws MslException if there was an error creating or processing a
         *         message.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         * @throws InterruptedException if the thread is interrupted while
         *         trying to acquire the master token lock.
         * @throws TimeoutException if the thread timed out while trying to
         *         acquire the renewal lock.
         */
        protected MslChannel peerToPeerExecute(final MessageContext msgCtx, final MessageBuilder builder, int msgCount) throws MslException, IOException, InterruptedException, MslErrorResponseException, TimeoutException {
            final MessageDebugContext debugCtx = msgCtx.getDebugContext();
            final MessageHeader requestHeader = request.getMessageHeader();

            // Do nothing if we cannot send and receive two more messages.
            //
            // Make sure to release the master token lock.
            if (msgCount + 2 > MslConstants.MAX_MESSAGES) {
                releaseMasterToken(ctx, builder.getMasterToken());
                return null;
            }

            // If the response wishes to attach a user ID token but there is no
            // master token then send an error requesting the master token. The
            // client must re-initiate the transaction.
            if (msgCtx.getUser() != null && builder.getPeerMasterToken() == null && builder.getKeyExchangeData() == null) {
                // Release the master token lock and try to send an error
                // response.
                releaseMasterToken(ctx, builder.getMasterToken());
                try {
                    final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.RESPONSE_REQUIRES_MASTERTOKEN, null, out);
                    return null;
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Response wishes to attach a user ID token but there is no master token.", rt, null);
                }
            }

            // Send the response. A reply is not expected, but may be received.
            // This adds two to our message count.
            //
            // This will release the master token lock.
            final SendReceiveResult result = sendReceive(ctx, msgCtx, in, out, builder, Receive.RENEWING, false, timeout);
            final MessageInputStream response = result.response;
            msgCount += 2;

            // If we did not receive a response then we're done. Return the
            // original message input stream and the new message output stream.
            if (response == null)
                return new MslChannel(request, result.request);

            // If the response is an error see if we can handle the error and
            // retry.
            final MessageHeader responseHeader = response.getMessageHeader();
            if (responseHeader == null) {
                // Close the response. We have everything we need.
                try {
                    response.close();
                } catch (final Throwable t) {
                    // If we were cancelled then return null.
                    if (cancelled(t)) return null;
                    // Otherwise we don't care about an exception on close.
                }

                // Build the error response. This will acquire the master token
                // lock.
                final ErrorHeader errorHeader = response.getErrorHeader();
                final ErrorResult errMsg = buildErrorResponse(ctx, msgCtx, result, errorHeader);

                // If there is no error response then return the error.
                if (errMsg == null)
                    return null;

                // Send the error response. Recursively execute this because it
                // may take multiple messages to succeed with sending the
                // response.
                //
                // The master token lock will be released by the recursive call
                // to peerToPeerExecute().
                final MessageBuilder requestBuilder = errMsg.builder;
                final MessageContext resendMsgCtx = errMsg.msgCtx;
                return peerToPeerExecute(resendMsgCtx, requestBuilder, msgCount);
            }

            // If we performed a handshake then re-send the message over the
            // same connection so this time the application can send its data.
            if (result.handshake) {
                // Close the response as we are discarding it.
                try {
                    response.close();
                } catch (final Throwable t) {
                    // If we were cancelled then return null.
                    if (cancelled(t)) return null;
                    // Otherwise we don't care about an exception on close.
                }

                // This will acquire the local entity's master token read lock.
                // The master token lock will be released by the recursive call
                // to peerToPeerExecute().
                final MessageContext resendMsgCtx = new ResendMessageContext(null, msgCtx);
                final MessageBuilder requestBuilder = buildResponse(ctx, resendMsgCtx, responseHeader);
                return peerToPeerExecute(resendMsgCtx, requestBuilder, msgCount);
            }

            // Otherwise we did send our application data (which may have been
            // zero-length) so we do not need to re-send our message. Return
            // the new message input stream and the new message output stream.
            return new MslChannel(result.response, result.request);
        }

        /**
         * @return a {@link MslChannel} on success or {@code null} if cancelled,
         *         interrupted, if an error response was received (peer-to-peer
         *         mode only), if the response could not be sent encrypted or
         *         integrity protected when required (trusted network-mode
         *         only), or if the maximum number of messages is hit.
         * @throws MslException if there was an error creating the response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         * @see java.util.concurrent.Callable#call()
         */
        @Override
        public MslChannel call() throws MslException, MslErrorResponseException, IOException {
            final MessageDebugContext debugCtx = msgCtx.getDebugContext();

            final MessageHeader requestHeader = request.getMessageHeader();
            final MessageBuilder builder;
            try {
                // In peer-to-peer mode this will acquire the local entity's
                // master token read lock.
                builder = buildResponse(ctx, msgCtx, requestHeader);
            } catch (final InterruptedException e) {
                // We were cancelled so return null.
                return null;
            } catch (final MslException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                try {
                    final MslError error = e.getError();
                    final MessageCapabilities caps = requestHeader.getMessageCapabilities();
                    final List<String> languages = (caps != null) ? caps.getLanguages() : null;
                    final String userMessage = messageRegistry.getUserMessage(error, languages);
                    sendError(ctx, debugCtx, requestHeader, e.getMessageId(), error, userMessage, out);
                } catch (final Throwable rt) {
                    throw new MslErrorResponseException("Error building the response.", rt, e);
                }
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return null.
                if (cancelled(t)) return null;

                try {
                    sendError(ctx, debugCtx, requestHeader, null, MslError.INTERNAL_EXCEPTION, null, out);
                } catch (final Throwable rt) {
                    throw new MslErrorResponseException("Error building the response.", rt, t);
                }
                throw new MslInternalException("Error building the response.", t);
            }

            // At most three messages would have been involved in the original
            // receive.
            try {
                // Send the response. This will release the master token lock.
                final MslChannel channel;
                if (!ctx.isPeerToPeer())
                    channel = trustedNetworkExecute(builder, 3);
                else
                    channel = peerToPeerExecute(msgCtx, builder, 3);

                // Clear any cached payloads.
                if (channel != null)
                    channel.output.stopCaching();

                // Return the established channel.
                return channel;
            } catch (final InterruptedException e) {
                // We were cancelled so return null.
                return null;
            } catch (final IOException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Maybe we can send an error response.
                try {
                    final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.MSL_COMMS_FAILURE, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error sending the response.", rt, e);
                }
                throw e;
            } catch (final MslException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Maybe we can send an error response.
                try {
                    final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    final MslError error = e.getError();
                    final MessageCapabilities caps = requestHeader.getMessageCapabilities();
                    final List<String> languages = (caps != null) ? caps.getLanguages() : null;
                    final String userMessage = messageRegistry.getUserMessage(error, languages);
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, error, userMessage, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error sending the response.", rt, e);
                }
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return null.
                if (cancelled(t)) return null;

                // Maybe we can send an error response.
                try {
                    final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.INTERNAL_EXCEPTION, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error sending the response.", rt, t);
                }
                throw new MslInternalException("Error sending the response.", t);
            }
        }
    }

    /**
     * <p>This service sends an error response to the remote entity.</p>
     *
     * <p>This class will only be used trusted network servers and peer-to-peer
     * entities.</p>
     */
    private class ErrorService implements Callable<Boolean> {
        /** MSL context. */
        private final MslContext ctx;
        /** Message context. */
        private final MessageContext msgCtx;
        /** Application error. */
        private final ApplicationError appError;
        /** Request message input stream. */
        private final MessageInputStream request;
        /** Remote entity output stream. */
        private final OutputStream out;

        /**
         * Create a new error service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param err the application error.
         * @param out remote entity output stream.
         * @param request request message input stream.
         */
        public ErrorService(final MslContext ctx, final MessageContext msgCtx, final ApplicationError err, final OutputStream out, final MessageInputStream request) {
            if (request.getErrorHeader() != null)
                throw new MslInternalException("Error service created for an error message.");
            this.ctx = ctx;
            this.msgCtx = msgCtx;
            this.appError = err;
            this.out = out;
            this.request = request;
        }

        /**
         * @return true on success or false if cancelled or interrupted.
         * @throws MslException if there was an error creating the response.
         * @throws IOException if there was an error writing the message.
         * @see java.util.concurrent.Callable#call()
         */
        @Override
        public Boolean call() throws MslException {
            final MessageDebugContext debugCtx = msgCtx.getDebugContext();
            final MessageHeader header = request.getMessageHeader();

            try {
                // Identify the correct MSL error.
                final MslError error;
                switch (appError) {
                    case ENTITY_REJECTED:
                        error = (header.getMasterToken() != null)
                            ? MslError.MASTERTOKEN_REJECTED_BY_APP
                            : MslError.ENTITY_REJECTED_BY_APP;
                        break;
                    case USER_REJECTED:
                        error = (header.getUserIdToken() != null)
                            ? MslError.USERIDTOKEN_REJECTED_BY_APP
                            : MslError.USER_REJECTED_BY_APP;
                        break;
                    default:
                        throw new MslInternalException("Unhandled application error " + appError + ".");
                }

                // Build and send the error response.
                final MessageCapabilities caps = header.getMessageCapabilities();
                final List<String> languages = (caps != null) ? caps.getLanguages() : null;
                final String userMessage = messageRegistry.getUserMessage(error, languages);
                sendError(ctx, debugCtx, header, header.getMessageId(), error, userMessage, out);

                // Success.
                return Boolean.TRUE;
            } catch (final MslException e) {
                // If we were cancelled then return false.
                if (cancelled(e)) return false;

                // We failed to return an error response. Deliver the exception
                // to the application.
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return false.
                if (cancelled(t)) return false;

                // An unexpected exception occurred.
                throw new MslInternalException("Error building the error response.", t);
            }
        }
    }

    /**
     * <p>This service sends a request to the remote entity and returns the
     * response.</p>
     *
     * <p>This class will only be used by trusted network clients, peer-to-peer
     * clients, and peer-to-peer servers.</p>
     */
    private class RequestService implements Callable<MslChannel> {
        /** MSL context. */
        private final MslContext ctx;
        /** Message context. */
        private final MessageContext msgCtx;
        /** Remote entity URL. */
        private final Url remoteEntity;
        /** Remote entity input stream. */
        private InputStream in;
        /** Remote entity output stream. */
        private OutputStream out;
        /** True if we opened the streams. */
        private boolean openedStreams;
        /** Request message builder. */
        private MessageBuilder builder;
        /** Response expectation. */
        private final Receive expectResponse;
        /** Connect and read timeout in milliseconds. */
        private final int timeout;
        /** Number of messages sent or received so far. */
        private final int msgCount;

        /** True if the maximum message count is hit. */
        private boolean maxMessagesHit = false;

        /**
         * Create a new message request service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param remoteEntity remote entity URL.
         * @param expectResponse response expectation.
         * @param timeout connect, read, and renewal lock acquisition timeout
         *        in milliseconds.
         */
        public RequestService(final MslContext ctx, final MessageContext msgCtx, final Url remoteEntity, final Receive expectResponse, final int timeout) {
            this.ctx = ctx;
            this.msgCtx = msgCtx;
            this.remoteEntity = remoteEntity;
            this.in = null;
            this.out = null;
            this.openedStreams = false;
            this.builder = null;
            this.expectResponse = expectResponse;
            this.timeout = timeout;
            this.msgCount = 0;
        }

        /**
         * Create a new message request service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param expectResponse response expectation.
         * @param timeout read and renewal lock acquisition timeout in
         *        milliseconds.
         */
        public RequestService(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final Receive expectResponse, final int timeout) {
            this.ctx = ctx;
            this.msgCtx = msgCtx;
            this.remoteEntity = null;
            this.in = in;
            this.out = out;
            this.openedStreams = false;
            this.builder = null;
            this.expectResponse = expectResponse;
            this.timeout = timeout;
            this.msgCount = 0;
        }

        /**
         * Create a new message request service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param remoteEntity remote entity URL.
         * @param builder request message builder.
         * @param expectResponse response expectation.
         * @param timeout connect, read, and renewal lock acquisition timeout
         *        in milliseconds.
         * @param msgCount number of messages that have already been sent or
         *        received.
         */
        private RequestService(final MslContext ctx, final MessageContext msgCtx, final Url remoteEntity, final MessageBuilder builder, final Receive expectResponse, final int timeout, final int msgCount) {
            this.ctx = ctx;
            this.msgCtx = msgCtx;
            this.remoteEntity = remoteEntity;
            this.in = null;
            this.out = null;
            this.openedStreams = false;
            this.builder = builder;
            this.expectResponse = expectResponse;
            this.timeout = timeout;
            this.msgCount = msgCount;
        }

        /**
         * Create a new message request service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param builder request message builder.
         * @param timeout renewal lock acquisition timeout in milliseconds.
         * @param msgCount number of messages that have already been sent or
         *        received.
         */
        public RequestService(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final MessageBuilder builder, final int timeout, final int msgCount) {
            this.ctx = ctx;
            this.msgCtx = msgCtx;
            this.remoteEntity = null;
            this.in = in;
            this.out = out;
            this.openedStreams = false;
            this.builder = builder;
            this.expectResponse = Receive.ALWAYS;
            this.timeout = timeout;
            this.msgCount = msgCount;
        }

        /**
         * <p>Send the provided request and receive a response from the remote
         * entity. Any necessary handshake messages will be sent.</p>
         *
         * <p>If an error was received and cannot be handled the returned MSL
         * channel will have {@code null} for its message output stream.</p>
         *
         * @param msgCtx message context.
         * @param builder request message builder.
         * @param timeout renewal lock acquisition timeout in milliseconds.
         * @param msgCount number of messages sent or received so far.
         * @return the established MSL channel or {@code null} if cancelled or
         *         if the maximum message count is hit.
         * @throws MslException if there was an error creating or processing
         *         a message.
         * @throws IOException if there was an error reading or writing a
         *         message.
         * @throws InterruptedException if the thread is interrupted while
         *         trying to acquire a master token's read lock.
         * @throws TimeoutException if the thread timed out while trying to
         *         acquire the renewal lock.
         */
        private MslChannel execute(final MessageContext msgCtx, final MessageBuilder builder, final int timeout, int msgCount) throws MslException, IOException, InterruptedException, TimeoutException {
            // Do not do anything if cannot send and receive two more messages.
            //
            // Make sure to release the master token lock.
            if (msgCount + 2 > MslConstants.MAX_MESSAGES) {
                releaseMasterToken(ctx, builder.getMasterToken());
                maxMessagesHit = true;
                return null;
            }

            // Send the request and receive the response. This adds two to our
            // message count.
            //
            // This will release the master token lock.
            final SendReceiveResult result = sendReceive(ctx, msgCtx, in, out, builder, expectResponse, openedStreams, timeout);
            final MessageOutputStream request = result.request;
            final MessageInputStream response = result.response;
            msgCount += 2;

            // If we did not receive a response then we're done. Return the
            // new message output stream.
            if (response == null)
                return new MslChannel(response, request);

            // If the response is an error see if we can handle the error and
            // retry.
            final MessageHeader responseHeader = response.getMessageHeader();
            if (responseHeader == null) {
                // Close the request and response. The response is an error and
                // the request is not usable.
                try {
                    request.close();
                } catch (final IOException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;
                    // Otherwise we don't care about an I/O exception on close.
                }
                try {
                    response.close();
                } catch (final IOException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;
                    // Otherwise we don't care about an I/O exception on close.
                }

                // Build the error response. This will acquire the master token
                // lock.
                final ErrorHeader errorHeader = response.getErrorHeader();
                final ErrorResult errMsg = buildErrorResponse(ctx, msgCtx, result, errorHeader);

                // If there is no error response then return the error.
                if (errMsg == null)
                    return new MslChannel(response, null);

                // In trusted network mode send the response in a new request.
                // In peer-to-peer mode reuse the connection.
                final MslChannel newChannel;
                final MessageBuilder requestBuilder = errMsg.builder;
                final MessageContext resendMsgCtx = errMsg.msgCtx;
                if (!ctx.isPeerToPeer()) {
                    // The master token lock acquired from buildErrorResponse()
                    // will be released when the service executes.
                    final RequestService service = new RequestService(ctx, resendMsgCtx, remoteEntity, requestBuilder, expectResponse, timeout, msgCount);
                    newChannel = service.call();
                    maxMessagesHit = service.maxMessagesHit;
                } else {
                    // Send the error response. Recursively execute this
                    // because it may take multiple messages to succeed with
                    // sending the request.
                    //
                    // The master token lock will be released by the recursive
                    // call to execute().
                    newChannel = execute(resendMsgCtx, requestBuilder, timeout, msgCount);
                }

                // If the maximum message count was hit or if there is no new
                // response then return the original error response.
                if (maxMessagesHit || (newChannel != null && newChannel.input == null))
                    return new MslChannel(response, null);

                // Return the new channel, which may contain an error or be
                // null if cancelled or interrupted.
                return newChannel;
            }

            // If we are in trusted network mode...
            if (!ctx.isPeerToPeer()) {
                // If we did not perform a handshake then we're done. Deliver
                // the response.
                if (!result.handshake)
                    return new MslChannel(response, request);

                // We did perform a handshake. Re-send the message over a new
                // connection to allow the application to send its data.
                //
                // Close the request and response. The response will be
                // discarded and we will be issuing a new request.
                try {
                    request.close();
                } catch (final IOException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;
                    // Otherwise we don't care about an I/O exception on close.
                }
                try {
                    response.close();
                } catch (final IOException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;
                    // Otherwise we don't care about an I/O exception on close.
                }

                // The master token lock acquired from buildResponse() will be
                // released when the service executes.
                final MessageContext resendMsgCtx = new ResendMessageContext(null, msgCtx);
                final MessageBuilder requestBuilder = buildResponse(ctx, msgCtx, responseHeader);
                final RequestService service = new RequestService(ctx, resendMsgCtx, remoteEntity, requestBuilder, expectResponse, timeout, msgCount);
                return service.call();
            }

            // We are in peer-to-peer mode...
            //
            // If we did perform a handshake. Re-send the message over the same
            // connection to allow the application to send its data. This may
            // also return key response data.
            if (result.handshake) {
                // Close the request and response. The response will be
                // discarded and we will be issuing a new request.
                try {
                    request.close();
                } catch (final IOException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;
                    // Otherwise we don't care about an I/O exception on close.
                }
                try {
                    response.close();
                } catch (final IOException e) {
                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;
                    // Otherwise we don't care about an I/O exception on close.
                }

                // Now resend.
                //
                // The master token lock acquired from buildResponse() will be
                // released by the recursive call to execute().
                final MessageContext resendMsgCtx = new ResendMessageContext(null, msgCtx);
                final MessageBuilder requestBuilder = buildResponse(ctx, msgCtx, responseHeader);
                return execute(resendMsgCtx, requestBuilder, timeout, msgCount);
            }

            // Otherwise we did send our application data (which may have been
            // zero-length) so we do not need to re-send our message.
            //
            // If the response contains key request data, or is renewable and
            // contains a master token and user authentication data, then we
            // need to return a response to perform key exchange and/or provide
            // a user ID token.
            final Set<KeyRequestData> responseKeyxData = responseHeader.getKeyRequestData();
            if (!responseKeyxData.isEmpty() ||
                (responseHeader.isRenewable() && responseHeader.getMasterToken() != null && responseHeader.getUserAuthenticationData() != null))
            {
                // Build the response. This will acquire the master token lock.
                final MessageContext keyxMsgCtx = new KeyxResponseMessageContext(msgCtx);
                final MessageBuilder keyxBuilder = buildResponse(ctx, keyxMsgCtx, responseHeader);

                // We should release the master token lock when finished, but
                // there is one case where we should not.
                boolean releaseLock = true;
                try {
                    // If the response is not a handshake message then we do not
                    // expect a reply.
                    if (!response.isHandshake()) {
                        // Close the request as we are issuing a new request.
                        try {
                            request.close();
                        } catch (final IOException e) {
                            // If we were cancelled then return null.
                            if (cancelled(e)) return null;
                            // Otherwise we don't care about an I/O exception on close.
                        }

                        // The remote entity is expecting a response. We need
                        // to send it even if this exceeds the maximum number of
                        // messages. We're guaranteed to stop sending more
                        // messages after this response.
                        //
                        // Return the original message input stream and the new
                        // message output stream to the caller.
                        keyxBuilder.setRenewable(false);
                        final SendResult newResult = send(ctx, keyxMsgCtx, out, keyxBuilder, openedStreams);
                        return new MslChannel(response, newResult.request);
                    }

                    // Otherwise the remote entity may still have to send us the
                    // application data in a reply.
                    else {
                        // Close the request and response. The response will be
                        // discarded and we will be issuing a new request.
                        try {
                            request.close();
                        } catch (final IOException e) {
                            // If we were cancelled then return null.
                            if (cancelled(e)) return null;
                            // Otherwise we don't care about an I/O exception on close.
                        }
                        try {
                            response.close();
                        } catch (final IOException e) {
                            // If we were cancelled then return null.
                            if (cancelled(e)) return null;
                            // Otherwise we don't care about an I/O exception on close.
                        }

                        // The master token lock acquired from buildResponse() will be
                        // released by the recursive call to execute().
                        releaseLock = false;
                        return execute(keyxMsgCtx, keyxBuilder, timeout, msgCount);
                    }
                } finally {
                    // Release the master token read lock if necessary.
                    if (releaseLock)
                        releaseMasterToken(ctx, keyxBuilder.getMasterToken());
                }
            }

            // Return the established MSL channel to the caller.
            return new MslChannel(response, request);
        }

        /**
         * @return the established MSL channel or {@code null} if cancelled or
         *         interrupted.
         * @throws MslException if there was an error creating or processing
         *         a message.
         * @throws IOException if there was an error reading or writing a
         *         message.
         * @throws TimeoutException if the thread timed out while trying to
         *         acquire the renewal lock.
         * @see java.util.concurrent.Callable#call()
         */
        @Override
        public MslChannel call() throws MslException, IOException, TimeoutException {
            // If we do not already have a connection then establish one.
            final int lockTimeout;
            if (in == null || out == null) {
                try {
                    // Set up the connection.
                    remoteEntity.setTimeout(timeout);

                    // Connect. Keep track of how much time this takes to subtract
                    // that from the lock timeout timeout.
                    final long start = System.currentTimeMillis();
                    final Connection conn = remoteEntity.openConnection();
                    out = conn.getOutputStream();
                    in = conn.getInputStream();
                    lockTimeout = timeout - (int)(System.currentTimeMillis() - start);
                    openedStreams = true;
                } catch (final IOException e) {
                    // If a message builder was provided then release the
                    // master token read lock.
                    if (builder != null)
                        releaseMasterToken(ctx, builder.getMasterToken());

                    // Close any open streams.
                    // We don't care about an I/O exception on close.
                    if (out != null) try { out.close(); } catch (final IOException ioe) { }
                    if (in != null) try { in.close(); } catch (final IOException ioe) { }

                    // If we were cancelled then return null.
                    if (cancelled(e)) return null;
                    throw e;
                } catch (final RuntimeException e) {
                    // If a message builder was provided then release the
                    // master token read lock.
                    if (builder != null)
                        releaseMasterToken(ctx, builder.getMasterToken());

                    // Close any open streams.
                    // We don't care about an I/O exception on close.
                    if (out != null) try { out.close(); } catch (final IOException ioe) { }
                    if (in != null) try { in.close(); } catch (final IOException ioe) { }

                    throw e;
                }
            } else {
                lockTimeout = timeout;
            }

            // If no builder was provided then build a new request. This will
            // acquire the master token lock.
            if (builder == null) {
                try {
                    builder = buildRequest(ctx, msgCtx);
                } catch (final InterruptedException e) {
                    // Close the streams if we opened them.
                    // We don't care about an I/O exception on close.
                    if (openedStreams) {
                        try { out.close(); } catch (final IOException ioe) { }
                        try { in.close(); } catch (final IOException ioe) { }
                    }

                    // We were cancelled so return null.
                    return null;
                }
            }

            try {
                // Execute. This will release the master token lock.
                final MslChannel channel = execute(msgCtx, builder, lockTimeout, msgCount);

                // If the channel was established clear the cached payloads.
                if (channel != null && channel.output != null)
                    channel.output.stopCaching();

                // Close the input stream if we opened it and there is no
                // response. This may be necessary to transmit data
                // buffered in the output stream, and the caller will not
                // be given a message input stream by which to close it.
                //
                // We don't care about an I/O exception on close.
                if (openedStreams && (channel == null || channel.input == null))
                    try { in.close(); } catch (final IOException ioe) { }

                // Return the established channel.
                return channel;
            } catch (final InterruptedException e) {
                // Close the streams if we opened them.
                // We don't care about an I/O exception on close.
                if (openedStreams) {
                    try { out.close(); } catch (final IOException ioe) { }
                    try { in.close(); } catch (final IOException ioe) { }
                }

                // We were cancelled so return null.
                return null;
            } catch (final MslException | IOException | RuntimeException | TimeoutException e) {
                // Close the streams if we opened them.
                // We don't care about an I/O exception on close.
                if (openedStreams) {
                    try { out.close(); } catch (final IOException ioe) { }
                    try { in.close(); } catch (final IOException ioe) { }
                }

                // If we were cancelled then return null.
                if (cancelled(e)) return null;
                throw e;
            }
        }
    }

    /**
     * <p>This service sends a message to a remote entity.</p>
     *
     * <p>This class is only used from trusted network clients and peer-to-peer
     * entities.</p>
     */
    private class SendService implements Callable<MessageOutputStream> {
        /** The request service. */
        private final RequestService requestService;

        /**
         * Create a new message send service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param remoteEntity remote entity URL.
         * @param timeout connect, read, and renewal lock acquisition timeout
         *        in milliseconds.
         */
        public SendService(final MslContext ctx, final MessageContext msgCtx, final Url remoteEntity, final int timeout) {
            this.requestService = new RequestService(ctx, msgCtx, remoteEntity, Receive.NEVER, timeout);
        }

        /**
         * Create a new message send service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param timeout read and renewal lock acquisition timeout in
         *        milliseconds.
         */
        public SendService(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final int timeout) {
            this.requestService = new RequestService(ctx, msgCtx, in, out, Receive.NEVER, timeout);
        }

        /**
         * @return the established MSL channel or {@code null} if cancelled or
         *         interrupted.
         * @throws MslException if there was an error creating or processing
         *         a message.
         * @throws IOException if there was an error reading or writing a
         *         message.
         * @throws TimeoutException if the thread timed out while trying to
         *         acquire the renewal lock.
         * @see java.util.concurrent.Callable#call()
         */
        @Override
        public MessageOutputStream call() throws MslException, IOException, TimeoutException {
            final MslChannel channel = this.requestService.call();
            return (channel != null) ? channel.output : null;
        }
    }

    /**
     * <p>This service sends a message to the remote entity using a request as
     * the basis for the response.</p>
     *
     * <p>This class will only be used trusted network servers.</p>
     */
    public class PushService extends RespondService {
        /**
         * Create a new message push service.
         *
         * @param ctx MSL context.
         * @param msgCtx message context.
         * @param in remote entity input stream.
         * @param out remote entity output stream.
         * @param request request message input stream.
         * @param timeout renewal lock acquisition timeout in milliseconds.
         */
        public PushService(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final MessageInputStream request, final int timeout) {
            super(ctx, msgCtx, in, out, request, timeout);
        }

        /**
         * @return a {@link MslChannel} on success or {@code null} if cancelled,
         *         interrupted, if the response could not be sent encrypted or
         *         integrity protected when required, or if the maximum number
         *         of messages is hit.
         * @throws MslException if there was an error creating the response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         * @see java.util.concurrent.Callable#call()
         */
        @Override
        public MslChannel call() throws MslException, MslErrorResponseException, IOException {
            final MessageDebugContext debugCtx = msgCtx.getDebugContext();

            final MessageHeader requestHeader = request.getMessageHeader();
            final MessageBuilder builder;
            try {
                builder = buildDetachedResponse(ctx, msgCtx, requestHeader);
            } catch (final MslException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                try {
                    final MslError error = e.getError();
                    final MessageCapabilities caps = requestHeader.getMessageCapabilities();
                    final List<String> languages = (caps != null) ? caps.getLanguages() : null;
                    final String userMessage = messageRegistry.getUserMessage(error, languages);
                    sendError(ctx, debugCtx, requestHeader, e.getMessageId(), error, userMessage, out);
                } catch (final Throwable rt) {
                    throw new MslErrorResponseException("Error building the message.", rt, e);
                }
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return null.
                if (cancelled(t)) return null;

                try {
                    sendError(ctx, debugCtx, requestHeader, null, MslError.INTERNAL_EXCEPTION, null, out);
                } catch (final Throwable rt) {
                    throw new MslErrorResponseException("Error building the message.", rt, t);
                }
                throw new MslInternalException("Error building the message.", t);
            }

            try {
                // Send the message. This will release the master token lock.
                final MslChannel channel = trustedNetworkExecute(builder, 0);

                // Clear any cached payloads.
                if (channel != null)
                    channel.output.stopCaching();

                // Return the established channel.
                return channel;
            } catch (final InterruptedException e) {
                // We were cancelled so return null.
                return null;
            } catch (final IOException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Maybe we can send an error response.
                try {
                    final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.MSL_COMMS_FAILURE, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error pushing the message.", rt, e);
                }
                throw e;
            } catch (final MslException e) {
                // If we were cancelled then return null.
                if (cancelled(e)) return null;

                // Maybe we can send an error response.
                try {
                    final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    final MslError error = e.getError();
                    final MessageCapabilities caps = requestHeader.getMessageCapabilities();
                    final List<String> languages = (caps != null) ? caps.getLanguages() : null;
                    final String userMessage = messageRegistry.getUserMessage(error, languages);
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, error, userMessage, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error pushing the message.", rt, e);
                }
                throw e;
            } catch (final Throwable t) {
                // If we were cancelled then return null.
                if (cancelled(t)) return null;

                // Maybe we can send an error response.
                try {
                    final long requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError.INTERNAL_EXCEPTION, null, out);
                } catch (final Throwable rt) {
                    // If we were cancelled then return null.
                    if (cancelled(rt)) return null;

                    throw new MslErrorResponseException("Error pushing the message.", rt, t);
                }
                throw new MslInternalException("Error pushing the message.", t);
            }
        }
    }

    /**
     * <p>Send a message to the entity at the provided URL.</p>
     *
     * <p>Use of this method is not recommended as it does not confirm delivery
     * or acceptance of the message. Establishing a MSL channel to send
     * application data without requiring the remote entity to acknowledge
     * receipt in the response application data is the recommended approach.
     * Only use this method if guaranteed receipt is not required.</p>
     *
     * <p>This method should only be used by trusted network clients and per-
     * to-peer entities when no response is expected from the remote entity.
     * The remote entity should be using
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}
     * and should not attempt to send a response.</p>
     *
     * <p>The returned {@code Future} will return a {@code MessageOutputStream}
     * containing the final {@code MessageOutputStream} that should be used to
     * send any additional application data not already sent via
     * {@link MessageContext#write(MessageOutputStream)}.</p>
     *
     * <p>The returned {@code Future} will return {@code null} if
     * {@link #cancelled(Throwable) cancelled or interrupted}, if an error
     * response was received resulting in a failure to send the message, or if
     * the maximum number of messages is hit without sending the message.</p>
     *
     * <p>The {@code Future} may throw an {@code ExecutionException} whose
     * cause is a {@code MslException}, {@code IOException}, or
     * {@code TimeoutException}.</p>
     *
     * <p>The caller must close the returned message output stream.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param remoteEntity remote entity URL.
     * @param timeout connect, read, and renewal lock acquisition timeout in
     *        milliseconds.
     * @return a future for the message output stream.
     */
    public Future<MessageOutputStream> send(final MslContext ctx, final MessageContext msgCtx, final Url remoteEntity, final int timeout) {
        final MessageContext sendMsgCtx = new SendMessageContext(msgCtx);
        final SendService service = new SendService(ctx, sendMsgCtx, remoteEntity, timeout);
        return executor.submit(service);
    }

    /**
     * <p>Send a message over the provided output stream.</p>
     *
     * <p>Use of this method is not recommended as it does not confirm delivery
     * or acceptance of the message. Establishing a MSL channel to send
     * application data without requiring the remote entity to acknowledge
     * receipt in the response application data is the recommended approach.
     * Only use this method if guaranteed receipt is not required.</p>
     *
     * <p>This method should only be used by trusted network clients and peer-
     * to-peer entities when no response is expected from the remote entity.
     * The remote entity should be using
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}
     * and should not attempt to send a response.</p>
     *
     * <p>The returned {@code Future} will return a {@code MessageOutputStream}
     * containing the final {@code MessageOutputStream} that should be used to
     * send any additional application data not already sent via
     * {@link MessageContext#write(MessageOutputStream)}.</p>
     *
     * <p>The returned {@code Future} will return {@code null} if
     * {@link #cancelled(Throwable) cancelled or interrupted}, if an error
     * response was received resulting in a failure to send the message, or if
     * the maximum number of messages is hit without sending the message.</p>
     *
     * <p>The {@code Future} may throw an {@code ExecutionException} whose
     * cause is a {@code MslException}, {@code IOException}, or
     * {@code TimeoutException}.</p>
     *
     * <p>The caller must close the returned message output stream. The remote
     * entity output stream will not be closed when the message output stream
     * is closed, in case the caller wishes to reuse them.</p>
     *
     * TODO once Java supports the WebSocket protocol we can remove this method
     * in favor of the one accepting a URL parameter. (Or is it the other way
     * around?)
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param timeout connect, read, and renewal lock acquisition timeout in
     *        milliseconds.
     * @return a future for the message output stream.
     */
    public Future<MessageOutputStream> send(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final int timeout) {
        final MessageContext sendMsgCtx = new SendMessageContext(msgCtx);
        final SendService service = new SendService(ctx, sendMsgCtx, in, out, timeout);
        return executor.submit(service);
    }

    /**
     * <p>Push a message over the provided output stream based on a message
     * received from the remote entity.</p>
     *
     * <p>Use of this method is not recommended as it does not perform master
     * token or user ID token issuance or renewal which the remote entity may
     * be attempting to perform. Only use this method if there is some other
     * means by which the client will be able to acquire and renew its master
     * token or user ID token on a regular basis.</p>
     *
     * <p>This method should only be used by trusted network servers that wish
     * to send multiple responses to a trusted network client. The remote
     * entity should be using
     * {@link #send(MslContext, MessageContext, Url, int)} or
     * {@link #send(MslContext, MessageContext, InputStream, OutputStream, int)}
     * and
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}.</p>
     *
     * <p>This method must not be used if
     * {@link MslControl#respond(MslContext, MessageContext, InputStream, OutputStream, MessageInputStream, int)}
     * has already been used with the same {@code MessageInputStream}.</p>
     *
     * <p>The returned {@code Future} will return a {@code MslChannel}
     * containing the same {@code MessageInputStream} that was provided and the
     * final {@code MessageOutputStream} that should be used to send any
     * additional application data not already sent via
     * {@link MessageContext#write(MessageOutputStream)} to the remote
     * entity.</p>
     *
     * <p>The returned {@code Future} will return {@code null} if
     * {@link #cancelled(Throwable) canncelled or interrupted}, if the message
     * could not be sent with encryption or integrity protection when required,
     * if a user cannot be attached to the respond to the response due to lack
     * of a master token, or if the maximum number of messages is hit without
     * sending the message. In these cases the local entity should wait for a
     * new message from the remote entity to be received by a call to
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}
     * before attempting to push another message.</p>
     *
     * <p>The {@code Future} may throw an {@code ExecutionException} whose
     * cause is a {@code MslException}, {@code MslErrorResponseException},
     * {@code IOException}, or {@code TimeoutException}.</p>
     *
     * <p>The remote entity input and output streams will not be closed in case
     * the caller wishes to reuse them.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param request message input stream used to create the message.
     * @param timeout renewal lock acquisition timeout in milliseconds.
     * @return a future for the communication channel.
     * @throws IllegalStateException if used in peer-to-peer mode.
     * @throws IllegalArgumentException if the request message input stream is
     *         an error message.
     */
    public Future<MslChannel> push(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final MessageInputStream request, final int timeout) {
        if (ctx.isPeerToPeer())
            throw new IllegalStateException("This method cannot be used in peer-to-peer mode.");
        if (request.getErrorHeader() != null)
            throw new IllegalArgumentException("Request message input stream cannot be for an error message.");
        final PushService service = new PushService(ctx, msgCtx, in, out, request, timeout);
        return executor.submit(service);
    }

    /**
     * <p>Receive a request over the provided input stream.</p>
     *
     * <p>If there is an error with the message an error response will be sent
     * over the provided output stream.</p>
     *
     * <p>This method should only be used to receive a request initiated by the
     * remote entity. The remote entity should have used one of the request
     * methods
     * {@link #request(MslContext, MessageContext, Url, int)} or
     * {@link #request(MslContext, MessageContext, InputStream, OutputStream, int)}
     * or one of the send methods
     * {@link #send(MslContext, MessageContext, Url, int)} or
     * {@link #send(MslContext, MessageContext, InputStream, OutputStream, int)}.<p>
     *
     * <p>The returned {@code Future} will return the received
     * {@code MessageInputStream} on completion or {@code null} if a reply was
     * automatically sent (for example in response to a handshake request) or
     * if the operation was
     * {@link #cancelled(Throwable) cancelled or interrupted}. The returned
     * message may be an error message if the maximum number of messages is hit
     * without successfully receiving the final message. The {@code Future} may
     * throw an {@code ExecutionException} whose cause is a
     * {@code MslException}, {@code MslErrorResponseException},
     * {@code IOException}, or {@code TimeoutException}.</p>
     *
     * <p>The remote entity input and output streams will not be closed in case
     * the caller wishes to reuse them.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param timeout renewal acquisition lock timeout in milliseconds.
     * @return a future for the message.
     */
    public Future<MessageInputStream> receive(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final int timeout) {
        final ReceiveService service = new ReceiveService(ctx, msgCtx, in, out, timeout);
        return executor.submit(service);
    }

    /**
     * <p>Send a response over the provided output stream.</p>
     *
     * <p>This method should only be used by trusted network servers and peer-
     * to-peer entities after receiving a request via
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}.
     * The remote entity should have used one of the request methods
     * {@link #request(MslContext, MessageContext, Url, int)} or
     * {@link #request(MslContext, MessageContext, InputStream, OutputStream, int)}.</p>
     *
     * <p>The returned {@code Future} will return a {@code MslChannel}
     * containing the final {@code MessageOutputStream} that should be used to
     * send any additional application data not already sent via
     * {@link MessageContext#write(MessageOutputStream)} to the remote entity,
     * and in peer-to-peer mode may also contain a {@code MessageInputStream}
     * as described below.</p>
     *
     * <p>In peer-to-peer mode a new {@code MessageInputStream} may be returned
     * which should be used in place of the previous {@code MessageInputStream}
     * being responded to. This will only occur if the initial response sent
     * could not include application data and was instead a handshake message.
     * The new {@code MessageInputStream} will not include any application data
     * already read off of the previous {@code MessageInputStream}; it will
     * only contain new application data that is a continuation of the previous
     * message's application data.</p>
     *
     * <p>The returned {@code Future} will return {@code null} if
     * {@link #cancelled(Throwable) cancelled or interrupted}, if an error
     * response was received (peer-to-peer only) resulting in a failure to
     * establish the communication channel, if the response could not be sent
     * with encryption or integrity protection when required (trusted network-
     * mode only), if a user cannot be attached to the response due to lack of
     * a master token, or if the maximum number of messages is hit without
     * sending the message. In these cases the remote entity's next message can
     * be received by another call to
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}.</p>
     *
     * <p>The {@code Future} may throw an {@code ExecutionException} whose
     * cause is a {@code MslException}, {@code MslErrorResponseException},
     * {@code IOException}, or {@code TimeoutException}.</p>
     *
     * <p>The remote entity input and output streams will not be closed in case
     * the caller wishes to reuse them.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param request message input stream to create the response for.
     * @param timeout renewal lock acquisition timeout in milliseconds.
     * @return a future for the communication channel.
     * @throws IllegalArgumentException if the request message input stream is
     *         an error message.
     */
    public Future<MslChannel> respond(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final MessageInputStream request, final int timeout) {
        if (request.getErrorHeader() != null)
            throw new IllegalArgumentException("Request message input stream cannot be for an error message.");
        final RespondService service = new RespondService(ctx, msgCtx, in, out, request, timeout);
        return executor.submit(service);
    }

    /**
     * <p>Send an error response over the provided output stream. Any replies
     * to the error response may be received by a subsequent call to
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}.</p>
     *
     * <p>This method should only be used by trusted network servers and peer-
     * to-peer entities after receiving a request via
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}.
     * The remote entity should have used
     * {@link #request(MslContext, MessageContext, Url, int)}.</p>
     *
     * <p>The returned {@code Future} will return true on success or false if
     * {@link #cancelled(Throwable) cancelled or interrupted}. The
     * {@code Future} may throw an {@code ExecutionException} whose cause is a
     * {@code MslException} or {@code IOException}.</p>
     *
     * <p>The remote entity input and output streams will not be closed in case
     * the caller wishes to reuse them.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param err error type.
     * @param out remote entity output stream.
     * @param request request input srtream to create the response for.
     * @return a future for the operation.
     * @throws IllegalArgumentException if the request message input stream is
     *         an error message.
     */
    public Future<Boolean> error(final MslContext ctx, final MessageContext msgCtx, final ApplicationError err, final OutputStream out, final MessageInputStream request) {
        if (request.getErrorHeader() != null)
            throw new IllegalArgumentException("Request message input stream cannot be for an error message.");
        final ErrorService service = new ErrorService(ctx, msgCtx, err, out, request);
        return executor.submit(service);
    }

    /**
     * <p>Send a request to the entity at the provided URL.</p>
     *
     * <p>This method should only be used by trusted network clients when
     * initiating a new request. The remote entity should be using
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}
     * and
     * {@link #respond(MslContext, MessageContext, InputStream, OutputStream, MessageInputStream, int)}.</p>
     *
     * <p>The returned {@code Future} will return a {@code MslChannel}
     * containing the final {@code MessageOutputStream} that should be used to
     * send any additional application data not already sent via
     * {@link MessageContext#write(MessageOutputStream)} and the
     * {@code MessageInputStream} of the established MSL communication
     * channel. If an error message was received then the MSL channel's message
     * output stream will be {@code null}.</p>
     *
     * <p>The returned {@code Future} will return {@code null} if
     * {@link #cancelled(Throwable) cancelled or interrupted}. The returned
     * message may be an error message if the maximum number of messages is hit
     * without successfully sending the request and receiving the response. The
     * {@code Future} may throw an {@code ExecutionException} whose cause is a
     * {@code MslException}, {@code IOException}, or
     * {@code TimeoutException}.</p>
     *
     * <p>The caller must close the returned message input stream and message
     * outut stream.</p>
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param remoteEntity remote entity URL.
     * @param timeout connect, read, and renewal lock acquisition timeout in
     *        milliseconds.
     * @return a future for the communication channel.
     * @throws IllegalStateException if used in peer-to-peer mode.
     */
    public Future<MslChannel> request(final MslContext ctx, final MessageContext msgCtx, final Url remoteEntity, final int timeout) {
        if (ctx.isPeerToPeer())
            throw new IllegalStateException("This method cannot be used in peer-to-peer mode.");
        final RequestService service = new RequestService(ctx, msgCtx, remoteEntity, Receive.ALWAYS, timeout);
        return executor.submit(service);
    }

    /**
     * <p>Send a request to the remote entity over the provided output stream
     * and receive a resposne over the provided input stream.</p>
     *
     * <p>This method should only be used by peer-to-peer entities when
     * initiating a new request. The remote entity should be using
     * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}
     * and
     * {@link #respond(MslContext, MessageContext, InputStream, OutputStream, MessageInputStream, int)}.</p>
     *
     * <p>The returned {@code Future} will return a {@code MslChannel}
     * containing the final {@code MessageOutputStream} that should be used to
     * send any additional application data not already sent via
     * {@link MessageContext#write(MessageOutputStream)} and the
     * {@code MessageInputStream} of the established MSL communication
     * channel. If an error message was received then the MSL channel's message
     * output stream will be {@code null}.</p>
     *
     * <p>The returned {@code Future} will return {@code null} if
     * {@link #cancelled(Throwable) cancelled or interrupted}. The returned
     * message may be an error message if the maximum number of messages is hit
     * without successfully sending the request and receiving the response. The
     * {@code Future} may throw an {@code ExecutionException} whose cause is a
     * {@code MslException}, {@code IOException}, or
     * {@code TimeoutException}.</p>
     *
     * <p>The caller must close the returned message input stream and message
     * outut stream. The remote entity input and output streams will not be
     * closed when the message input and output streams are closed, in case the
     * caller wishes to reuse them.</p>
     *
     * TODO once Java supports the WebSocket protocol we can remove this method
     * in favor of the one accepting a URL parameter. (Or is it the other way
     * around?)
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param timeout renewal lock acquisition timeout in milliseconds.
     * @return a future for the communication channel.
     * @throws IllegalStateException if used in trusted network mode.
     */
    public Future<MslChannel> request(final MslContext ctx, final MessageContext msgCtx, final InputStream in, final OutputStream out, final int timeout) {
        if (!ctx.isPeerToPeer())
            throw new IllegalStateException("This method cannot be used in trusted network mode.");
        final RequestService service = new RequestService(ctx, msgCtx, in, out, Receive.ALWAYS, timeout);
        return executor.submit(service);
    }

    /** MSL executor. */
    private final ExecutorService executor;

    /** Message factory. */
    private final MessageFactory messageFactory;
    /** Error message registry. */
    private final ErrorMessageRegistry messageRegistry;
    /** Filter stream factory. May be null. */
    private FilterStreamFactory filterFactory = null;

    /**
     * Map tracking outstanding renewable messages by MSL context. The blocking
     * queue is used to wait for a master token from a different thread if the
     * message requires one.
     */
    private final ConcurrentHashMap<MslContext,BlockingQueue<MasterToken>> renewingContexts = new ConcurrentHashMap<MslContext,BlockingQueue<MasterToken>>();
    /** Dummy master token used to release the renewal lock. */
    private final MasterToken NULL_MASTER_TOKEN;

    /**
     * Map of in-flight master token read-write locks by MSL context and master
     * token.
     */
    private final ConcurrentHashMap<MslContextMasterTokenKey,ReadWriteLock> masterTokenLocks = new ConcurrentHashMap<MslContextMasterTokenKey,ReadWriteLock>();
}

/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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
#ifndef _SRC_MSG_MSLCONTROL_H_
#define _SRC_MSG_MSLCONTROL_H_

// FIXME: Consider making this a PIMPL to hide the plenitude of private methods

#include <keyx/KeyExchangeFactory.h>  // FIXME: Have to include this because can't forward-declare nested classes
#include <util/BlockingQueue.h>
#include <util/ConcurrentHashMap.h>
#include <future>
#include <memory>

namespace netflix {
namespace msl {
namespace io { class Url; class OutputStream; class InputStream; }
namespace util { class MslContext; class ReadWriteLock; class Executor; }
namespace msg {

class ErrorHeader;
class ErrorMessageRegistry;
class FilterStreamFactory;
class MessageBuilder;
class MessageDebugContext;
class MessageHeader;
class MessageInputStream;
class MessageOutputStream;
class MessageContext;
class MessageFactory;
class MslContextMasterTokenKey;
    
/**
 * Application level errors that may translate into MSL level errors.
 */
enum ApplicationError
{
    /** The entity identity is no longer accepted by the application. */
    ENTITY_REJECTED,
    /** The user identity is no longer accepted by the application. */
    USER_REJECTED
};

/**
 * A {@link MessageInputStream} and {@link MessageOutputStream} pair
 * representing a single MSL communication channel established between
 * the local and remote entities.
 */
class MslChannel
{
public:
    /**
     * Create a new MSL channel with the provided input and output streams.
     *
     * @param input message input stream to read from the remote entity.
     * @param output message output stream to write to the remote entity.
     */
    MslChannel(std::shared_ptr<MessageInputStream> input,
               std::shared_ptr<MessageOutputStream> output);
    std::shared_ptr<MessageInputStream> input();
    std::shared_ptr<MessageOutputStream> output();
private:
    std::shared_ptr<MessageInputStream> input_;
    std::shared_ptr<MessageOutputStream> output_;
};
    
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
 */
class MslControl
{
public:
    /**
     * Create a new instance of MSL control with the specified number of
     * threads. A thread count of zero will cause all operations to execute on
     * the calling thread.
     *
     * @param numThreads number of worker threads to create.
     */
    MslControl(int numThreads);

    /**
     * Create a new instance of MSL control with the specified number of
     * threads and user error message registry. A thread count of zero will
     * cause all operations to execute on the calling thread.
     *
     * @param numThreads number of worker threads to create.
     * @param messageFactory message factory. May be {@code null}.
     * @param messageRegistry error message registry. May be {@code null}.
     */
    MslControl(int32_t numThreads, std::shared_ptr<MessageFactory> messageFactory,
            std::shared_ptr<ErrorMessageRegistry> messageRegistry);

    /**
     * Assigns a filter stream factory that will be used to filter any incoming
     * or outgoing messages. The filters will be placed between the MSL message
     * and MSL control, meaning they will see the actual MSL message data as it
     * is being read from or written to the remote entity.
     *
     * @param factory filter stream factory. May be null.
     */
    void setFilterFactory(std::shared_ptr<FilterStreamFactory> factory);

    /**
     * Gracefully shutdown the MSL control instance. No additional messages may
     * be processed. Any messages pending or in process will be completed.
     */
    void shutdown();
    
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
    std::future<std::shared_ptr<MessageOutputStream>> send(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::Url> remoteEntity,
            int64_t timeout);

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
    std::future<std::shared_ptr<MessageOutputStream>> send(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::InputStream> in,
            std::shared_ptr<io::OutputStream> out,
            int64_t timeout);

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
    std::future<std::shared_ptr<MslChannel>> push(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::InputStream> in,
            std::shared_ptr<io::OutputStream> out,
            std::shared_ptr<MessageInputStream> request,
            int64_t timeout);

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
     * if the operation was cancelled or interrupted. The returned message may
     * be an error message if the maximum number of messages is hit without
     * successfully receiving the final message. The {@code Future} may throw
     * an {@code ExecutionException} whose cause is a {@code MslException},
     * {@code MslErrorResponseException}, {@code IOException}, or
     * {@code TimeoutException}.</p>
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
    std::future<std::shared_ptr<MessageInputStream>> receive(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::InputStream> in,
            std::shared_ptr<io::OutputStream> out,
            int64_t timeout);
    

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
     * <p>The returned {@code Future} will return {@code null} if cancelled,
     * interrupted, if an error response was received (peer-to-peer only)
     * resulting in a failure to establish the communication channel, if the
     * response could not be sent with encryption or integrity protection when
     * required (trusted network-mode only), if a user cannot be attached to
     * the response due to lack of a master token, or if the maximum number of
     * messages is hit without sending the message. In these cases the remote
     * entity's next message can be received by another call to
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
    std::future<std::shared_ptr<MslChannel>> respond(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::InputStream> in,
            std::shared_ptr<io::OutputStream> out,
            std::shared_ptr<MessageInputStream> request,
            int64_t timeout);

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
     * cancelled or interrupted. The {@code Future} may throw an
     * {@code ExecutionException} whose cause is a {@code MslException} or
     * {@code IOException}.</p>
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
    std::future<bool> error(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            ApplicationError err,
            std::shared_ptr<io::OutputStream> out,
            std::shared_ptr<MessageInputStream> request);

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
     * <p>The returned {@code Future} will return {@code null} if cancelled or
     * interrupted. The returned message may be an error message if the maximum
     * number of messages is hit without successfully sending the request and
     * receiving the response. The {@code Future} may throw an
     * {@code ExecutionException} whose cause is a {@code MslException},
     * {@code IOException}, or {@code TimeoutException}.</p>
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
    std::future<std::shared_ptr<MslChannel>> request(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::Url> remoteEntity,
            int64_t timeout);

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
     * <p>The returned {@code Future} will return {@code null} if cancelled or
     * interrupted. The returned message may be an error message if the maximum
     * number of messages is hit without successfully sending the request and
     * receiving the response. The {@code Future} may throw an
     * {@code ExecutionException} whose cause is a {@code MslException},
     * {@code IOException}, or {@code TimeoutException}.</p>
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
    std::future<std::shared_ptr<MslChannel>> request(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::InputStream> in,
            std::shared_ptr<io::OutputStream> out,
            int64_t timeout);

private: // types

    /**
     * The result of building an error response, forward declaration.
     */
    struct ErrorResult;

    /**
     * The result of sending a message, forward declaration.
     */
    struct SendResult;

    /**
     * The result of sending and receiving messages, forward declaration.
     */
    struct SendReceiveResult;

    /**
     * Forward declarations of thread-callable classes
     */
    class ReceiveService;
    class RespondService;
    class ErrorService;
    class RequestService;
    class SendService;
    class PushService;

    /**
     * Indicates response expectations for a specific request.
     */
    enum Receive {
        /** A response is always expected. */
        ALWAYS,
        /** A response is only expected if tokens are being renewed. */
        RENEWING,
        /** A response is never expected. */
        NEVER
    };

private: // methods

    void init(int32_t numThreads);

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
    std::shared_ptr<tokens::MasterToken> getNewestMasterToken(std::shared_ptr<util::MslContext> ctx);

    /**
     * Deletes the provided master token from the MSL store. Doing so requires
     * acquiring the master token's write lock.
     *
     * @param ctx MSL context.
     * @param masterToken master token to delete. May be null.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to acquire the master token's write lock.
     */
    void deleteMasterToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<tokens::MasterToken> masterToken);

    /**
     * Release the read lock of the provided master token. If no master token
     * is provided then this method is a no-op.
     *
     * @param ctx MSL context.
     * @param masterToken the master token. May be null.
     * @see #getNewestMasterToken(MslContext)
     */
    void releaseMasterToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<tokens::MasterToken> masterToken);

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
    void updateCryptoContexts(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<msg::MessageHeader> messageHeader,
            std::shared_ptr<keyx::KeyExchangeFactory::KeyExchangeData> keyExchangeData);

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
    void updateCryptoContexts(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<msg::MessageHeader> request,
            std::shared_ptr<msg::MessageInputStream> response);

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
    std::shared_ptr<MessageBuilder> buildRequest(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx);

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
    std::shared_ptr<MessageBuilder> buildResponse(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx, std::shared_ptr<msg::MessageHeader> request);

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
    std::shared_ptr<MessageBuilder> buildDetachedResponse(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<MessageHeader> request);

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
    std::shared_ptr<ErrorResult> buildErrorResponse(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx, std::shared_ptr<SendResult> sent,
            std::shared_ptr<ErrorHeader> errorHeader);

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
    void cleanupContext(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<msg::MessageHeader> requestHeader,
            std::shared_ptr<ErrorHeader> errorHeader);

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
    std::shared_ptr<SendResult> send(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<io::OutputStream> out, std::shared_ptr<MessageBuilder> builder, bool closeDestination);

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
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token, or there is an error updating the
     *         service tokens, or the header data is missing or invalid, or the
     *         message ID is negative, or the message is not encrypted and
     *         contains user authentication data, or if the message master
     *         token is expired and the message is not renewable.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token, or there is an error updating the
     *         service tokens.
     * @throws InterruptedException if the thread is interrupted while trying
     *         to delete an old master token the received message is replacing.
     */
    std::shared_ptr<MessageInputStream> receive(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx, std::shared_ptr<io::InputStream> in,
            std::shared_ptr<MessageHeader> request);

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
     * @param builder request message builder->
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
    std::shared_ptr<SendReceiveResult> sendReceive(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageContext> msgCtx, std::shared_ptr<io::InputStream> in,
            std::shared_ptr<io::OutputStream> out, std::shared_ptr<MessageBuilder> builder,
            Receive receive, bool closeStreams, int64_t timeout);

    /**
     * <p>Attempt to acquire the renewal lock if the message will need it using
     * the given blocking queue.</p>
     *
     * <p>If anti-replay is required then this method will block until the
     * renewal lock is acquired.</p>
     *
     * <p>If the message has already been marked renewable then this method
     * will block until the renewal lock is acquired or a renewing thread
     * delivers a new master token to this builder-></p>
     *
     * <p>If encryption is required but the builder will not be able to encrypt
     * the message payloads, or if integrity protection is required but the
     * builder will not be able to integrity protect the message payloads, or
     * if the builder's master token is expired, or if there is no user ID
     * token but the message is associated with a user and the builder will not
     * be able to encrypt and integrity protect the message header, then this
     * method will block until the renewal lock is acquired or a renewing
     * thread delivers a master token to this builder-></p>
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
    bool acquireRenewalLock(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<MessageContext> msgCtx,
            std::shared_ptr<util::BlockingQueue<tokens::MasterToken>> queue,
            std::shared_ptr<MessageBuilder> builder, int64_t timeout);

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
    void releaseRenewalLock(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<util::BlockingQueue<tokens::MasterToken>> queue,
            std::shared_ptr<MessageInputStream> message);

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
     * @throws IOException if there is an error sending the error response->
     */
    void sendError(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<MessageDebugContext> debugCtx,
            std::shared_ptr<MessageHeader> requestHeader, int64_t messageId,
            const MslError& error, const std::string& userMessage, std::shared_ptr<io::OutputStream> out);

private: // attributes

    /** MSL executor. */
    std::shared_ptr<util::Executor> executor;

    /** Message factory. */
    std::shared_ptr<MessageFactory> messageFactory;
    /** Error message registry. */
    std::shared_ptr<ErrorMessageRegistry> messageRegistry;
    /** Filter stream factory. May be null. */
    std::shared_ptr<FilterStreamFactory> filterFactory;

    /**
     * Map tracking outstanding renewable messages by MSL context. The blocking
     * queue is used to wait for a master token from a different thread if the
     * message requires one.
     */
    util::ConcurrentHashMap<util::MslContext, util::BlockingQueue<tokens::MasterToken>> renewingContexts;
    /** Dummy master token used to release the renewal lock. */
    std::shared_ptr<tokens::MasterToken> NULL_MASTER_TOKEN;

    /**
     * Map of in-flight master token read-write locks by MSL context and master
     * token.
     */
    util::ConcurrentHashMap<MslContextMasterTokenKey, util::ReadWriteLock> masterTokenLocks;
};
    
}}} // namespace netflix::msl::msg

#endif

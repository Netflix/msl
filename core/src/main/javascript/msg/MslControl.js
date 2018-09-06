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
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var OutputStream = require('../io/OutputStream.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var ErrorMessageRegistry = require('../msg/ErrorMessageRegistry.js');
	var MessageContext = require('../msg/MessageContext.js');
	var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
	var MslInterruptedException = require('../MslInterruptedException.js');
	var MslException = require('../MslException.js');
	var MessageFactory = require('../msg/MessageFactory.js');
	var ReadWriteLock = require('../util/ReadWriteLock.js');
	var MessageBuilder = require('../msg/MessageBuilder.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslConstants = require('../MslConstants.js');
	var MessageServiceTokenBuilder = require('../msg/MessageServiceTokenBuilder.js');
	var MslMessageException = require('../MslMessageException.js');
	var MslError = require('../MslError.js');
	var BlockingQueue = require('../util/BlockingQueue.js');
	var MessageCapabilities = require('../msg/MessageCapabilities.js');
	var MslErrorResponseException = require('../MslErrorResponseException.js');
	var MslIoException = require('../MslIoException.js');
	var MslUtils = require('../util/MslUtils.js');
	var Semaphore = require('../util/Semaphore.js');

    /**
     * Application level errors that may translate into MSL level errors.
     */
    var ApplicationError = {
        /** The entity identity is no longer accepted by the application. */
        ENTITY_REJECTED: "ENTITY_REJECTED",
        /** The user identity is no longer accepted by the application. */
        USER_REJECTED: "USER_REJECTED"
    };

    /**
     * A {@link MessageInputStream} and {@link MessageOutputStream} pair
     * representing a single MSL communication channel established between
     * the local and remote entities.
     */
    var MslChannel = function MslChannel(input, output) {
        var props = {
            /** Message input stream to read from the remote entity. */
            input: { value: input, writable: false, configurable: false },
            /** Message output stream to write to the remote entity. */
            output: { value: output, writable: false, configurable: false }
        };
        Object.defineProperties(this, props);
        return this;
    };

    /**
     * A map key based off a MSL context and master token pair.
     */
    var MslContextMasterTokenKey = Class.create({
        /**
         * Create a new MSL context and master token map key.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MasterToken} masterToken master token.
         */
        init: function init(ctx, masterToken) {
            // The properties.
            var props = {
                _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                _masterToken: { value: masterToken, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is an instance of this
         *         class pointing at the exact same MSL context and with an
         *         equal master token.
         * @see #uniqueKey()
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof MslContextMasterTokenKey)) return false;
            return this._ctx === that._ctx && this._masterToken.equals(that._masterToken);
        },

        /**
         * @return {string} a string that uniquely identifies this MSL context
         *         and master token key pair.
         * @see #equals(that)
         */
        uniqueKey: function uniqueKey() {
            return this._ctx.uniqueKey() + ':' + this._masterToken.uniqueKey();
        },
    });

    /**
     * Creates a function that when called will abort the service.
     *
     * @param {MslControl} ctrl the MSL control reference.
     * @parma {?number} ticket the transaction cancellation ticket.
     * @param {ReceiveService|RespondService|RequestService} service the
     *        service that will be aborted.
     */
    function CancellationFunction(ctrl, ticket, service) {
        return function() {
            if (ticket)
                ctrl._threads.cancel(ticket);
            service.abort();
        };
    }

    /**
     * A null output stream has no-ops when writing data.
     */
    var NullOutputStream = OutputStream.extend({
        /** @inheritDoc */
        close: function close(timeout, callback) {
            callback.result(true);
        },

        /** @inheritDoc */
        write: function write(data, off, len, timeout, callback) {
            AsyncExecutor(callback, function() {
                var written = Math.min(data.length - off, len);
                return written;
            });
        },

        /** @inheritDoc */
        flush: function flush(timeout, callback) {
            callback.result(true);
        }
    });

    /**
     * A dummy error message registry that always returns null for the user
     * message.
     */
    var DummyMessageRegistry = ErrorMessageRegistry.extend({
        /** @inheritDoc */
        getUserMessage: function getUserMessage(err, languages) {
            return null;
        },
    });

    /**
     * Base class for custom message contexts. All methods are passed through
     * to the backing message context.
     */
    var FilterMessageContext = MessageContext.extend({
        /**
         * Creates a message context that passes through calls to the backing
         * message context.
         *
         * @param {MessageContext} appCtx the application's message context.
         */
        init: function init(appCtx) {
            // The properties.
            var props = {
                _appCtx: { value: appCtx, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getCryptoContexts: function getCryptoContexts() {
            return this._appCtx.getCryptoContexts();
        },

        /** @inheritDoc */
        getRemoteEntityIdentity: function getRemoteEntityIdentity() {
            return this._appCtx.getRemoteEntityIdentity();
        },

        /** @inheritDoc */
        isEncrypted: function isEncrypted() {
            return this._appCtx.isEncrypted();
        },

        /** @inheritDoc */
        isIntegrityProtected: function isIntegrityProtected() {
            return this._appCtx.isIntegrityProtected();
        },

        /** @inheritDoc */
        isNonReplayable: function isNonReplayable() {
            return this._appCtx.isNonReplayable();
        },

        /** @inheritDoc */
        isRequestingTokens: function isRequestingTokens() {
            return this._appCtx.isRequestingTokens();
        },

        /** @inheritDoc */
        getUserId: function getUserId() {
            return this._appCtx.getUserId();
        },

        /** @inheritDoc */
        getUserAuthData: function getUserAuthData(reauthCode, renewable, required, callback) {
            this._appCtx.getUserAuthData(reauthCode, renewable, required, callback);
        },

        /** @inheritDoc */
        getUser: function getUser() {
            return this._appCtx.getUser();
        },

        /** @inheritDoc */
        getKeyRequestData: function getKeyRequestData(callback) {
            this._appCtx.getKeyRequestData(callback);
        },

        /** @inheritDoc */
        updateServiceTokens: function updateServiceTokens(builder, handshake, callback) {
            this._appCtx.updateServiceTokens(builder, handshake, callback);
        },

        /** @inheritDoc */
        write: function write(output, timeout, callback) {
            this._appCtx.write(output, timeout, callback);
        },

        /** @inheritDoc */
        getDebugContext: function getDebugContext() {
            return this._appCtx.getDebugContext();
        }
    });

    /**
     * This message context is used to re-send a message.
     */
    var ResendMessageContext = FilterMessageContext.extend({
        /**
         * Creates a message context used to re-send a message after an error
         * or handshake. If the payloads are null the application's message
         * context will be asked to write its data. Otherwise the provided
         * payloads will be used for the message's application data.
         *
         * @param {?Array.<PayloadChunk>} payloads original request payload chunks. May be null.
         * @param {MessageContext} appCtx the application's message context.
         */
        init: function init(payloads, appCtx) {
            init.base.call(this, appCtx);
            // The properties.
            var props = {
                _payloads: { value: payloads, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        write: function write(output, timeout, callback) {
            var self = this;

            // If there are no payloads ask the application message context to
            // write its data.
            if (!this._payloads || this._payloads.length == 0) {
                write.base.call(this, output, timeout, callback);
                return;
            }

            // Rewrite the payloads one-by-one.
            function nextChunk(index) {
                if (index == self._payloads.length) {
                    callback.result(true);
                    return;
                }

                var chunk = self._payloads[index];
                output.setCompressionAlgorithm(chunk.compressionAlgo, timeout, {
                    result: function(success) {
                        output.write(chunk.data, 0, chunk.data.length, timeout, {
                            result: function(written) {
                                InterruptibleExecutor(callback, function() {
                                    if (chunk.isEndOfMessage()) {
                                        output.close(timeout, {
                                            result: function(success) {
                                                if (!success) callback.result(success);
                                                else nextChunk(index + 1);
                                            },
                                            timeout: callback.timeout,
                                            error: callback.error,
                                        });
                                    } else {
                                        output.flush(timeout, {
                                            result: function(success) {
                                                if (!success) callback.result(success);
                                                else nextChunk(index + 1);
                                            },
                                            timeout: callback.timeout,
                                            error: callback.error,
                                        });
                                    }
                                }, self);
                            },
                            timeout: callback.timeout,
                            error: callback.error,
                        });
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }
            nextChunk(0);
        }
    });
    
    /**
     * This message context is used to send messages that will not expect a
     * response.
     */
    var SendMessageContext = FilterMessageContext.extend({
        /**
         * Creates a message context used to send messages that do not expect a
         * response by ensuring that the message context conforms to those
         * expectations.
         * 
         * @param {MessageContext} appCtx the application's message context.
         */
        init: function init(appCtx) {
            init.base.call(this, appCtx);
        },

        /** @inheritDoc */
        isRequestingTokens: function isRequestingTokens() {
            return false;
        },
    });

    /**
     * This message context is used to send a handshake response.
     */
    var KeyxResponseMessageContext = FilterMessageContext.extend({
        /**
         * Creates a message context used for automatically generated handshake
         * responses.
         *
         * @param {MessageContext} appCtx the application's message context.
         */
        init: function init(appCtx) {
            init.base.call(this, appCtx);
        },

        /** @inheritDoc */
        isEncrypted: function isEncrypted() {
            // Key exchange responses cannot require encryption otherwise key
            // exchange could never succeed in some cases.
            return false;
        },

        /** @inheritDoc */
        isIntegrityProtected: function isIntegrityProtected() {
            // Key exchange responses cannot require integrity protection
            // otherwise key exchange could never succeed in some cases.
            return false;
        },

        /** @inheritDoc */
        isNonReplayable: function isNonReplayable() {
            return false;
        },

        /** @inheritDoc */
        write: function write(output, timeout, callback) {
            // No application data.
            callback.result(true);
        }
    });

    /**
     * A master token and its associated read/write lock ticket number.
     *
     * @param {MasterToken} masterToken
     * @param {number} ticket
     */
    function TokenTicket(masterToken, ticket) {
        // The properties.
        var props = {
            masterToken: { value: masterToken, writable: false, configurable: false },
            ticket: { value: ticket, writable: false, configurable: false }
        };
        Object.defineProperties(this, props);
    }

    /**
     * The result of building an error response.
     *
     * Create a new result with the provided request builder and message
     * context.
     *
     * @param {MessageBuilder} builder
     * @param {MessageContext} msgCtx
     */
    function ErrorResult(builder, msgCtx) {
        // The properties.
        var props = {
            /** The new request to send. */
            builder: { value: builder, writable: false, configurable: false },
            /** The new message context to use. */
            msgCtx: { value: msgCtx, writable: false, configurable: false }
        };
        Object.defineProperties(this, props);
    }

    /**
     * The result of sending a message.
     *
     * Create a new result with the provided message output stream
     * containing the cached application data (which was not sent if the
     * message was a handshake).
     *
     * @param {MessageOutputStream} request request message output stream.
     * @param {boolean} handshake true if a handshake message was sent and the
     *        application data was not sent.
     */
    function SendResult(request, handshake) {
        // The properties.
        var props = {
            /** The request message output stream. */
            request: { value: request, writable: false, configurable: false },
            /** True if the message was a handshake (application data was not sent). */
            handshake: { value: handshake, writable: false, configurable: false }
        };
        Object.defineProperties(this, props);
    }
    
    /**
     * Indicates response expectations for a specific request.
     */
    var Receive = {
        /** A response is always expected. */
        ALWAYS: 0,
        /** A response is only expected if tokens are being renewed. */
        RENEWING: 1,
        /** A response is never expected. */
        NEVER: 2
    };

    /**
     * The result of sending and receiving messages.
     *
     * Create a new result with the provided response and send result.
     *
     * @param {MessageInputStream} response response message input stream. May be {@code null}.
     * @param {SendResult} sent sent message result.
     */
    function SendReceiveResult(response, sent) {
        // The properties.
        var props = {
            /** The request message output stream. */
            request: { value: sent.request, writable: false, configurable: false },
            /** True if the message was a handshake (application data was not sent). */
            handshake: { value: sent.handshake, writable: false, configurable: false },
            /** The response message input stream. */
            response: { value: response, writable: false, configurable: false }
        };
        Object.defineProperties(this, props);
    }

    /**
     * Dummy master token used to release the renewal lock.
     */
    var NULL_MASTER_TOKEN = {};

    /**
     * <p>Returns true if the current operation has been interrupted/cancelled
     * as indicated by the type of caught error.</p>
     * 
     * <p>The following error types are considered interruptions or
     * cancellations that the application initiated or should otherwise be
     * aware of:
     * <ul>
     * <li>{@link MslInterruptedException}</li>
     * </ul></p>
     *
     * @param {?Error} e caught error. May be null.
     * @return {boolean} true if the error indicates an operation was
     *         interrupted.
     */
    function cancelled(t) {
        while (t) {
            if (t instanceof MslInterruptedException)
                return true;
            if (t instanceof MslException)
                t = t.cause;
            else
                t = undefined;
        }
        return false;
    }

    var MslControlImpl = Class.create({
        /**
         * Create a new instance of MSL control.
         *
         * @param {?MessageFactory} messageFactory message factory. May be {@code null}.
         * @param {?ErrorMessageRegistry} messageRegistry error message registry. May be {@code null}.
         */
        init: function init(messageFactory, messageRegistry) {
            if (!messageFactory)
                messageFactory = new MessageFactory();
            if (!messageRegistry)
                messageRegistry = new DummyMessageRegistry();

            // The properties.
            var props = {
                /**
                 * Message factory.
                 * @type {MessageFactory}
                 */
                _messageFactory: { value: messageFactory, writable: false, enumerable: false, configurable: false },
                /**
                 * Error message registry.
                 * @type {ErrorMessageRegistry}
                 */
                _messageRegistry: { value: messageRegistry, writable: false, enumerable: false, configurable: false },
                /**
                 * Filter stream factory. May be null.
                 * @type {FilterStreamFactory}
                 */
                _filterFactory: { value: null, writable: true, enumerable: false, configurable: false },
                /**
                 * Map tracking outstanding renewable messages by MSL context. The blocking
                 * queue is used to wait for a master token from a different thread if the
                 * message requires one.
                 * @type {Array.<{ctx: MslContext, queue: BlockingQueue}>}
                 */
                _renewingContexts: { value: [], writable: false, enumerable: false, configurable: false },
                /**
                 * Map of in-flight master token read-write locks by MSL context and master
                 * token.
                 * @type {Object.<MslContextMasterTokenKey,ReadWriteLock>}
                 */
                _masterTokenLocks: { value: {}, writable: false, enumerable: false, configurable: false },
                /**
                 * Map of remote entity clocks by MSL context. This data is only relevant
                 * to trusted network clients and peer-to-peer entities.
                 * @type {Array.<{ctx: MslContext, clock: SynchronizedClock}>}
                 */
                _remoteClocks: { value: [], writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * Assigns a filter stream factory that will be used to filter any incoming
         * or outgoing messages. The filters will be placed between the MSL message
         * and MSL control, meaning they will see the actual MSL message data as it
         * is being read from or written to the remote entity.
         *
         * @param {FilterStreamFactory} factory filter stream factory. May be null.
         */
        setFilterFactory: function setFilterFactory(factory) {
            this._filterFactory = factory;
        },

        /**
         * <p>Returns the newest master token from the MSL store and acquires the
         * master token's read lock.</p>
         *
         * <p>When the caller no longer requires the master token or its crypto
         * context to exist (i.e. it does not expect to receive a response that
         * uses the same master token) then it must release the lock.</p>
         *
         * @param {ReceiveService|RespondService|RequestService} service the calling service.
         * @param {MslContext} ctx MSL context.
         * @param {number} timeout lock acquisition timeout in milliseconds.
         * @param {{result: function(TokenTicket), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the master token (or null
         *        if there is none) and lock ticket, notification of timeout,
         *        or any thrown exceptions.
         * @throws InterruptedException if the thread is interrupted while trying
         *         to acquire the master token's read lock.
         * @see #releaseMasterToken(MasterToken)
         */
        getNewestMasterToken: function getNewestMasterToken(service, ctx, timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // Get the newest master token. If there is none then immediately
                // return.
                var store = ctx.getMslStore();
                var masterToken = store.getMasterToken();
                if (!masterToken) return null;

                // Acquire the master token read lock, creating it if necessary.
                var key = new MslContextMasterTokenKey(ctx, masterToken).uniqueKey();
                var rwlock = this._masterTokenLocks[key];
                if (!rwlock) {
                    rwlock = new ReadWriteLock();
                    this._masterTokenLocks[key] = rwlock;
                }
                var ticket = rwlock.readLock(timeout, {
                    result: function(ticket) {
                        InterruptibleExecutor(callback, function() {
                            // If aborted throw an exception.
                            if (ticket === undefined)
                                throw new MslInterruptedException('getNewestMasterToken aborted.');

                            // Now we have to be tricky and make sure the master token we just
                            // acquired is still the newest master token. This is necessary
                            // just in case the master token was deleted between grabbing it
                            // from the MSL store and acquiring the read lock.
                            var newestMasterToken = store.getMasterToken();
                            if (masterToken.equals(newestMasterToken))
                                return new TokenTicket(masterToken, ticket);

                            // If the master tokens are not the same then release the read
                            // lock, acquire the write lock, and then delete the master token
                            // lock (it may already be deleted). Then try again.
                            rwlock.unlock(ticket);
                            rwlock.writeLock(timeout, {
                                result: function(writeTicket) {
                                    InterruptibleExecutor(callback, function() {
                                        // If aborted throw an exception.
                                        if (writeTicket === undefined)
                                            throw new MslInterruptedException('getNewestMasterToken aborted.');

                                        delete this._masterTokenLocks[key];
                                        rwlock.unlock(writeTicket);
                                        return this.getNewestMasterToken(service, ctx, timeout, callback);
                                    }, self);
                                },
                                timeout: callback.timeout,
                                error: callback.error,
                            });
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
                service.setAbort(function() {
                    if (ticket) {
                        rwlock.cancel(ticket);
                        ticket = undefined;
                    }
                });
            }, self);
        },

        /**
         * Deletes the provided master token from the MSL store. Doing so requires
         * acquiring the master token's write lock.
         *
         * @param {MslContext} ctx MSL context.
         * @param {?MasterToken} masterToken master token to delete. May be null.
         * @throws InterruptedException if the thread is interrupted while trying
         *         to acquire the master token's write lock.
         */
        deleteMasterToken: function deleteMasterToken(ctx, masterToken) {
            // Do nothing if the master token is null.
            if (!masterToken)
                return;

            // Separately, acquire the write lock and delete the master token
            // from the store. We must do this 'later' because the write lock
            // cannot be acquired until the read lock is released and we are
            // currently holding it.
            //
            // The timeout will be clamped.
            var self = this;
            setTimeout(function() {
                var key = new MslContextMasterTokenKey(ctx, masterToken).uniqueKey();
                var rwlock = self._masterTokenLocks[key];
                if (!rwlock) {
                    rwlock = new ReadWriteLock();
                    self._masterTokenLocks[key] = rwlock;
                }
                // No need to register an abort function with the calling
                // service as this occurs independently.
                rwlock.writeLock(-1, {
                    result: function(ticket) {
                        ctx.getMslStore().removeCryptoContext(masterToken);
                        // It should be okay to delete this read/write lock because no
                        // one should be using the deleted master token anymore; a new
                        // master token would have been received before deleting the
                        // old one.
                        delete self._masterTokenLocks[key];
                        rwlock.unlock(ticket);
                    },
                    timeout: function() { throw new MslInternalException("Unexpected timeout received."); },
                    error: function(e) { throw e; }
                });
            }, 0);
        },

        /**
         * Release the read lock of the provided master token. If no master token
         * is provided then this method is a no-op.
         *
         * @param {MslContext} ctx MSL context.
         * @param {?TokenTicket} tokenTicket the
         *        master token (which may be null) and lock ticket.
         * @see #getNewestMasterToken(MslContext)
         */
        releaseMasterToken: function releaseMasterToken(ctx, tokenTicket) {
            if (tokenTicket && tokenTicket.masterToken) {
                var masterToken = tokenTicket.masterToken;
                var key = new MslContextMasterTokenKey(ctx, masterToken).uniqueKey();
                var rwlock = this._masterTokenLocks[key];

                // The lock may be null if the master token was deleted.
                if (rwlock)
                    rwlock.unlock(tokenTicket.ticket);
            }
        },

        /**
         * Update the MSL store crypto contexts with the crypto contexts of the
         * message being sent. Only crypto contexts for master tokens used by the
         * local entity for message authentication are saved.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageHeader} messageHeader outgoing message header.
         * @param {KeyExchangeData} keyExchangeData outgoing message key exchange
         *        data.
         * @throws InterruptedException if the thread is interrupted while trying
         *         to delete an old master token.
         */
        updateOutgoingCryptoContexts: function updateOutgoingCryptoContexts(ctx, messageHeader, keyExchangeData) {
            // In trusted network mode save the crypto context of the message's key
            // response data as an optimization.
            var store = ctx.getMslStore();
            if (!ctx.isPeerToPeer() && keyExchangeData) {
                var keyResponseData = keyExchangeData.keyResponseData;
                var keyxCryptoContext = keyExchangeData.cryptoContext;
                var keyxMasterToken = keyResponseData.masterToken;
                store.setCryptoContext(keyxMasterToken, keyxCryptoContext);

                // Delete the old master token. Even if we receive future messages
                // with this master token we can reconstruct the crypto context.
                this.deleteMasterToken(ctx, messageHeader.masterToken);
            }
        },

        /**
         * Update the MSL store crypto contexts with the crypto contexts provided
         * by received message.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageHeader} request previous message the response was received for.
         * @param {MessageInputStream} response received message input stream.
         * @throws InterruptedException if the thread is interrupted while trying
         *         to delete an old master token.
         */
        updateIncomingCryptoContexts: function updateIncomingCryptoContexts(ctx, request, response) {
            // Do nothing for error messages.
            var messageHeader = response.getMessageHeader();
            if (!messageHeader)
                return;
            
            // Save the crypto context of the message's key response data.
            var store = ctx.getMslStore();
            var keyResponseData = messageHeader.keyResponseData;
            if (keyResponseData) {
                var keyxMasterToken = keyResponseData.masterToken;
                store.setCryptoContext(keyxMasterToken, response.getKeyExchangeCryptoContext());

                // Delete the old master token. We won't use it anymore to build
                // messages.
                this.deleteMasterToken(ctx, request.masterToken);
            }
        },

        /**
         * Update the MSL store by removing any service tokens marked for deletion
         * and adding/replacing any other service tokens contained in the message
         * header.
         *
         * @param {MslContext} ctx MSL context.
         * @param {?MasterToken} masterToken master for the service tokens.
         * @param {?UserIdToken} userIdToken user ID token for the service tokens.
         * @param {Array.<ServiceToken>} serviceTokens the service tokens to update.
         * @throws MslException if a token cannot be removed or added/replaced
         *         because of a master token or user ID token mismatch.
         */
        storeServiceTokens: function storeServiceTokens(ctx, masterToken, userIdToken, serviceTokens) {
            // Remove deleted service tokens from the store. Update stored
            // service tokens.
            var store = ctx.getMslStore();
            var storeTokens = [];
            for (var i = 0; i < serviceTokens.length; ++i) {
                var token = serviceTokens[i];

                // Skip service tokens that are bound to a master token if the
                // local entity issued the master token.
                if (token.isBoundTo(masterToken) && masterToken.isVerified())
                    continue;
                var data = token.data;
                if (data && data.length == 0)
                    store.removeServiceTokens(token.name, token.isMasterTokenBound() ? masterToken : null, token.isUserIdTokenBound() ? userIdToken : null);
                else
                    storeTokens.push(token);
            }
            if (storeTokens.length > 0)
                store.addServiceTokens(storeTokens);
        },

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
         * @param {ReceiveService|RespondService|RequestService} service the calling service.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {number} lock acquisition timeout in milliseconds.
         * @param {{result: function({builder: MessageBuilder, tokenTicket: ?TokenTicket}),
         *         timeout: function(), error: function(Error)}} callback the
         *        callback that will receive the message builder and master
         *        token / lock ticket, notification of a timeout, and any
         *        thrown exceptions.
         * @throws InterruptedException if the thread is interrupted while trying
         *         to acquire the master token's read lock.
         */
        buildRequest: function buildRequest(service, ctx, msgCtx, timeout, callback) {
            var self = this;

            // Grab the newest master token.
            this.getNewestMasterToken(service, ctx, timeout, {
                result: function(tokenTicket) {
                    AsyncExecutor(callback, function() {
                        try {
                            var masterToken = (tokenTicket && tokenTicket.masterToken);
                            var userIdToken;
                            if (masterToken) {
                                // Grab the user ID token for the message's user. It may not be bound
                                // to the newest master token if the newest master token invalidated
                                // it.
                                var userId = msgCtx.getUserId();
                                var store = ctx.getMslStore();
                                var storedUserIdToken = (userId) ? store.getUserIdToken(userId) : null;
                                userIdToken = (storedUserIdToken && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                            } else {
                                userIdToken = null;
                            }
    
                            this._messageFactory.createRequest(ctx, masterToken, userIdToken, null, {
                                result: function(builder) {
                                    AsyncExecutor(callback, function() {
                                        builder.setNonReplayable(msgCtx.isNonReplayable());
                                        return {
                                            builder: builder,
                                            tokenTicket: tokenTicket
                                        };
                                    });
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        // Release the master token lock.
                                        this.releaseMasterToken(ctx, tokenTicket);
                                        if (e instanceof MslException)
                                            e = new MslInternalException("User ID token not bound to master token despite internal check.", e);
                                        throw e;
                                    }, self);
                                }
                            });
                        } catch (e) {
                            // Release the master token lock.
                            this.releaseMasterToken(ctx, tokenTicket);
                        }
                    }, self);
                },
                timeout: callback.timeout,
                error: callback.error,
            });
        },

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
         * @param {ReceiveService|RespondService|RequestService} service the calling service.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {MessageHeader} request message header to respond to.
         * @param {number} lock acquisition timeout in milliseconds.
         * @param {{result: function({builder: MessageBuilder, tokenTicket: ?TokenTicket}),
         *         timeout: function(), error: function(Error)}} callback the
         *        callback that will receive the message builder and master
         *        token / lock ticket, notification of a timeout, and any
         *        thrown exceptions.
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
        buildResponse: function buildResponse(service, ctx, msgCtx, request, timeout, callback) {
            var self = this;

            // Create the response.
            this._messageFactory.createResponse(ctx, request, {
                result: function(builder) {
                    InterruptibleExecutor(callback, function() {
                        builder.setNonReplayable(msgCtx.isNonReplayable());

                        // Trusted network clients should use the newest master token. Trusted
                        // network servers must not use a newer master token. This method is
                        // only called by trusted network clients after a handshake response is
                        // received so if the request does not contain key response data then
                        // we know the local entity is a trusted network server and should
                        // return immediately.
                        if (!ctx.isPeerToPeer() && !request.keyResponseData) {
                            return { builder: builder, tokenTicket: null };
                        }

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
                        this.getNewestMasterToken(service, ctx, timeout, {
                            result: function(tokenTicket) {
                                InterruptibleExecutor(callback, function() {
                                    try {
                                        var masterToken = tokenTicket && tokenTicket.masterToken;
                                        var userIdToken;
                                        if (masterToken) {
                                            // Grab the user ID token for the message's user. It may not be
                                            // bound to the newest master token if the newest master token
                                            // invalidated it.
                                            var userId = msgCtx.getUserId();
                                            var store = ctx.getMslStore();
                                            var storedUserIdToken = (userId) ? store.getUserIdToken(userId) : null;
                                            userIdToken = (storedUserIdToken && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                                        } else {
                                            userIdToken = null;
                                        }
    
                                        // Set the authentication tokens.
                                        builder.setAuthTokens(masterToken, userIdToken);
                                        return { builder: builder, tokenTicket: tokenTicket };
                                    } catch (e) {
                                        // Release the master token lock.
                                        this.releaseMasterToken(ctx, tokenTicket);
                                    }
                                }, self);
                            },
                            timeout: callback.timeout,
                            error: callback.error,
                        });
                    }, self);
                },
                error: callback.error,
            });
        },
        
        /**
         * <p>Create a new message builder that will craft a new message based on
         * another message. The constructed message will have a randomly assigned
         * message ID, thus detaching it from the message being responded to, and
         * may be used as a request.</p>
         * 
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {MessageHeader} request message header to respond to.
         * @param {{result: function({builder: MessageBuilder, tokenTicket: ?TokenTicket}),
         *         timeout: function(), error: function(Error)}} callback the
         *        callback that will receive the message builder and null for
         *        the master token / lock ticket, notification of a timeout,
         *        and any thrown exceptions.
         * @throws MslCryptoException if there is an error accessing the remote
         *         entity identity.
         * @throws MslException if any of the request's user ID tokens is not bound
         *         to its master token.
         */
        buildDetachedResponse: function buildDetachedResponse(ctx, msgCtx, request, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                // Create an idempotent response. Assign a random message ID.
                MessageBuilder.createIdempotentResponse(ctx, request, {
                    result: function(builder) {
                        AsyncExecutor(callback, function() {
                            builder.setNonReplayable(msgCtx.isNonReplayable());
                            builder.setMessageId(MslUtils.getRandomLong(ctx));
                            return { builder: builder, tokenTicket: null };
                        }, self);
                    },
                    error: callback.error,
                });
            }, self);
        },

        /**
         * Creates a message builder and message context appropriate for re-sending
         * the original message in response to the received error.
         *
         * @param {ReceiveService|RespondService|RequestService} service the calling service.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {SendResult} sent result of original sent message.
         * @param {ErrorHeader} errorHeader received error header.
         * @param {number} lock acquisition timeout in milliseconds.
         * @param {{result: function({errorResult: ErrorResult, tokenTicket: ?TokenTicket}),
         *         timeout: function(), error: function(Error)}} callback the
         *        callback that will receive the message builder and message
         *        context that should be used to re-send the original request
         *        in response to the received error and master token / lock
         *        ticket or null if the error cannot be handled (i.e. should be
         *        returned to the application), notification of a timeout, and
         *        any thrown exceptions.
         * @throws MslException if there is an error creating the message.
         * @throws InterruptedException if the thread is interrupted while trying
         *         to acquire the master token lock (user re-authentication only).
         */
        buildErrorResponse: function buildErrorResponse(service, ctx, msgCtx, sent, errorHeader, timeout, callback) {
            var self = this;

            function entityReauth(requestHeader, payloads) {
                InterruptibleExecutor(callback, function() {
                    // Resend the request without a master token or user ID token.
                    // Make sure the use the error header message ID + 1.
                    var messageId = MessageBuilder.incrementMessageId(errorHeader.messageId);
                    var resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                    this._messageFactory.createRequest(ctx, null, null, messageId, {
                        result: function(requestBuilder) {
                            InterruptibleExecutor(callback, function() {
                                if (ctx.isPeerToPeer()) {
                                    var peerMasterToken = requestHeader.peerMasterToken;
                                    var peerUserIdToken = requestHeader.peerUserIdToken;
                                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                                }
                                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                                return {
                                    errorResult: new ErrorResult(requestBuilder, resendMsgCtx),
                                    tokenTicket: null,
                                };
                            },self);
                        },
                        error: callback.error,
                    });
                }, self);
            }

            function userReauth(requestHeader, payloads) {
                // Grab the newest master token and its read lock.
                self.getNewestMasterToken(service, ctx, timeout, {
                    result: function(tokenTicket) {
                        InterruptibleExecutor(callback, function() {
                            // Resend the request without a user ID token.
                            // Make sure the use the error header message ID + 1.
                            var masterToken = tokenTicket && tokenTicket.masterToken;
                            var messageId = MessageBuilder.incrementMessageId(errorHeader.messageId);
                            var resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                            this._messageFactory.createRequest(ctx, masterToken, null, messageId, {
                                result: function(requestBuilder) {
                                    InterruptibleExecutor(callback, function() {
                                        if (ctx.isPeerToPeer()) {
                                            var peerMasterToken = requestHeader.peerMasterToken;
                                            var peerUserIdToken = requestHeader.peerUserIdToken;
                                            requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                                        }
                                        requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                                        return {
                                            errorResult: new ErrorResult(requestBuilder, resendMsgCtx),
                                            tokenTicket: tokenTicket
                                        };
                                    }, self);
                                },
                                error: callback.error,
                            });

                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }

            InterruptibleExecutor(callback, function() {
                // Handle the error.
                var requestHeader = sent.request.getMessageHeader();
                var payloads = sent.request.getPayloads();
                var errorCode = errorHeader.errorCode;
                var reauthCode;
                switch (errorCode) {
                    case MslConstants.ResponseCode.ENTITYDATA_REAUTH:
                    case MslConstants.ResponseCode.ENTITY_REAUTH:
                    {
                        // If the MSL context cannot provide new entity authentication
                        // data then return null. This function should never return
                        // null.
                        reauthCode = errorCode;
                        ctx.getEntityAuthenticationData(reauthCode, {
                            result: function(entityAuthData) {
                                InterruptibleExecutor(callback, function() {
                                    if (!entityAuthData)
                                        return null;

                                    // Otherwise we have now triggered the need for new entity
                                    // authentication data. Fall through.
                                    entityReauth(requestHeader, payloads);
                                }, self);
                            },
                            error: callback.error,
                        });
                        return;
                    }
                    case MslConstants.ResponseCode.USERDATA_REAUTH:
                    case MslConstants.ResponseCode.SSOTOKEN_REJECTED:
                    {
                        // If the message context cannot provide user authentication
                        // data then return null.
                        reauthCode = errorCode;
                        msgCtx.getUserAuthData(reauthCode, false, true, {
                            result: function(userAuthData) {
                                InterruptibleExecutor(callback, function() {
                                    if (!userAuthData)
                                        return null;

                                    // Otherwise we have now triggered the need for new user
                                    // authentication data. Fall through.
                                    userReauth(requestHeader, payloads);
                                }, self);
                            },
                            error: callback.error,
                        });
                        return;
                    }
                    case MslConstants.ResponseCode.USER_REAUTH:
                    {
                        userReauth(requestHeader, payloads);
                        return;
                    }
                    case MslConstants.ResponseCode.KEYX_REQUIRED:
                    {
                        // This error will only be received by trusted network clients
                        // and peer-to-peer entities that do not have a master token.
                        // Make sure the use the error header message ID + 1.
                        var messageId = MessageBuilder.incrementMessageId(errorHeader.messageId);
                        var resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                        this._messageFactory.createRequest(ctx, null, null, messageId, {
                            result: function(requestBuilder) {
                                InterruptibleExecutor(callback, function() {
                                    if (ctx.isPeerToPeer()) {
                                        var peerMasterToken = requestHeader.peerMasterToken;
                                        var peerUserIdToken = requestHeader.peerUserIdToken;
                                        requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                                    }
                                    // Mark the message as renewable to make sure the response can
                                    // be encrypted. During renewal lock acquisition we will either
                                    // block until we acquire the renewal lock or receive a master
                                    // token.
                                    requestBuilder.setRenewable(true);
                                    requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                                    return {
                                        errorResult: new ErrorResult(requestBuilder, resendMsgCtx),
                                        tokenTicket: null,
                                    };
                                }, self);
                            },
                            error: callback.error,
                        });
                        return;
                    }
                    case MslConstants.ResponseCode.EXPIRED:
                    {
                        // Grab the newest master token and its read lock.
                        this.getNewestMasterToken(service, ctx, timeout, {
                            result: function(tokenTicket) {
                                InterruptibleExecutor(callback, function() {
                                    var masterToken = (tokenTicket && tokenTicket.masterToken);
                                    var userIdToken;
                                    if (masterToken) {
                                        // Grab the user ID token for the message's user. It may not be bound
                                        // to the newest master token if the newest master token invalidated
                                        // it.
                                        var userId = msgCtx.getUserId();
                                        var store = ctx.getMslStore();
                                        var storedUserIdToken = (userId) ? store.getUserIdToken(userId) : null;
                                        userIdToken = (storedUserIdToken && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                                    } else {
                                        userIdToken = null;
                                    }

                                    // Resend the request.
                                    var messageId = MessageBuilder.incrementMessageId(errorHeader.messageId);
                                    var resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                                    this._messageFactory.createRequest(ctx, masterToken, userIdToken, messageId, {
                                        result: function(requestBuilder) {
                                            InterruptibleExecutor(callback, function() {
                                                if (ctx.isPeerToPeer()) {
                                                    var peerMasterToken = requestHeader.peerMasterToken;
                                                    var peerUserIdToken = requestHeader.peerUserIdToken;
                                                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                                                }
                                                // If the newest master token is equal to the previous
                                                // request's master token then mark this message as renewable.
                                                // During renewal lock acquisition we will either block until
                                                // we acquire the renewal lock or receive a master token.
                                                //
                                                // Check for a missing master token in case the error is incorrect
                                                var requestMasterToken = requestHeader.masterToken;
                                                if (!requestMasterToken || requestMasterToken.equals(masterToken))
                                                    requestBuilder.setRenewable(true);
                                                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                                                return {
                                                    errorResult: new ErrorResult(requestBuilder, resendMsgCtx),
                                                    tokenTicket: tokenTicket
                                                };
                                            }, self);
                                        },
                                        error: callback.error,
                                    }, self);
                                }, self);
                            },
                            timeout: callback.timeout,
                            error: callback.error,
                        });
                        return;
                    }
                    case MslConstants.ResponseCode.REPLAYED:
                    {
                        // This error will be received if the previous request's non-
                        // replayable ID is not accepted by the remote entity. In this
                        // situation simply try again.
                        //
                        // Grab the newest master token and its read lock.
                        this.getNewestMasterToken(service, ctx, timeout, {
                            result: function(tokenTicket) {
                                InterruptibleExecutor(callback, function() {
                                    var masterToken = (tokenTicket && tokenTicket.masterToken);
                                    var userIdToken;
                                    if (masterToken) {
                                        // Grab the user ID token for the message's user. It may not be bound
                                        // to the newest master token if the newest master token invalidated
                                        // it.
                                        var userId = msgCtx.getUserId();
                                        var store = ctx.getMslStore();
                                        var storedUserIdToken = (userId) ? store.getUserIdToken(userId) : null;
                                        userIdToken = (storedUserIdToken && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                                    } else {
                                        userIdToken = null;
                                    }

                                    // Resend the request.
                                    var messageId = MessageBuilder.incrementMessageId(errorHeader.messageId);
                                    var resendMsgCtx = new ResendMessageContext(payloads, msgCtx);
                                    this._messageFactory.createRequest(ctx, masterToken, userIdToken, messageId, {
                                        result: function(requestBuilder) {
                                            InterruptibleExecutor(callback, function() {
                                                if (ctx.isPeerToPeer()) {
                                                    var peerMasterToken = requestHeader.peerMasterToken;
                                                    var peerUserIdToken = requestHeader.peerUserIdToken;
                                                    requestBuilder.setPeerAuthTokens(peerMasterToken, peerUserIdToken);
                                                }

                                                // Mark the message as replayable or not as dictated by the
                                                // message context.
                                                requestBuilder.setNonReplayable(resendMsgCtx.isNonReplayable());
                                                return {
                                                    errorResult: new ErrorResult(requestBuilder, resendMsgCtx),
                                                    tokenTicket: tokenTicket
                                                };
                                            }, self);
                                        },
                                        error: callback.error,
                                    });
                                }, self);
                            },
                            timeout: callback.timeout,
                            error: callback.error,
                        });
                        return;
                    }
                    default:
                        // Nothing to do. Return null.
                        return null;
                }
            }, self);
        },

        /**
         * Called after successfully handling an error message to delete the old
         * invalid crypto contexts and bound service tokens associated with the
         * invalid master token or user ID token.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageHeader} requestHeader initial request that generated the error.
         * @param {ErrorHeader} errorHeader error response received and successfully handled.
         * @throws MslException if the user ID token is not bound to the master
         *         token. (This should not happen.)
         * @throws InterruptedException if the thread is interrupted while trying
         *         to delete the old master token.
         */
        cleanupContext: function cleanupContext(ctx, requestHeader, errorHeader) {
        	// The data-reauth error codes also delete tokens in case those errors
        	// are returned when a token does exist.
            switch (errorHeader.errorCode) {
	            case MslConstants.ResponseCode.ENTITY_REAUTH:
	            case MslConstants.ResponseCode.ENTITYDATA_REAUTH:
	            {
	                // The old master token is invalid. Delete the old
	                // crypto context and any bound service tokens.
	                this.deleteMasterToken(ctx, requestHeader.masterToken);
	                break;
	            }
	            case MslConstants.ResponseCode.USER_REAUTH:
	            case MslConstants.ResponseCode.USERDATA_REAUTH:
	            {
	                // The old user ID token is invalid. Delete the old user ID
	                // token and any bound service tokens. It is okay to stomp on
	                // other requests when doing this because automatically
	                // generated messages and replies to outstanding requests that
	                // use the user ID token and service tokens will work fine.
	                //
	                // This will be a no-op if we received a new user ID token that
	                // overwrote the old one.
	                var masterToken = requestHeader.masterToken;
	                var userIdToken = requestHeader.userIdToken;
	                if (masterToken && userIdToken) {
	                    var store = ctx.getMslStore();
	                    store.removeUserIdToken(userIdToken);
	                }
	                break;
	            }
	            default:
	                // No cleanup required.
            }
        },

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
         * @param {ReceiveService|RespondService|RequestService} service the calling service.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {OutputStream} out remote entity output stream.
         * @param {MessageBuilder} builder message builder.
         * @param {boolean} closeDestination true if the remote entity output stream must
         *        be closed when the constructed message output stream is closed.
         * @param {number} timeout send timeout in milliseconds.
         * @param {{result: function(SendResult), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive a result containing
         *        the sent message header and a copy of the application data,
         *        notification of a timeout, or any thrown exceptions.
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
         * @throws MslException if there was an error updating the service tokens
         *         or building the message header.
         * @throws InterruptedException if the thread is interrupted while trying
         *         to delete an old master token the sent message is replacing.
         */
        send: function send(service, ctx, msgCtx, out, builder, closeDestination, timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                var masterToken = builder.getMasterToken();
                var userIdToken = builder.getUserIdToken();

                // Ask the message context for user authentication data.
                var userAuthDataDelayed = false;
                var userId = msgCtx.getUserId();
                if (userId) {
                    // If we are not including a user ID token, the user authentication
                    // data is required.
                    var required = (!userIdToken);
                    msgCtx.getUserAuthData(null, builder.isRenewable(), required, {
                        result: function(userAuthData) {
                            InterruptibleExecutor(callback, function() {
                                if (userAuthData) {
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

                                    // Fall through to attach the user.
                                }

                                // If user authentication data is required but was not provided
                                // then this message may be associated with a user but not have any
                                // user authentication data. For example upon user creation.

                                // Everything is okay so continue.
                                attachUser(masterToken, userIdToken, userAuthDataDelayed);
                            }, self);
                        },
                        error: callback.error,
                    });
                } else {
                    attachUser(masterToken, userIdToken, userAuthDataDelayed);
                }
            }, self);

            function attachUser(masterToken, userIdToken, userAuthDataDelayed) {
                InterruptibleExecutor(callback, function() {
                    var peerUserIdToken = builder.getPeerUserIdToken();

                    // If there is no user ID token for the remote user then check if a
                    // user ID token should be created and attached.
                    if (!ctx.isPeerToPeer() && !userIdToken ||
                        ctx.isPeerToPeer() && !peerUserIdToken)
                    {
                        var user = msgCtx.getUser();
                        if (user) {
                            builder.setUser(user, {
                                result: function(complete) {
                                    InterruptibleExecutor(callback, function() {
                                        // The user ID token may have changed and we need the latest one to
                                        // store the service tokens below.
                                        userIdToken = builder.getUserIdToken();
                                        prepare(masterToken, userIdToken, userAuthDataDelayed);
                                    }, self);
                                },
                                error: callback.error,
                            });
                        } else {
                            prepare(masterToken, userIdToken, userAuthDataDelayed);
                        }
                    } else {
                        prepare(masterToken, userIdToken, userAuthDataDelayed);
                    }
                }, self);
            }

            function prepare(masterToken, userIdToken, userAuthDataDelayed) {
                InterruptibleExecutor(callback, function() {
                    // If we have not delayed the user authentication data, and the message
                    // payloads either do not need to be encrypted or can be encrypted with
                    // this message, and the message payloads either do not need to be
                    // integrity protected or can be integrity protected with this message,
                    // and the message is either replayable or the message will be sent non-
                    // replayable and has a master token, then we can write the application
                    // data now.
                    var writeData = !userAuthDataDelayed &&
                        (!msgCtx.isEncrypted() || builder.willEncryptPayloads()) &&
                        (!msgCtx.isIntegrityProtected() || builder.willIntegrityProtectPayloads()) &&
                        (!msgCtx.isNonReplayable() || (builder.isNonReplayable() && masterToken));
                    var handshake = !writeData;

                    // Set the message handshake flag.
                    builder.setHandshake(handshake);

                    // If this message is renewable...
                    var keyRequests = [];
                    if (builder.isRenewable()) {
                        // Ask for key request data if we are using entity authentication
                        // data or if the master token needs renewing or if the message is
                        // non-replayable.
                        var now = ctx.getRemoteTime();
                        if (!masterToken || masterToken.isRenewable(now) || msgCtx.isNonReplayable()) {
                            msgCtx.getKeyRequestData({
                                result: function(requests) {
                                    InterruptibleExecutor(callback, function() {
                                        for (var i = 0; i < requests.length; ++i) {
                                            var request = requests[i];
                                            keyRequests.push(request);
                                            builder.addKeyRequestData(request);
                                        }
                                        perform(masterToken, userIdToken, handshake, keyRequests);
                                    }, self);
                                },
                                error: callback.error,
                            });
                            return;
                        }
                    }
                    perform(masterToken, userIdToken, handshake, keyRequests);
                }, self);
            }

            function perform(masterToken, userIdToken, handshake, keyRequests) {
                InterruptibleExecutor(callback, function() {
                    // Ask the caller to perform any final modifications to the
                    // message and then build the message.
                    var serviceTokenBuilder = new MessageServiceTokenBuilder(ctx, msgCtx, builder);
                    msgCtx.updateServiceTokens(serviceTokenBuilder, handshake, {
                        result: function(success) {
                            builder.getHeader({
                                result: function(requestHeader) {
                                    InterruptibleExecutor(callback, function() {
                                        // Deliver the header that will be sent to the debug context.
                                        var debugCtx = msgCtx.getDebugContext();
                                        if (debugCtx) debugCtx.sentHeader(requestHeader);

                                        // Update the stored crypto contexts just before sending the
                                        // message so we can receive new messages immediately after it is
                                        // sent.
                                        var keyExchangeData = builder.getKeyExchangeData();
                                        this.updateOutgoingCryptoContexts(ctx, requestHeader, keyExchangeData);

                                        // Update the stored service tokens.
                                        var tokenVerificationMasterToken = (keyExchangeData) ? keyExchangeData.keyResponseData.masterToken : masterToken;
                                        var serviceTokens = requestHeader.serviceTokens;
                                        this.storeServiceTokens(ctx, tokenVerificationMasterToken, userIdToken, serviceTokens);

                                        // We will either use the header crypto context or the key exchange
                                        // data crypto context in trusted network mode to process the message
                                        // payloads.
                                        var payloadCryptoContext;
                                        if (!ctx.isPeerToPeer() && keyExchangeData)
                                            payloadCryptoContext = keyExchangeData.cryptoContext;
                                        else
                                            payloadCryptoContext = requestHeader.cryptoContext;

                                        // Stop and throw an exception if aborted.
                                        if (service.isAborted())
                                            throw new MslInterruptedException('send aborted.');

                                        // Send the request.
                                        var os = (this._filterFactory != null) ? this._filterFactory.getOutputStream(out) : out;
                                        this._messageFactory.createOutputStream(ctx, os, requestHeader, payloadCryptoContext, null, timeout, {
                                            result: function(request) {
                                                InterruptibleExecutor(callback, function() {
                                                    // Register abort function.
                                                    service.setAbort(function() { request.abort(); });
                                                    request.closeDestination(closeDestination);
                                                    
                                                    // Wait until the output stream is ready.
                                                    request.isReady({
                                                        result: function(ready) {
                                                            InterruptibleExecutor(callback, function() {
                                                                // If aborted throw an exception.
                                                                if (!ready)
                                                                    throw new MslInterruptedException('MessageOutputStream aborted.');
                                                                write(request, handshake);
                                                            }, self);
                                                        },
                                                        timeout: callback.timeout,
                                                        error: callback.error,
                                                    });
                                                }, self);
                                            },
                                            timeout: callback.timeout,
                                            error: callback.error,
                                        });
                                    }, self);
                                },
                                timeout: callback.timeout,
                                error: callback.error,
                            });
                        },
                        error: callback.error,
                    });
                }, self);
            }

            function write(request, handshake) {
                // If it is okay to write the data then ask the application to write it
                // and return the real output stream. Otherwise it will be asked to do
                // so after the handshake is completed.
                if (!handshake) {
                    msgCtx.write(request, timeout, {
                        result: function(success) {
                            InterruptibleExecutor(callback, function() {
                                // If aborted throw an exception.
                                if (service.isAborted())
                                    throw new MslInterruptedException('MessageOutputStream write aborted.');

                                return new SendResult(request, handshake);
                            }, self);
                        },
                        timeout: callback.timeout,
                        error: callback.error,
                    });
                } else {
                    InterruptibleExecutor(callback, function() {
                        return new SendResult(request, handshake);
                    }, self);
                }
            }
        },

        /**
         * <p>Receive a message.</p>
         *
         * <p>If a message is received the stored master tokens, crypto contexts,
         * user ID tokens, and service tokens will be updated.</p>
         *
         * @param {ReceiveService|RespondService|RequestService} service calling service.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {MessageHeader} request message header of the previously sent message, if any,
         *        the received message is responding to. May be null.
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
         *        callback the callback returned the received message, timeouts,
         *        or any thrown exceptions.
         * @throws IOException if there is a problem reading from the input stream.
         * @throws MslEncodingException if there is an error parsing the message.
         * @throws MslCryptoException if there is an error decrypting or verifying
         *         the header or creating the message payload crypto context.
         * @throws MslEntityAuthException if unable to create the entity
         *         authentication data.
         * @throws MslUserAuthException if unable to create the user authentication
         *         data.
         * @throws MslMessageException if the message master token is expired and
         *         the message is not renewable.
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
        receive: function receive(service, ctx, msgCtx, input, request, timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                // Stop and throw an exception if aborted.
                if (service.isAborted())
                    throw new MslInterruptedException('receive aborted.');

                // Grab the response.
                var keyRequestData = [];
                if (request)
                    keyRequestData = request.keyRequestData.filter(function() { return true; });
                var cryptoContexts = msgCtx.getCryptoContexts();
                var is = (this._filterFactory) ? this._filterFactory.getInputStream(input) : input;
                this._messageFactory.createInputStream(ctx, is, keyRequestData, cryptoContexts, timeout, {
                    result: function(response) {
                        InterruptibleExecutor(callback, function() {
                            // Register abort function.
                            service.setAbort(function() { response.abort(); });

                            // Wait until the input stream is ready.
                            response.isReady({
                                result: function(ready) {
                                    InterruptibleExecutor(callback, function() {
                                        // If aborted throw an exception.
                                        if (!ready)
                                            throw new MslInterruptedException('MessageInputStream aborted.');
                                        process(response);
                                    }, self);
                                },
                                timeout: callback.timeout,
                                error: callback.error,
                            });
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
            
            function process(response) {
                InterruptibleExecutor(callback, function() {
                    // Deliver the received header to the debug context.
                    var responseHeader = response.getMessageHeader();
                    var errorHeader = response.getErrorHeader();
                    var debugCtx = msgCtx.getDebugContext();
                    if (debugCtx) debugCtx.receivedHeader((responseHeader) ? responseHeader : errorHeader);

                    // Pull the response master token or entity authentication data and
                    // user ID token or user authentication data to attach them to any
                    // thrown exceptions.
                    var masterToken, entityAuthData, userIdToken, userAuthData;
                    if (responseHeader) {
                        masterToken = responseHeader.masterToken;
                        entityAuthData = responseHeader.entityAuthenticationData;
                        userIdToken = responseHeader.userIdToken;
                        userAuthData = responseHeader.userAuthenticationData;
                    } else {
                        masterToken = null;
                        entityAuthData = errorHeader.entityAuthenticationData;
                        userIdToken = null;
                        userAuthData = null;
                    }

                    // If there is a request, make sure the response message ID equals the
                    // request message ID + 1.
                    if (request) {
                        // Only enforce this for message headers and error headers that are
                        // not entity re-authenticate or entity data re-authenticate (as in
                        // those cases the remote entity is not always able to extract the
                        // request message ID).
                        var errorCode = (errorHeader) ? errorHeader.errorCode : null;
                        if (responseHeader ||
                            (errorCode != MslConstants.ResponseCode.FAIL && errorCode != MslConstants.ResponseCode.TRANSIENT_FAILURE && errorCode != MslConstants.ResponseCode.ENTITY_REAUTH && errorCode != MslConstants.ResponseCode.ENTITYDATA_REAUTH))
                        {
                            var responseMessageId = (responseHeader) ? responseHeader.messageId : errorHeader.messageId;
                            var expectedMessageId = MessageBuilder.incrementMessageId(request.messageId);
                            if (responseMessageId != expectedMessageId) {
                                throw new MslMessageException(MslError.UNEXPECTED_RESPONSE_MESSAGE_ID, "expected " + expectedMessageId + "; received " + responseMessageId)
                                .setMasterToken(masterToken)
                                .setEntityAuthenticationData(entityAuthData)
                                .setUserIdToken(userIdToken)
                                .setUserAuthenticationData(userAuthData);
                            }
                        }
                    }

                    try {
                        // Verify expected identity if specified.
                        var expectedIdentity = msgCtx.getRemoteEntityIdentity();
                        if (expectedIdentity) {
                            // Reject if the remote entity identity is not equal to the
                            // message entity authentication data identity.
                            if (entityAuthData) {
                                var entityAuthIdentity = entityAuthData.getIdentity();
                                if (entityAuthIdentity && expectedIdentity != entityAuthIdentity)
                                    throw new MslMessageException(MslError.MESSAGE_SENDER_MISMATCH, "expected " + expectedIdentity + "; received " + entityAuthIdentity);
                            }

                            // Reject if in peer-to-peer mode and the message sender does
                            // not match.
                            if (ctx.isPeerToPeer()) {
                                var sender = response.getIdentity();
                                if (sender && expectedIdentity != sender)
                                    throw new MslMessageException(MslError.MESSAGE_SENDER_MISMATCH, "expected " + expectedIdentity + "; received " + sender);
                            }
                        }

                        // Process the response.
                        if (responseHeader) {
                            // If there is a request update the stored crypto contexts.
                            if (request)
                                this.updateIncomingCryptoContexts(ctx, request, response);

                            // In trusted network mode the local tokens are the primary tokens.
                            // In peer-to-peer mode they are the peer tokens. The master token
                            // might be in the key response data.
                            var keyResponseData = responseHeader.keyResponseData;
                            var tokenVerificationMasterToken;
                            var localUserIdToken;
                            var serviceTokens;
                            if (!ctx.isPeerToPeer()) {
                                tokenVerificationMasterToken = (keyResponseData) ? keyResponseData.masterToken : responseHeader.masterToken;
                                localUserIdToken = responseHeader.userIdToken;
                                serviceTokens = responseHeader.serviceTokens;
                            } else {
                                tokenVerificationMasterToken = (keyResponseData) ? keyResponseData.masterToken : responseHeader.peerMasterToken;
                                localUserIdToken = responseHeader.peerUserIdToken;
                                serviceTokens = responseHeader.peerServiceTokens;
                            }

                            // Save any returned user ID token if the local entity is not the
                            // issuer of the user ID token.
                            var userId = msgCtx.getUserId();
                            if (userId && localUserIdToken && !localUserIdToken.isVerified())
                                ctx.getMslStore().addUserIdToken(userId, localUserIdToken);

                            // Update the stored service tokens.
                            this.storeServiceTokens(ctx, tokenVerificationMasterToken, localUserIdToken, serviceTokens);
                        }

                        // Update the synchronized clock if we are a trusted network client
                        // (there is a request) or peer-to-peer entity.
                        var timestamp = (responseHeader) ? responseHeader.timestamp : errorHeader.timestamp;
                        if (timestamp && (request || ctx.isPeerToPeer()))
                            ctx.updateRemoteTime(timestamp);
                    } catch (e) {
                        if (e instanceof MslException) {
                            e.setMasterToken(masterToken);
                            e.setEntityAuthenticationData(entityAuthData);
                            e.setUserIdToken(userIdToken);
                            e.setUserAuthenticationData(userAuthData);
                        }
                        throw e;
                    }

                    // Return the result.
                    return response;
                }, self);
            }
        },

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
         * @param {ReceiveService|RespondService|RequestService} service the calling service.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {{builder: MessageBuilder, tokenTicket: ?TokenTicket}}
         *        builderTokenTicket request message builder and master token /
         *        lock ticket.
         * @param {Receive} receive indicates if a response should always be expected, should
         *        only be expected if the master token or user ID token will be
         *        renewed, or should never be expected. 
         * @param {boolean} closeStreams true if the remote entity input and output streams
         *        must be closed when the constructed message input and output
         *        streams are closed.
         * @param {number} timeout renewal lock acquisition timeout in milliseconds.
         * @param {{result: function(?SendReceiveResult), timeout: function(), error: function(Error)}}
         *        callback the callback will be given the received message or
         *        {@code null} if cancelled, notified of timeouts, or any
         *        thrown exceptions.
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
         */
        sendReceive: function sendReceive(service, ctx, msgCtx, input, output, builderTokenTicket, receive, closeStreams, timeout, callback) {
            var self = this;

            // Attempt to acquire the renewal lock.
            InterruptibleExecutor(callback, function() {
                // acquireRenewalLock() may change the master token, and in
                // that case will update the builderTokenTicket.tokenTicket
                // value.
                var renewalQueue = new BlockingQueue();
                this.acquireRenewalLock(service, ctx, msgCtx, renewalQueue, builderTokenTicket, timeout, {
                    result: function(renewing) {
                        sendrecv(builderTokenTicket, renewalQueue, renewing);
                    },
                    timeout: function() {
                        InterruptibleExecutor(callback, function() {
                            // Release the master token lock.
                            this.releaseMasterToken(ctx, builderTokenTicket.ticket);
                            callback.timeout();
                        }, self);
                    },
                    error: function(e) {
                        InterruptibleExecutor(callback, function() {
                            // Release the master token lock.
                            this.releaseMasterToken(ctx, builderTokenTicket.ticket);

                            // This should only be if we were cancelled so return null.
                            if (e instanceof MslInterruptedException) {
                                return null;
                            } else {
                                callback.error(e);
                            }
                        }, self);
                    }
                });
            }, self);

            // Send the request and receive the response.
            function sendrecv(builderTokenTicket, renewalQueue, renewing) {
                InterruptibleExecutor(callback, function sendrecv_send() {
                    var builder = builderTokenTicket.builder;
                    var tokenTicket = builderTokenTicket.tokenTicket;

                    // Send the request.
                    builder.setRenewable(renewing);
                    this.send(service, ctx, msgCtx, output, builder, closeStreams, timeout, {
                        result: function(sent) {
                            InterruptibleExecutor(callback, function sendrecv_receive() {
                                // Receive the response if expected, if we sent a handshake request,
                                // or if we expect a response when renewing tokens and either key
                                // request data was included or a master token and user
                                // authentication data was included in a renewable message.
                                var requestHeader = sent.request.getMessageHeader();
                                var keyRequestData = requestHeader.keyRequestData;
                                if (receive == Receive.ALWAYS || sent.handshake ||
                                    (receive == Receive.RENEWING &&
                                     (!keyRequestData.isEmpty() ||
                                      (requestHeader.isRenewable() && requestHeader.masterToken && requestHeader.userAuthenticationData))))
                                {
                                    this.receive(service, ctx, msgCtx, input, requestHeader, timeout, {
                                        result: function(response) {
                                            InterruptibleExecutor(callback, function() {
                                                // If we received an error response then cleanup.
                                                var errorHeader = response.getErrorHeader();
                                                if (errorHeader)
                                                    this.cleanupContext(ctx, requestHeader, errorHeader);

                                                // Release the renewal lock.
                                                if (renewing)
                                                    this.releaseRenewalLock(ctx, renewalQueue, response);

                                                // Release the master token lock.
                                                this.releaseMasterToken(ctx, tokenTicket);

                                                // Return the response.
                                                response.closeSource(closeStreams);
                                                return new SendReceiveResult(response, sent);
                                            }, self);
                                        },
                                        timeout: function() {
                                            InterruptibleExecutor(callback, function() {
                                                // Release the renewal lock.
                                                if (renewing)
                                                    this.releaseRenewalLock(ctx, renewalQueue, null);

                                                // Release the master token lock.
                                                this.releaseMasterToken(ctx, tokenTicket);

                                                callback.timeout();
                                            }, self);
                                        },
                                        error: function(e) {
                                            InterruptibleExecutor(callback, function() {
                                                // Release the renewal lock.
                                                if (renewing)
                                                    this.releaseRenewalLock(ctx, renewalQueue, null);

                                                // Release the master token lock.
                                                this.releaseMasterToken(ctx, tokenTicket);

                                                callback.error(e);
                                            }, self);
                                        }
                                    });
                                } else {
                                    InterruptibleExecutor(callback, function() {
                                        var response = null;

                                        // Release the renewal lock.
                                        if (renewing)
                                            this.releaseRenewalLock(ctx, renewalQueue, response);

                                        // Release the master token lock.
                                        this.releaseMasterToken(ctx, tokenTicket);

                                        // Return the response.
                                        return new SendReceiveResult(response, sent);
                                    }, self);
                                }
                            }, self);
                        },
                        timeout: function() {
                            InterruptibleExecutor(callback, function() {
                                // Release the renewal lock.
                                if (renewing)
                                    this.releaseRenewalLock(ctx, renewalQueue, null);

                                // Release the master token lock.
                                this.releaseMasterToken(ctx, tokenTicket);

                                callback.timeout();
                            }, self);
                        },
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                var response = null;

                                // Release the renewal lock.
                                if (renewing)
                                    this.releaseRenewalLock(ctx, renewalQueue, response);

                                // Release the master token lock.
                                this.releaseMasterToken(ctx, tokenTicket);

                                callback.error(e);
                            }, self);
                        }
                    });
                }, self);
            }
        },

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
         * @param {ReceiveService|RespondService|RequestService} service the calling service.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {BlockingQueue} queue caller's blocking queue.
         * @param {{builder: MessageBuilder, tokenTicket: ?TokenTicket}
         *        builderTokenTicket message builder and master token / lock
         *        ticket for the message to be sent.
         * @param {number} timeout timeout in milliseconds for acquiring the renewal lock
         *        or receiving a master token.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback will receive true if the renewal lock
         *        was acquired, false if the builder's message is now capable
         *        of encryption or the renewal lock is not needed, notified of
         *        timeouts and any thrown exceptions.
         * @throws MslInterruptedException if interrupted while waiting to acquire
         *         a master token from a renewing thread.
         * @see #releaseRenewalLock(MslContext, BlockingQueue, MessageInputStream)
         */
        acquireRenewalLock: function acquireRenewalLock(service, ctx, msgCtx, queue, builderTokenTicket, timeout, callback) {
            var self = this;
            InterruptibleExecutor(callback, function() {
                var builder = builderTokenTicket.builder;
                var tokenTicket = builderTokenTicket.tokenTicket;

                var masterToken = builder.getMasterToken();
                var userIdToken = builder.getUserIdToken();
                var userId = msgCtx.getUserId();

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
                var startTime = ctx.getRemoteTime();
                if ((msgCtx.isEncrypted() && !builder.willEncryptPayloads()) ||
                    (msgCtx.isIntegrityProtected() && !builder.willIntegrityProtectPayloads()) ||
                    builder.isRenewable() ||
                    (!masterToken && msgCtx.isNonReplayable()) ||
                    (masterToken && masterToken.isExpired(startTime)) ||
                    (!userIdToken && userId && (!builder.willEncryptHeader() || !builder.willIntegrityProtectHeader())) ||
                    (msgCtx.isRequestingTokens() && (!masterToken || (userId && !userIdToken))))
                {
                    blockingAcquisition(masterToken, userIdToken, userId, builder, tokenTicket);
                } else {
                    tryAcquisition(masterToken, userIdToken);
                }
            }, self);

            function blockingAcquisition(masterToken, userIdToken, userId, builder, tokenTicket) {
                InterruptibleExecutor(callback, function() {
                    // Stop and throw an exception if aborted.
                    if (service.isAborted())
                        throw new MslInterruptedException('acquireRenewalLock aborted.');

                    // We do not have a master token or this message is non-
                    // replayable. Try to acquire the renewal lock on this MSL
                    // context so we can send a handshake message.
                    var ctxRenewingQueue = null;
                    for (var i = 0; i < this._renewingContexts.length; ++i) {
                        var ctxQueue = this._renewingContexts[i];
                        if (ctxQueue.ctx === ctx) {
                            ctxRenewingQueue = ctxQueue.queue;
                            break;
                        }
                    }

                    // If there is no one else already renewing then our queue has
                    // acquired the renewal lock.
                    if (!ctxRenewingQueue) {
                        this._renewingContexts.push({ctx: ctx, queue: queue});
                        return true;
                    }

                    // Otherwise we need to wait for a master token from the
                    // renewing request.
                    var ticket = ctxRenewingQueue.poll(timeout, {
                        result: function(newMasterToken) {
                            InterruptibleExecutor(callback, function() {
                                // If aborted throw an exception.
                                if (newMasterToken === undefined)
                                    throw new MslInterruptedException('acquireRenewalLock aborted.');

                                // Put the same master token back on the renewing queue so
                                // anyone else waiting can also proceed.
                                ctxRenewingQueue.add(newMasterToken);

                                // If the renewing request did not acquire a master token then
                                // try again to acquire renewal ownership.
                                if (newMasterToken === NULL_MASTER_TOKEN) {
                                    blockingAcquisition(masterToken, userIdToken, userId, builder, tokenTicket);
                                    return;
                                }

                                // If the new master token is not equal to the previous master
                                // token then release the previous master token and get the
                                // newest master token.
                                //
                                // We cannot simply use the new master token directly since we
                                // have not acquired its master token lock.
                                var previousMasterToken = masterToken;
                                if (!masterToken || !masterToken.equals(newMasterToken)) {
                                    this.releaseMasterToken(ctx, tokenTicket);
                                    this.getNewestMasterToken(service, ctx, timeout, {
                                        result: function(tokenTicket) {
                                            InterruptibleExecutor(callback, function() {
                                                // This is a hack to ensure the caller ends up with the
                                                // right token ticket, now that we have potentially
                                                // swapped master tokens.
                                                builderTokenTicket.tokenTicket = tokenTicket;

                                                // If there is no newest master token (it could have been
                                                // deleted despite just being delivered to us) then try
                                                // again to acquire renewal ownership.
                                                masterToken = (tokenTicket && tokenTicket.masterToken);
                                                if (!masterToken) {
                                                    blockingAcquisition(masterToken, userIdToken, userId, builder, tokenTicket);
                                                    return;
                                                }

                                                // Otherwise continue with renewal lock acquisition.
                                                continueAcquisition(previousMasterToken, masterToken, userIdToken, userId, builder, tokenTicket);
                                            }, self);
                                        },
                                        timeout: callback.timeout,
                                        error: callback.error,
                                    });
                                    return;
                                } else {
                                    // The master token has not changed. Continue with renewal lock
                                    // acquisition.
                                    continueAcquisition(previousMasterToken, masterToken, userIdToken, userId, builder, tokenTicket);
                                }
                            }, self);
                        },
                        timeout: callback.timeout,
                        error: callback.error,
                    });
                    service.setAbort(function() {
                        if (ticket) {
                            ctxRenewingQueue.cancel(ticket);
                            ticket = undefined;
                        }
                    });
                }, self);
            }

            function continueAcquisition(previousMasterToken, masterToken, userIdToken, userId, builder, tokenTicket) {
                InterruptibleExecutor(callback, function() {
                    // The renewing request may have acquired a new user ID token.
                    // Attach it to this message if the message is associated with
                    // a user and we do not already have a user ID token.
                    //
                    // Unless the previous master token was thrown out, any user ID
                    // token should still be bound to this new master token. If the
                    // master token serial number has changed then our user ID
                    // token is no longer valid and the new one should be attached.
                    if ((userId && !userIdToken) ||
                        (userIdToken && !userIdToken.isBoundTo(masterToken)))
                    {
                        var storedUserIdToken = ctx.getMslStore().getUserIdToken(userId);
                        userIdToken = (storedUserIdToken && storedUserIdToken.isBoundTo(masterToken)) ? storedUserIdToken : null;
                    }

                    // Update the message's master token and user ID token.
                    builder.setAuthTokens(masterToken, userIdToken);

                    // If the new master token is still expired then try again to
                    // acquire renewal ownership.
                    var updateTime = ctx.getRemoteTime();
                    if (masterToken.isExpired(updateTime)) {
                        blockingAcquisition(masterToken, userIdToken, userId, builder, tokenTicket);
                        return;
                    }

                    // If this message is already marked renewable and the received
                    // master token is the same as the previous master token then
                    // we must still attempt to acquire the renewal lock.
                    if (builder.isRenewable() && masterToken.equals(previousMasterToken)) {
                        blockingAcquisition(masterToken, userIdToken, userId, builder, tokenTicket);
                        return;
                    }

                    // If this message is requesting tokens and is associated with
                    // a user but there is no user ID token then we must still
                    // attempt to acquire the renewal lock.
                    if (msgCtx.isRequestingTokens() && !userIdToken) {
                        blockingAcquisition(masterToken, userIdToken, userId, builder, tokenTicket);
                        return;
                    }

                    // We may still want to renew, but it is not required. Fall
                    // through.
                    tryAcquisition(masterToken, userIdToken);
                }, self);
            }

            function tryAcquisition(masterToken, userIdToken) {
                InterruptibleExecutor(callback, function() {
                    // Stop and throw an exception if aborted.
                    if (service.isAborted())
                        throw new MslInterruptedException('acquireRenewalLock aborted.');

                    // If we do not have a master token or the master token should be
                    // renewed, or we do not have a user ID token but the message is
                    // associated with a user, or if the user ID token should be renewed,
                    // then try to mark this message as renewable.
                    var finalTime = ctx.getRemoteTime();
                    if ((!masterToken || masterToken.isRenewable(finalTime)) ||
                        (!userIdToken && msgCtx.getUserId()) ||
                        (userIdToken && userIdToken.isRenewable(finalTime)))
                    {
                        // Try to acquire the renewal lock on this MSL context.
                        var ctxRenewingQueue = null;
                        for (var i = 0; i < this._renewingContexts.length; ++i) {
                            var ctxQueue = this._renewingContexts[i];
                            if (ctxQueue.ctx === ctx) {
                                ctxRenewingQueue = ctxQueue.queue;
                                break;
                            }
                        }

                        // If there is no one else already renewing then our queue has
                        // acquired the renewal lock.
                        if (!ctxRenewingQueue) {
                            this._renewingContexts.push({ctx: ctx, queue: queue});
                            return true;
                        }

                        // Otherwise proceed without acquiring the lock.
                        return false;
                    }

                    // Otherwise we do not need to acquire the renewal lock.
                    return false;
                }, self);
            }
        },

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
         * @param {MslContext} ctx MSL context.
         * @param {BlockingQueue} queue caller's blocking queue.
         * @param {?MessageInputStream} message received message. May be null if no message was received.
         */
        releaseRenewalLock: function releaseRenewalLock(ctx, queue, message) {
            // Sanity check.
            var index;
            var ctxQueue;
            for (var i = 0; i < this._renewingContexts.length; ++i) {
                var q = this._renewingContexts[i];
                if (q.ctx === ctx) {
                    index = i;
                    ctxQueue = q.queue;
                    break;
                }
            }

            if (ctxQueue !== queue)
                throw new MslInternalException("Attempt to release renewal lock that is not owned by this queue.");

            // If no message was received then deliver a null master token, release
            // the lock, and return immediately.
            if (!message) {
                queue.add(NULL_MASTER_TOKEN);
                this._renewingContexts.splice(index, 1);
                return;
            }

            // If we received an error message then deliver a null master token,
            // release the lock, and return immediately.
            var messageHeader = message.getMessageHeader();
            if (!messageHeader) {
                queue.add(NULL_MASTER_TOKEN);
                this._renewingContexts.splice(index, 1);
                return;
            }

            // If we performed key exchange then the renewed master token should be
            // delivered.
            var keyResponseData = messageHeader.keyResponseData;
            if (keyResponseData) {
                queue.add(keyResponseData.masterToken);
            }

            // In trusted network mode deliver the header master token. This may be
            // null.
            else if (!ctx.isPeerToPeer()) {
                var masterToken = messageHeader.masterToken;
                if (masterToken)
                    queue.add(masterToken);
                else
                    queue.add(NULL_MASTER_TOKEN);
            }

            // In peer-to-peer mode deliver the peer master token. This may be
            // null.
            else {
                var peerMasterToken = messageHeader.peerMasterToken;
                if (peerMasterToken)
                    queue.add(peerMasterToken);
                else
                    queue.add(NULL_MASTER_TOKEN);
            }

            // Release the lock.
            this._renewingContexts.splice(index, 1);
        }
    });

    var MslControl = module.exports = Class.create({
        /**
         * Create a new instance of MSL control with the specified number of
         * threads and user error message registry. A thread count of zero will
         * allow an unlimited number of simultaneous MSL transactions.
         *
         * @param {number=} numThreads number of worker threads to create.
         * @param {?MessageFactory=} messageFactory message factory. May be {@code null}.
         * @param {?ErrorMessageRegistry=} messageRegistry error message registry. May be {@code null}.
         */
        init: function init(numThreads, messageFactory, messageRegistry) {
            // Create the thread pool if requested.
            var threads = null;
            if (typeof numThreads === 'number' && numThreads > 0)
                threads = new Semaphore(numThreads);
            
            // The properties.
            var props = {
                /** @type {MslControlImpl} */
                _impl: { value: new MslControlImpl(messageFactory, messageRegistry), writable: false, enumerable: false, configurable: false },
                /** @type {Semaphore} */
                _threads: { value: threads, writable: false, enumerable: false, configurable: false },
                /** True if shutdown. */
                _shutdown: { value: false, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * Assigns a filter stream factory that will be used to filter any incoming
         * or outgoing messages. The filters will be placed between the MSL message
         * and MSL control, meaning they will see the actual MSL message data as it
         * is being read from or written to the remote entity.
         *
         * @param {FilterStreamFactory} factory filter stream factory. May be null.
         */
        setFilterFactory: function setFilterFactory(factory) {
            this._impl.setFilterFactory(factory);
        },

        /**
         * Gracefully shutdown the MSL control instance. No additional messages may
         * be processed. Any messages pending or in process will be completed.
         */
        shutdown: function shutdown() {
            this._shutdown = true;
        },
        
        /**
         * Submit a service for execution on one of the threads, or immediately
         * if threads are not being used. Upon completion, timeout, or error
         * the thread will be released.
         * 
         * @param {SendService|ReceiveService|RespondService|ErrorService|RequestService}
         *        service the service to execute.
         * @param {?} cancelledValue the value to return if the thread is not
         *        acquired due to cancellation.
         * @param {number} timeout thread acquisition timeout in milliseconds.
         * @param {{result: function(?), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the service return
         *        value, be notified of timeout, or any thrown exceptions.
         * @return {CancellationFunction} a function which if called will
         *         cancel the operation and release the thread.
         */
        submit: function(service, cancelledValue, timeout, callback) {
            var self = this;
            
            // If we have a thread limit, acquire one of the threads and then
            // execute.
            if (this._threads) {
                // Create a callback that will release the thread upon completion.
                var threadCallback = {
                    result: function(x) {
                        AsyncExecutor(callback, function() {
                            this._threads.signal();
                            return x;
                        }, self);
                    },
                    timeout: function() {
                        AsyncExecutor(callback, function() {
                            this._threads.signal();
                            callback.timeout();
                        }, self);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            this._threads.signal();
                            callback.error(e);
                        }, self);
                    },
                };
                
                // Acquire the thread.
                var ticket = this._threads.wait(timeout, {
                    result: function(acquired) {
                        if (acquired)
                            setTimeout(function() { service.call(threadCallback); }, 0);
                        else
                            callback.result(cancelledValue);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
                return CancellationFunction(this, ticket, service);
            }
            
            // Otherwise execute immediately.
            setTimeout(function() { service.call(callback); }, 0);
            return CancellationFunction(this, null, service);
        },
        
        /**
         * <p>Use of this method is not recommended as it does not confirm delivery
         * or acceptance of the message. Establishing a MSL channel to send
         * application data without requiring the remote entity to acknowledge
         * receipt in the response application data is the recommended approach.
         * Only use this method if guaranteed receipt is not required.</p>
         * 
         * <p>This method has two acceptable parameter lists. Both forms should
         * only be used by trusted network clients and peer-to-peer entities
         * when no response is expected from the remote entity.</p>
         * 
         * <p>The first form accepts a remote entity URL and will send a
         * message to the remote entity at the provided URL.</p>
         * 
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {Url} remoteEntity remote entity URL.
         * @param {number} timeout connect, read, and renewal lock acquisition timeout in
         *        milliseconds.
         * @param {{result: function(MessageOutputStream), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         * 
         * <p>The caller must close the returned message output stream.</p>
         * 
         * <hr>
         * 
         * <p>The second form accepts an InputStream and OutputStream and will
         * send a message to the remote entity over the provided output
         * stream.</p>
         * 
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} in remote entity input stream.
         * @param {OutputStream} out remote entity output stream.
         * @param {number} timeout connect, read, and renewal lock acquisition timeout in
         *        milliseconds.
         * @param {{result: function(MessageOutputStream), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         *         
         * <p>The caller must close the returned message output stream. The
         * remote entity output stream will not be closed when the message
         * output stream is closed, in case the caller wishes to reuse
         * them.</p>
         * 
         * TODO once Java supports the WebSocket protocol we can remove this method
         * in favor of the one accepting a URL parameter. (Or is it the other way
         * around?)
         * 
         * <hr>
         * 
         * <p>In either case the remote entity should be using
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
         */
        send: function send(ctx, msgCtx /* variable arguments */) {
            if (this._shutdown)
                throw new MslException('MslControl is shutdown.');
            
            var remoteEntity,
                input,
                output,
                timeout,
                callback;
            
            // Handle the first form.
            if (arguments.length == 5) {
                remoteEntity = arguments[2];
                input = null;
                output = null;
                timeout = arguments[3];
                callback = arguments[4];
            }
            
            // Handle the second form.
            else if (arguments.length == 6) {
                remoteEntity = null;
                input = arguments[2];
                output = arguments[3];
                timeout = arguments[4];
                callback = arguments[5];
            }
            
            // Malformed arguments are not explicitly handled, just as with any
            // other function.
            
            var sendMsgCtx = new SendMessageContext(msgCtx);
            var service = new SendService(this._impl, ctx, msgCtx, remoteEntity, input, output, timeout);
            return this.submit(service, null, timeout, callback);
        },

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
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {MessageInputStream} request message input stream used to create the message.
         * @param {number} timeout renewal lock acquisition timeout in milliseconds.
         * @param {{result: function(MslChannel), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         * @throws MslInternalException if used in peer-to-peer mode or if the
         *         request message input stream is an error message.
         */
        push: function push(ctx, msgCtx, input, output, request, timeout, callback) {
            if (this._shutdown)
                throw new MslException('MslControl is shutdown.');
            
            if (ctx.isPeerToPeer()) {
                callback.error(new MslInternalException("This method cannot be used in peer-to-peer mode."));
                return;
            }
            if (request.getErrorHeader()) {
                callback.error(new MslInternalException("Request message input stream cannot be for an error message."));
                return;
            }
            
            var service = new PushService(this._impl, ctx, msgCtx, input, output, request, timeout);
            return this.submit(service, null, timeout, callback);
        },

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
         * or {@code IOException}.</p>
         *
         * <p>The remote entity input and output streams will not be closed in case
         * the caller wishes to reuse them.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {number} timeout read/write and renewal lock acquisition
         *        timeout in milliseconds.
         * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         * @throws MslException immediately if called after having been shut
         *         down. This exception is not delivered to the callback.
         */
        receive: function receive(ctx, msgCtx, input, output, timeout, callback) {
            if (this._shutdown)
                throw new MslException('MslControl is shutdown.');            
            var service = new ReceiveService(this._impl, ctx, msgCtx, input, output, timeout);
            return this.submit(service, null, timeout, callback);
        },

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
         * cause is a {@code MslException}, {@code MslErrorResponseException}, or
         * {@code IOException}.</p>
         *
         * <p>The remote entity input and output streams will not be closed in case
         * the caller wishes to reuse them.</p>
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {MessageInputStream} request message input stream to create the response for.
         * @param {number} timeout read/write and renewal lock acquisition
         *        timeout in milliseconds.
         * @param {{result: function(MslChannel), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         * @throws MslException immediately if called after having been shut
         *         down. This exception is not delivered to the callback.
         */
        respond: function respond(ctx, msgCtx, input, output, request, timeout, callback) {
            if (this._shutdown)
                throw new MslException('MslControl is shutdown.');
            var service = new RespondService(this._impl, ctx, msgCtx, input, output, request, timeout);
            return this.submit(service, null, timeout, callback);
        },

        /**
         * <p>Send an error response over the provided output stream. Any replies
         * to the error response may be received by a subsequent call to
         * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}.</p>
         *
         * <p>This method should only be used by trusted network servers and peer-
         * to-peer entities after receiving a request via
         * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}.
         * The remote entity should have used
         * {@link #request(MslContext, MessageContext, URL, int)}.</p>
         *
         * <p>The returned {@code Future} will return true on success or false if
         * {@link #cancelled(Throwable) cancelled or interrupted}. The
         * {@code Future} may throw an {@code ExecutionException} whose cause is a
         * {@code MslException} or {@code IOException}.</p>
         *
         * <p>The remote entity input and output streams will not be closed in case
         * the caller wishes to reuse them.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {ApplicationError} err error type.
         * @param {OutputStream} out remote entity output stream.
         * @param {MessageHeader} request request header to create the response from.
         * @param {number} timeout read/write timeout in milliseconds.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         * @throws MslException immediately if called after having been shut
         *         down. This exception is not delivered to the callback.
         */
        error: function error(ctx, msgCtx, err, out, request, timeout, callback) {
            if (this._shutdown)
                throw new MslException('MslControl is shutdown.');
            var service = new ErrorService(this._impl, ctx, msgCtx, err, out, request, timeout);
            return this.submit(service, false, timeout, callback);
        },

        /**
         * <p>This method has two acceptable parameter lists.</p>
         *
         * <p>The first form accepts a remote entity URL and will send a
         * request to the remote entity at the provided URL. This form should
         * only be used by trusted network clients when initiating a new
         * request.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {Url} remoteEntity remote entity URL.
         * @param {number} timeout connect, read/write, and renewal lock
         *        acquisition timeout in milliseconds.
         * @param {{result: function(MslChannel), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         * @throws MslInternalException if used in peer-to-peer mode.
         * @throws MslException immediately if called after having been shut
         *         down. This exception is not delivered to the callback.
         *
         * <p>The caller must close the returned message input stream and message
         * output stream.</p>
         *
         * <hr>
         *
         * <p>The second form accepts an InputStream and OutputStream and will
         * send a request to the remote entity over the provided output stream
         * and receive a response over the provided input stream. This form
         * should only be used by peer-to-peer entities when initiating a new
         * request.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {number} timeout connect and read timeout in milliseconds.
         * @param {{result: function(MslChannel), timeout: function(), error: function(Error)}}
         *        callback the callback that will be used for the operation.
         * @return {function()} a function which if called will cancel the
         *         operation.
         * @throws MslInternalException if used in trusted network mode.
         * @throws MslException immediately if called after having been shut
         *         down. This exception is not delivered to the callback.
         *
         * <p>The caller must close the returned message input stream and message
         * outut stream. The remote entity input and output streams will not be
         * closed when the message input and output streams are closed, in case the
         * caller wishes to reuse them.</p>
         *
         * TODO once Java supports the WebSocket protocol we can remove this form
         * in favor of the one accepting a URL parameter. (Or is it the other way
         * around?)
         *
         * <hr>
         *
         * <p>In either case the remote entity should be using
         * {@link #receive(MslContext, MessageContext, InputStream, OutputStream, int)}
         * and
         * {@link #respond(MslContext, MessageContext, InputStream, OutputStream, MessageBuilder, int)}.</p>
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
         * {@code MslException} or {@code IOException}.</p>
         */
        request: function request(ctx, msgCtx /* variable arguments */) {
            if (this._shutdown)
                throw new MslException('MslControl is shutdown.');

            var remoteEntity,
                input,
                output,
                timeout,
                callback;

            // Handle the first form.
            if (arguments.length == 5) {
                remoteEntity = arguments[2];
                input = null;
                output = null;
                timeout = arguments[3];
                callback = arguments[4];

                if (ctx.isPeerToPeer()) {
                    callback.error(new MslInternalException("This method cannot be used in peer-to-peer mode."));
                    return;
                }
            }

            // Handle the second form.
            else if (arguments.length == 6) {
                remoteEntity = null;
                input = arguments[2];
                output = arguments[3];
                timeout = arguments[4];
                callback = arguments[5];

                if (!ctx.isPeerToPeer()) {
                    callback.error(new MslInternalException("This method cannot be used in trusted network mode."));
                    return;
                }
            }

            // Malformed arguments are not explicitly handled, just as with any
            // other function.

            var service = new RequestService(this._impl, ctx, msgCtx, remoteEntity, input, output, null, Receive.ALWAYS, 0, timeout);
            return this.submit(service, null, timeout, callback);
        }
    });

    /**
     * Send an error response over the provided output stream.
     *
     * @param {ReceiveService|RespondService|ErrorService|RequestService} service the calling service.
     * @param {MslControlImpl} ctrl MSL control.
     * @param {MslContext} ctx MSL context.
     * @param {?MessageDebugContext} debugCtx message debug context. May be {@code null}.
     * @param {?MessageHeader} requestHeader message the error is being sent in response to. May
     *        be {@code null}.
     * @param {number} messageId error response message ID.
     * @param {MslError} err MSL error.
     * @param {string} userMessage user-consumable error message. May be
     *        {@code null}.
     * @param {OutputStream} output remote entity output stream.
     * @param {number} timeout send timeout in milliseconds.
     * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
     *        callback the callback will receive true on success, be notified
     *        of timeout and any thrown exceptions.
     */
    function sendError(service, ctrl, ctx, debugCtx, requestHeader, messageId, error, userMessage, output, timeout, callback) {
        // Create error header.
        messageFactory.createErrorResponse(ctx, messageId, error, userMessage, {
            result: function(errorHeader) {
                if (debugCtx) debugCtx.sentHeader(errorHeader);
                
                // Determine encoder format.
                var encoder = ctx.getMslEncoderFactory();
                var capabilities = (requestHeader)
                    ? MessageCapabilities.intersection(ctx.getMessageCapabilities(), requestHeader.messageCapabilities)
                    : ctx.getMessageCapabilities();
                var formats = (capabilities) ? capabilities.encoderFormats : null;
                var format = encoder.getPreferredFormat(formats);
                
                // Send error response.
                ctrl._messageFactory.createOutputStream(ctx, output, errorHeader, null, format, timeout, {
                    result: function(response) {
                        InterruptibleExecutor(callback, function() {
                            // Register abort function.
                            service.setAbort(function() { response.abort(); });
                            
                            // Wait until the output stream is ready.
                            response.isReady({
                                result: function(ready) {
                                    InterruptibleExecutor(callback, function() {
                                        // If aborted throw an exception.
                                        if (!ready)
                                            throw new MslInterruptedException('sendError aborted.');
                                        response.close(timeout, {
                                            result: function(success) {
                                                InterruptibleExecutor(callback, function() {
                                                    // If aborted throw an exception.
                                                    if (!success)
                                                        throw new MslInterruptedException('sendError aborted.');
                                                    return success;
                                                });
                                            },
                                            timeout: callback.timeout,
                                            error: callback.error,
                                        });
                                    });
                                },
                                timeout: callback.timeout,
                                error: callback.error,
                            });
                        });
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            },
            error: callback.error,
        });
    }

    /**
     * <p>This service receives a request from a remote entity, and either
     * returns the received message or automatically generates a reply (and
     * returns null).</p>
     *
     * <p>This class will only be used by trusted-network servers and peer-to-
     * peer servers.</p>
     */
    var ReceiveService = Class.create({
        /**
         * Create a new message receive service.
         *
         * @param {MslControlImpl} ctrl parent MSL control.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {number} timeout read/write and renewal lock acquisition
         *        timeout in milliseconds.
         */
        init: function init(ctrl, ctx, msgCtx, input, output, timeout) {
            // The properties.
            var props = {
                _ctrl: { value: ctrl, writable: false, enumerable: false, configurable: false },
                _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                _msgCtx: { value: msgCtx, writable: false, enumerable: false, configurable: false },
                _input: { value: input, writable: false, enumerable: false, configurable: false },
                _output: { value: output, writable: false, enumerable: false, configurable: false },
                _timeout: { value: timeout, writable: false, enumerable: false, configurable: false },
                _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                _abortFunc: { value: undefined, writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {boolean} true if the oepration has been aborted.
         */
        isAborted: function isAborted() {
            return this._aborted;
        },

        /**
         * Abort the operation. The service cannot be used after being aborted.
         */
        abort: function abort() {
            this._aborted = true;
            if (this._abortFunc)
                this._abortFunc.call(this);
        },

        /**
         * Set the abort function. This replaces any previous abort function.
         *
         * @param {?function()} func the abort function. Null to unset.
         */
        setAbort: function setAbort(func) {
            this._abortFunc = func;
        },

        /**
         * @param {{result: function(?MessageInputStream), timeout: function(), error: function(Error)}}
         *        callback the callback will be given the received message or
         *        {@code null} if cancelled, notified of timeout and any thrown
         *        exceptions.
         * @throws MslException if there was an error with the received message
         *         or an error creating an automatically generated response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error reading or writing a
         *         message.
         */
        call: function call(callback) {
            var self = this;

            // Read the incoming message.
            InterruptibleExecutor(callback, function() {
                this._ctrl.receive(this, this._ctx, this._msgCtx, this._input, null, this._timeout, {
                    result: function(request) { deliverMessage(request); },
                    timeout: callback.timeout,
                    error: function(e) {
                        InterruptibleExecutor(callback, function() {
                            // If we were cancelled then return null.
                            if (cancelled(e)) return null;

                            // Try to send an error response.
                            var requestMessageId, mslError, userMessage, toThrow;
                            if (e instanceof MslException) {
                                requestMessageId = e.messageId;
                                mslError = e.error;
                                userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, null);
                                toThrow = e;
                            } else if (e instanceof MslIoException) {
                                requestMessageId = null;
                                mslError = MslError.MSL_COMMS_FAILURE;
                                userMessage = null;
                                toThrow = e;
                            } else {
                                requestMessageId = null;
                                mslError = MslError.INTERNAL_EXCEPTION;
                                userMessage = null;
                                toThrow = new MslInternalException("Error receiving the message header.", e);
                            }
                            sendError(this, this._ctrl, this._ctx, this._msgCtx.getDebugContext(), null, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                result: function(success) { callback.error(toThrow); },
                                timeout: callback.timeout,
                                error: function(re) {
                                    InterruptibleExecutor(callback, function() {
                                        // If we were cancelled then return null.
                                        if (cancelled(re)) return null;

                                        throw new MslErrorResponseException("Error receiving the message header.", re, e);
                                    }, self);
                                }
                            });
                        }, self);
                    }
                });
            }, self);

            function deliverMessage(request) {
                InterruptibleExecutor(callback, function() {
                    // Return error headers to the caller.
                    var requestHeader = request.getMessageHeader();
                    if (!requestHeader)
                        return request;

                    // If the message payload is not a handshake message deliver it to the
                    // caller.
                    this.setAbort(function() { request.abort(); });
                    request.isHandshake(this._timeout, {
                       result: function(handshake) {
                           InterruptibleExecutor(callback, function() {
                               // If aborted return null.
                               if (handshake === undefined)
                                   return null;

                               // If not a handshake message deliver it to the
                               // caller.
                               if (!handshake)
                                   return request;

                               // Otherwise continue processing.
                               handshakeResponse(request);
                           }, self);
                       },
                       timeout: callback.timeout,
                       error: function(e) {
                           InterruptibleExecutor(callback, function() {
                               // If we were cancelled then return null.
                               if (cancelled(e)) return null;

                               // We couldn't read, but maybe we can write an error response.
                               var requestMessageId, mslError, userMessage, toThrow;
                               if (e instanceof MslException) {
                                   requestMessageId = e.messageId;
                                   mslError = e.error;
                                   userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, null);
                                   toThrow = e;
                               } else {
                                   requestMessageId = requestHeader.messageId;
                                   mslError = MslError.INTERNAL_EXCEPTION;
                                   userMessage = null;
                                   toThrow = new MslInternalException("Error peeking into the message payloads.", e);
                               }
                               sendError(this, this._ctrl, this._ctx, this._msgCtx.getDebugContext(), requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                   result: function(success) { callback.error(toThrow); },
                                   timeout: callback.timeout,
                                   error: function(re) {
                                       InterruptibleExecutor(callback, function() {
                                           // If we were cancelled then return null.
                                           if (cancelled(re)) return null;

                                           throw new MslErrorResponseException("Error peeking into the message payloads.", re, e);
                                       }, self);
                                   }
                               });
                           }, self);
                       }
                    });
                }, self);
            }

            function handshakeResponse(request) {
                InterruptibleExecutor(callback, function() {
                    // Close the request. We're done with it.
                    request.close(this._timeout, {
                    	result: function() {},
                    	timeout: function() {},
                    	error: function() {}
                    });

                    // This is a handshake request so automatically return a response.
                    //
                    // In peer-to-peer mode this will acquire the local entity's
                    // master token read lock.
                    this._ctrl.buildResponse(this, this._ctx, this._msgCtx, request.getMessageHeader(), this._timeout, {
                        result: function(builderTokenTicket) {
                            InterruptibleExecutor(callback, function() {
                                var responseBuilder = builderTokenTicket.builder;
                                var tokenTicket = builderTokenTicket.tokenTicket;

                                // If we are in trusted services mode then no additional data is
                                // expected. Send the handshake response and return null. The next
                                // message from the remote entity can be retrieved by another call
                                // to receive.
                                var keyxMsgCtx = new KeyxResponseMessageContext(this._msgCtx);
                                if (!this._ctx.isPeerToPeer()) {
                                    sendHandshake(request, responseBuilder, keyxMsgCtx, tokenTicket);
                                    return;
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
                                var service = new RequestService(this._ctrl, this._ctx, keyxMsgCtx, null, this._input, this._output, builderTokenTicket, 1, this._timeout);
                                // Set the abort function to abort the new service before executing
                                // the service.
                                this.setAbort(function() { service.abort(); });
                                service.call({
                                    result: function(channel) {
                                        InterruptibleExecutor(callback, function() {
                                            // The MSL channel message output stream can be discarded since it
                                            // only contained a handshake response.
                                            if (channel)
                                                return channel.input;
                                            return null;
                                        });
                                    },
                                    timeout: callback.timeout,
                                    error: callback.error,
                                });
                            }, self);
                        },
                        timeout: callback.timeout,
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // If we were cancelled then return null.
                                if (cancelled(e)) return null;

                                // Try to send an error response.
                                var requestHeader = request.getMessageHeader();
                                var requestMessageId, mslError, userMessage, toThrow;
                                if (e instanceof MslException) {
                                    requestMessageId = e.messageId;
                                    mslError = e.error;
                                    var caps = requestHeader.messageCapabilities;
                                    var languages = (caps) ? caps.languages : null;
                                    userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, languages);
                                    toThrow = e;
                                } else {
                                    requestMessageId = requestHeader.messageId;
                                    mslError = MslError.INTERNAL_EXCEPTION;
                                    userMessage = null;
                                    toThrow = new MslInternalException("Error creating an automatic handshake response.", e);
                                }
                                sendError(this, this._ctrl, this._ctx, this._msgCtx.getDebugContext(), requestHeader, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                    result: function(success) { callback.error(toThrow); },
                                    timeout: callback.timeout,
                                    error: function(re) {
                                        InterruptibleExecutor(callback, function() {
                                            // If we were cancelled then return null.
                                            if (cancelled(re)) return null;

                                            throw new MslErrorResponseException("Error creating an automatic handshake response.", re, e);
                                        }, self);
                                    }
                                });
                            }, self);
                        }
                    });
                }, self);
            }

            function sendHandshake(request, responseBuilder, keyxMsgCtx, tokenTicket) {
                InterruptibleExecutor(callback, function() {
                    responseBuilder.setRenewable(false);
                    this._ctrl.send(this._ctx, keyxMsgCtx, this._output, responseBuilder, false, this._timeout, {
                        result: function(sent) {
                            callback.result(null);
                        },
                        timeout: callback.timeout,
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // If we were cancelled then return null.
                                if (cancelled(e)) return null;

                                // Try to send an error response.
                                var requestHeader = request.getMessageHeader();
                                var requestMessageId, mslError, userMessage, toThrow;
                                if (e instanceof MslException) {
                                    requestMessageId = e.messageId;
                                    mslError = e.error;
                                    var caps = requestHeader.messageCapabilities;
                                    var languages = (caps) ? caps.languages : null;
                                    userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, languages);
                                    toThrow = e;
                                } else if (e instanceof MslIoException) {
                                    requestMessageId = requestHeader.messageId;
                                    mslError = MslError.MSL_COMMS_FAILURE;
                                    userMessage = null;
                                    toThrow = e;
                                } else {
                                    requestMessageId = requestHeader.messageId;
                                    mslError = MslError.INTERNAL_EXCEPTION;
                                    userMessage = null;
                                    toThrow = new MslInternalException("Error sending an automatic handshake response.", e);
                                }
                                sendError(this, this._ctrl, this._ctx, this._msgCtx.getDebugContext(), requestHeader, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                    result: function(success) { callback.error(toThrow); },
                                    timeout: callback.timeout,
                                    error: function(re) {
                                        InterruptibleExecutor(callback, function() {
                                            // If we were cancelled then return null.
                                            if (cancelled(re)) return null;

                                            throw new MslErrorResponseException("Error sending an automatic handshake response.", re, e);
                                        }, self);
                                    }
                                });
                            }, self);
                        }
                    });
                }, self);
            }
        }
    });

    /**
     * <p>This service sends a response to the remote entity.</p>
     *
     * <p>This class will only be used trusted network servers and peer-to-peer
     * servers.</p>
     */
    var RespondService = Class.create({
        /**
         * Create a new message respond service.
         *
         * @param {MslControlImpl} ctrl parent MSL control.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {MessageInputStream} request request message input stream.
         * @param {number} timeout read/write and renewal lock acquisition
         *        timeout in milliseconds.
         */
        init: function init(ctrl, ctx, msgCtx, input, output, request, timeout) {
            // The properties.
            var props = {
                _ctrl: { value: ctrl, writable: false, enumerable: false, configurable: false },
                _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                _msgCtx: { value: msgCtx, writable: false, enumerable: false, configurable: false },
                _input: { value: input, writable: false, enumerable: false, configurable: false },
                _output: { value: output, writable: false, enumerable: false, configurable: false },
                _request: { value: request, writable: false, enumerable: false, configurable: false },
                _timeout: { value: timeout, writable: false, enumerable: false, configurable: false },
                _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                _abortFunc: { value: undefined, writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {boolean} true if the oepration has been aborted.
         */
        isAborted: function isAborted() {
            return this._aborted;
        },

        /**
         * Abort the operation. The service cannot be used after being aborted.
         */
        abort: function abort() {
            this._aborted = true;
            if (this._abortFunc)
                this._abortFunc.call(this);
        },

        /**
         * Set the abort function. This replaces any previous abort function.
         *
         * @param {?function()} func the abort function. Null to unset.
         */
        setAbort: function setAbort(func) {
            this._abortFunc = func;
        },

        /**
         * Send the response as a trusted network server.
         *
         * @param {{builder: MessageBuilder, tokenTicket: ?TokenTicket}}
         *        builderTokenTicket response message builder and master token /
         *        lock ticket.
         * @param {number} msgCount number of messages that have already been sent or
         *        received.
         * @param {{result: function(?MslChannel), timeout: function(), error: function(Error)}}
         *        callback the callback will receive the MSL channel if the
         *        response was sent or null if cancelled, interrupted, if the
         *        response could not be sent encrypted or integrity protected
         *        when required, a user could not be attached due to lack of
         *        a master token, or if the maximum message count is hit;
         *        notified of timeouts or any thrown exceptions.
         * @throws MslException if there was an error creating the response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         */
        trustedNetworkExecute: function trustedNetworkExecute(builderTokenTicket, msgCount, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                var tokenTicket;
                try {
                    var builder = builderTokenTicket.builder;
                    tokenTicket = builderTokenTicket.tokenTicket;
                    var debugCtx = this._msgCtx.getDebugContext();
                    var requestHeader = this._request.getMessageHeader();
                    var requestMessageId;
                    
                    // Do nothing if we cannot send one more message.
                    if (msgCount + 1 > MslConstants.MAX_MESSAGES) {
                        // Release the master token lock.
                        this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                        return null;
                    }

                    // If the response must be encrypted or integrity protected but
                    // cannot then send an error requesting it. The client must re-
                    // initiate the transaction.
                    var securityRequired;
                    if (this._msgCtx.isIntegrityProtected() && !builder.willIntegrityProtectHeader())
                        securityRequired = MslError.RESPONSE_REQUIRES_INTEGRITY_PROTECTION;
                    else if (this._msgCtx.isEncrypted() && !builder.willEncryptPayloads())
                        securityRequired = MslError.RESPONSE_REQUIRES_ENCRYPTION;
                    else
                        securityRequired = null;
                    if (securityRequired) {
                        // Try to send an error response.
                        requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                        sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, securityRequired, null, this._output, this._timeout, {
                            result: function(success) { callback.result(null); },
                            timeout: callback.timeout,
                            error: function(re) {
                                InterruptibleExecutor(callback, function() {
                                    // If we were cancelled then return null.
                                    if (cancelled(re)) return null;

                                    throw new MslErrorResponseException("Response requires encryption or integrity protection but cannot be protected: " + securityRequired, re, null);
                                }, self);
                            }
                        });

                        // Release the master token lock.
                        this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                        return;
                    }

                    // If the response wishes to attach a user ID token but there is no
                    // master token then send an error requesting the master token. The
                    // client must re-initiate the transaction.
                    if (this._msgCtx.getUser() && !builder.getMasterToken() && !builder.getKeyExchangeData()) {
                        // Try to send an error response.
                        requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                        sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, MslError.RESPONSE_REQUIRES_MASTERTOKEN, null, this._output, this._timeout, {
                            result: function(success) { callback.result(null); },
                            timeout: callback.timeout,
                            error: function(re) {
                                InterruptibleExecutor(callback, function() {
                                    // If we were cancelled then return null.
                                    if (cancelled(re)) return null;

                                    throw new MslErrorResponseException("Response wishes to attach a user ID token but there is no master token.", re, null);
                                }, self);
                            }
                        });

                        // Release the master token lock.
                        this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                        return;
                    }

                    // Otherwise simply send the response.
                    builder.setRenewable(false);
                    this._ctrl.send(this._ctx, this._msgCtx, this._output, builder, false, this._timeout, {
                        result: function(result) {
                            InterruptibleExecutor(callback, function() {
                                // Release the master token lock.
                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                                return new MslChannel(this._request, result.request);
                            }, self);
                        },
                        timeout: function() {
                            InterruptibleExecutor(callback, function() {
                                // Release the master token lock.
                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                                callback.timeout();
                            }, self);
                        },
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // Release the master token lock.
                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                                callback.error(e);
                            }, self);
                        }
                    });
                } catch (e) {
                    // Release the master token lock.
                    this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                    throw e;
                }
            }, self);
        },

        /**
         * Send the response as a peer-to-peer entity.
         *
         * @param {MessageContext} msgCtx message context.
         * @param {{builder: MessageBuilder, tokenTicket: ?TokenTicket}}
         *        builderTokenTicket response message builder and master token /
         *        lock ticket.
         * @param {number} msgCount number of messages sent or received so far.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback will receive a MSL channel if the
         *        response was sent or null if cancelled, interrupted, or if
         *        the response could not be sent encrypted or integrity
         *        protected when required, a user could not be attached due to
         *        lack of a master token, or if the maximum message count is
         *        hit; notified of timeout or any thrown exceptions.
         * @throws MslException if there was an error creating or processing a
         *         message.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         * @throws InterruptedException if the thread is interrupted while
         *         trying to acquire the master token lock.
         */
        peerToPeerExecute: function peerToPeerExecute(msgCtx, builderTokenTicket, msgCount, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                var builder = builderTokenTicket.builder;
                var tokenTicket = builderTokenTicket.tokenTicket;
                var debugCtx = msgCtx.getDebugContext();
                var requestHeader = this._request.getMessageHeader();
                
                // Do nothing if we cannot send and receive two more messages.
                //
                // Make sure to release the master token lock.
                if (msgCount + 2 > MslConstants.MAX_MESSAGES) {
                    this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                    return null;
                }

                // If the response wishes to attach a user ID token but there is no
                // master token then send an error requesting the master token. The
                // client must re-initiate the transaction.
                if (msgCtx.getUser() != null && builder.getPeerMasterToken() == null && builder.getKeyExchangeData() == null) {
                    // Release the master token lock and try to send an error
                    // response.
                    this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                    var requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                    sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, MslError.RESPONSE_REQUIRES_MASTERTOKEN, null, this._output, this._timeout, {
                        result: function(success) { callback.result(null); },
                        timeout: callback.timeout,
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // If we were cancelled then return null.
                                if (cancelled(e)) return null;

                                throw new MslErrorResponseException("Response wishes to attach a user ID token but there is no master token.", e, null);
                            }, self);
                        }
                    });
                    return;
                }

                // Send the response. A reply is not expected, but may be received.
                // This adds two to our message count.
                //
                // This will release the master token lock.
                this._ctrl.sendReceive(this._ctx, msgCtx, this._input, this._output, builderTokenTicket, Receive.RENEWING, false, this._timeout, {
                    result: function(result) {
                        InterruptibleExecutor(callback, function() {
                            var response = result.response;
                            msgCount += 2;

                            // If we did not receive a response then we're done. Return the
                            // original message input stream and the new message output stream.
                            if (!response)
                                return new MslChannel(this._request, result.request);

                            // If the response is an error see if we can handle the error and
                            // retry.
                            var responseHeader = response.getMessageHeader();
                            if (!responseHeader) {
                                prepareError(result);
                                return;
                            }

                            // If we performed a handshake then re-send the message over the
                            // same connection so this time the application can send its data.
                            if (result.handshake) {
                                prepareResend();
                                return;
                            }

                            // Otherwise we did send our application data (which may have been
                            // zero-length) so we do not need to re-send our message. Return
                            // the new message input stream and the new message output stream.
                            return new MslChannel(result.response, result.request);

                            function prepareResend() {
                                // Close the response as we are discarding it.
                                response.close(self._timeout, {
                                    result: function(success) {
                                        InterruptibleExecutor(callback, function() {
                                            // If we were cancelled then return null.
                                            if (!success)
                                                return null;
                                            resend();
                                        }, self);
                                    },
                                    timeout: function() {
                                        // We don't care about timeout.
                                        resend();
                                    },
                                    error: function(e) {
                                        InterruptibleExecutor(callback, function() {
                                            // If we were cancelled then return null.
                                            if (cancelled(e)) return null;
                                            // Otherwise we don't care about an exception on close.
                                            resend();
                                        }, self);
                                    }
                                });
                            }

                            function resend() {
                                InterruptibleExecutor(callback, function() {
                                    var resendMsgCtx = new ResendMessageContext(null, msgCtx);
                                    this._ctrl.buildResponse(this, this._ctx, resendMsgCtx, responseHeader, this._timeout, {
                                        result: function(builderTokenTicket) {
                                            InterruptibleExecutor(callback, function() {
                                                // The master token lock will be released by the recursive call
                                                // to peerToPeerExecute().
                                                this.peerToPeerExecute(resendMsgCtx, builderTokenTicket, msgCount, callback);
                                            }, self);
                                        },
                                        timeout: callback.timeout,
                                        error: callback.error,
                                    });
                                }, self);
                            }
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);

            function prepareError(result) {
                InterruptibleExecutor(callback, function() {
                    // Close the response. We have everything we need.
                    var response = result.response;
                    response.close(this._timeout, {
                        result: function(success) {
                            InterruptibleExecutor(callback, function() {
                                // If we were cancelled then return null.
                                if (!success)
                                    return null;
                                handleError(result);
                            }, self);
                        },
                        timeout: function() {
                            // We don't care about timeout.
                            handleError(result);
                        },
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // If we were cancelled then return null.
                                if (cancelled(e)) return null;
                                // Otherwise we don't care about an exception on close.
                                handleError(result);
                            }, self);
                        }
                    });
                }, self);
            }

            function handleError(result) {
                InterruptibleExecutor(callback, function() {
                    // Build the error response. This will acquire the master token
                    // lock.
                    var errorHeader = result.response.getErrorHeader();
                    this._ctrl.buildErrorResponse(this, this._ctx, msgCtx, result, errorHeader, {
                        result: function(errTokenTicket) {
                            InterruptibleExecutor(callback, function() {
                                // If there is no error response then return the error.
                                if (!errTokenTicket)
                                    return null;

                                var errMsg = errTokenTicket.errorResult;
                                var tokenTicket = errTokenTicket.tokenTicket;

                                // Send the error response. Recursively execute this because it
                                // may take multiple messages to succeed with sending the
                                // response.
                                //
                                // The master token lock will be released by the recursive call
                                // to peerToPeerExecute().
                                var builderTokenTicket = { builder: errMsg.builder, tokenTicket: tokenTicket };
                                var resendMsgCtx = errMsg.msgCtx;
                                this.peerToPeerExecute(resendMsgCtx, builderTokenTicket, msgCount, callback);
                            }, self);
                        }
                    });
                }, self);
            }
        },

        /**
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback will receive a {@link MslChannel} on
         *        success or {@code null} if cancelled, interrupted, if an error
         *        response was received (peer-to-peer mode only), if the
         *        response could not be sent encrypted or integrity protected
         *        when required (trusted network-mode only), or if the maximum
         *        number of messages is hit;; notified of a timeout or any
         *        thrown exceptions.
         * @throws MslException if there was an error creating the response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         */
        call: function call(callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                var debugCtx = this._msgCtx.getDebugContext();
                var requestHeader = this._request.getMessageHeader();
                
                // In peer-to-peer mode this will acquire the local entity's
                // master token read lock.
                this._ctrl.buildResponse(this, this._ctx, this._msgCtx, requestHeader, this._timeout, {
                    result: function(builderTokenTicket) {
                        InterruptibleExecutor(callback, function() {
                            var builder = builderTokenTicket.builder;

                            // At most three messages would have been involved in the original
                            // receive.
                            //
                            // Send the response. This will release the master token lock.
                            if (!this._ctx.isPeerToPeer()) {
                                this.trustedNetworkExecute(builderTokenTicket, 3, {
                                    result: function(channel) {
                                        InterruptibleExecutor(callback, function() {
                                            // Clear any cached payloads.
                                            if (channel)
                                                channel.output.stopCaching();

                                            // Return the established channel.
                                            return channel;
                                        }, self);
                                    },
                                    timeout: callback.timeout,
                                    error: function(e) {
                                        InterruptibleExecutor(callback, function() {
                                            // If we were cancelled then return null.
                                            if (cancelled(e)) return null;

                                            // Maybe we can send an error response.
                                            var requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                                            var mslError, userMessage, toThrow;
                                            if (e instanceof MslException) {
                                                mslError = e.error;
                                                var caps = requestHeader.messageCapabilities;
                                                var languages = (caps) ? caps.languages : null;
                                                userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, languages);
                                                toThrow = e;
                                            } else if (e instanceof MslIoException) {
                                                mslError = MslError.MSL_COMMS_FAILURE;
                                                userMessage = null;
                                                toThrow = e;
                                            } else {
                                                mslError = MslError.INTERNAL_EXCEPTION;
                                                userMessage = null;
                                                toThrow = new MslInternalException("Error sending the response.", e);
                                            }
                                            sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                                result: function(success) { callback.error(toThrow); },
                                                timeout: callback.timeout,
                                                error: function(re) {
                                                    InterruptibleExecutor(callback, function() {
                                                        // If we were cancelled then return null.
                                                        if (cancelled(re)) return null;

                                                        throw new MslErrorResponseException("Error sending the response.", re, null);
                                                    }, self);
                                                }
                                            });
                                        }, self);
                                    }
                                });
                            } else {
                                this.peerToPeerExecute(this._msgCtx, builderTokenTicket, 3, {
                                    result: function(channel) {
                                        InterruptibleExecutor(callback, function() {
                                            // Clear any cached payloads.
                                            if (channel)
                                                channel.output.stopCaching();

                                            // Return the established channel.
                                            return channel;
                                        }, self);
                                    },
                                    timeout: callback.timeout,
                                    error: function(e) {
                                        InterruptibleExecutor(callback, function() {
                                            // If we were cancelled then return null.
                                            if (cancelled(e)) return null;

                                            // Maybe we can send an error response.
                                            var requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                                            var mslError, userMessage, toThrow;
                                            if (e instanceof MslException) {
                                                mslError = e.error;
                                                var caps = this._request.messageCapabilities;
                                                var languages = (caps) ? caps.languages : null;
                                                userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, languages);
                                                toThrow = e;
                                            } else if (e instanceof MslIoException) {
                                                mslError = MslError.MSL_COMMS_FAILURE;
                                                userMessage = null;
                                                toThrow = e;
                                            } else {
                                                mslError = MslError.INTERNAL_EXCEPTION;
                                                userMessage = null;
                                                toThrow = new MslInternalException("Error sending the response.", e);
                                            }
                                            sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                                result: function(success) { callback.error(toThrow); },
                                                timeout: callback.timeout,
                                                error: function(re) {
                                                    InterruptibleExecutor(callback, function() {
                                                        // If we were cancelled then return false.
                                                        if (cancelled(re)) return false;

                                                        throw new MslErrorResponseException("Error sending the response.", re, null);
                                                    }, self);
                                                }
                                            });
                                        }, self);
                                    }
                                });
                            }
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: function(e) {
                        InterruptibleExecutor(callback, function() {
                            // If we were cancelled then return null.
                            if (cancelled(e)) return null;

                            // Try to send an error response.
                            var requestMessageId, mslError, userMessage, toThrow;
                            if (e instanceof MslException) {
                                requestMessageId = e.messageId;
                                mslError = e.error;
                                var caps = requestHeader.messageCapabilities;
                                var languages = (caps) ? caps.languages : null;
                                userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, languages);
                                toThrow = e;
                            } else {
                                requestMessageId = null;
                                mslError = MslError.INTERNAL_EXCEPTION;
                                userMessage = null;
                                toThrow = new MslInternalException("Error building the response.", e);
                            }
                            sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                result: function(success) { callback.error(toThrow); },
                                timeout: callback.timeout,
                                error: function(re) {
                                    InterruptibleExecutor(callback, function() {
                                        // If we were cancelled then return null.
                                        if (cancelled(re)) return null;

                                        throw new MslErrorResponseException("Error building the response.", re, e);
                                    }, self);
                                }
                            });
                        }, self);
                    }
                });
            }, self);
        }
    });

    /**
     * <p>This service sends an error response to the remote entity.</p>
     *
     * <p>This class will only be used trusted network servers and peer-to-peer
     * entities.</p>
     */
    var ErrorService = Class.create({
        /**
         * Create a new error service.
         *
         * @param {MslControlImpl} ctrl parent MSL control.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {ApplicationError} err the application error.
         * @param {OutputStream} out remote entity output stream.
         * @param {MessageHeader} request request message header.
         * @param {number} timeout read/write timeout in milliseconds.
         */
        init: function init(ctrl, ctx, msgCtx, err, out, request, timeout) {
            // The properties.
            var props = {
                _ctrl: { value: ctrl, writable: false, enumerable: false, configurable: false },
                _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                _msgCtx: { value: msgCtx, writable: false, enumerable: false, configurable: false },
                _appError: { value: err, writable: false, enumerable: false, configurable: false },
                _output: { value: out, writable: false, enumerable: false, configurable: false },
                _request: { value: request, writable: false, enumerable: false, configurable: false },
                _timeout: { value: timeout, writable: false, enumerable: false, configurable: false },
                _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                _abortFunc: { value: undefined, writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {boolean} true if the oepration has been aborted.
         */
        isAborted: function isAborted() {
            return this._aborted;
        },

        /**
         * Abort the operation. The service cannot be used after being aborted.
         */
        abort: function abort() {
            this._aborted = true;
            if (this._abortFunc)
                this._abortFunc.call(this);
        },

        /**
         * Set the abort function. This replaces any previous abort function.
         *
         * @param {?function()} func the abort function. Null to unset.
         */
        setAbort: function setAbort(func) {
            this._abortFunc = func;
        },

        /**
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback will receive true on success or false
         *        if cancelled or interrupted and notified of a timeout or any
         *        thrown exceptions.
         * @throws MslException if there was an error creating the response.
         * @throws IOException if there was an error writing the message.
         */
        call: function call(callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // Identify the correct MSL error.
                var err;
                if (this._appError == ApplicationError.ENTITY_REJECTED) {
                    err = (this._request.masterToken)
                        ? MslError.MASTERTOKEN_REJECTED_BY_APP
                        : MslError.ENTITY_REJECTED_BY_APP;
                } else if (this._appError == ApplicationError.USER_REJECTED) {
                    err = (this._request.userIdToken)
                        ? MslError.USERIDTOKEN_REJECTED_BY_APP
                        : MslError.USER_REJECTED_BY_APP;
                } else {
                    throw new MslInternalException("Unhandled application error " + this._appError + ".");
                }

                // Build and send the error response.
                var caps = this._request.messageCapabilities;
                var languages = (caps) ? caps.languages : null;
                var userMessage = this._ctrl.messageRegistry.getUserMessage(err, languages);
                sendError(this, this._ctrl, this._ctx, this._msgCtx.getDebugContext(), this._request.messageId, err, userMessage, this._output, this._timeout, {
                    result: function(success) { callback.result(success); },
                    timeout: callback.timeout,
                    error: function(e) {
                        InterruptibleExecutor(callback, function() {
                            // If we were cancelled then return false.
                            if (cancelled(e)) return false;

                            if (e instanceof MslException) {
                                // We failed to return an error response. Deliver the exception
                                // to the application.
                                callback.error(e);
                            }

                            // An unexpected exception occurred.
                            throw new MslInternalException("Error building the error response.", e);
                        }, self);
                    }
                });
            }, self);
        },
    });

    /**
     * The null close handler is used to close output streams without caring if
     * the close operation is successful or not.
     *
     * TODO: Log failures/errors.
     */
    var NULL_CLOSE_HANDLER = {
        result: function() {},
        timeout: function() {},
        error: function() {}
    };

    /**
     * <p>This service sends a request to the remote entity and returns the
     * response.</p>
     *
     * <p>This class will only be used by trusted network clients, peer-to-peer
     * clients, and peer-to-peer servers.</p>
     */
    var RequestService = Class.create({
        /**
         * Create a new message request service.
         *
         * @param {MslControlImpl} ctrl parent MSL control.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {?Url} remoteEntity remote entity URL.
         * @param {?InputStream} input remote entity input stream.
         * @param {?OutputStream} output remote entity output stream.
         * @param {?{builder: MessageBuilder, tokenTicket: ?TokenTicket}} builderTokenTicket request message builder.
         * @param {Receive} expectResponse response expectation.
         * @param {number} msgCount number of messages that have already been
         *        sent or received.
         * @param {number} timeout connect, read/write, and renewal lock
         *        acquisition timeout in milliseconds.
         */
        init: function init(ctrl, ctx, msgCtx, remoteEntity, input, output, builderTokenTicket, expectResponse, msgCount, timeout) {
            var builder, tokenTicket;
            if (builderTokenTicket) {
                builder = builderTokenTicket.builder;
                tokenTicket = builderTokenTicket.tokenTicket;
            } else {
                builder = null;
                tokenTicket = null;
            }

            // The properties.
            var props = {
                _ctrl: { value: ctrl, writable: false, enumerable: false, configurable: false },
                _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                _msgCtx: { value: msgCtx, writable: false, enumerable: false, configurable: false },
                _remoteEntity: { value: remoteEntity, writable: false, enumerable: false, configurable: false },
                _input: { value: input, writable: true, enumerable: false, configurable: false },
                _output: { value: output, writable: true, enumerable: false, configurable: false },
                _openedStreams: { value: false, writable: true, enumerable: false, configurable: false },
                _builder: { value: builder, writable: true, enumerable: false, configurable: false },
                _tokenTicket: { value: tokenTicket, writable: true, enumerable: false, configurable: false },
                _expectResponse: { value: expectResponse, writable: false, enumerable: false, configurable: false },
                _timeout: { value: timeout, writable: false, enumerable: false, configurable: false },
                _msgCount: { value: msgCount, writable: false, enumerable: false, configurable: false },
                _maxMessagesHit: { value: false, writable: true, enumerable: false, configurable: false },
                _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                _abortFunc: { value: undefined, writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {boolean} true if the oepration has been aborted.
         */
        isAborted: function isAborted() {
            return this._aborted;
        },

        /**
         * Abort the operation. The service cannot be used after being aborted.
         */
        abort: function abort() {
            this._aborted = true;
            if (this._abortFunc)
                this._abortFunc.call(this);
        },

        /**
         * Set the abort function. This replaces any previous abort function.
         *
         * @param {?function()} func the abort function. Null to unset.
         */
        setAbort: function setAbort(func) {
            this._abortFunc = func;
        },

        /**
         * <p>Send the provided request and receive a response from the remote
         * entity. Any necessary handshake messages will be sent.</p>
         *
         * <p>If an error was received and cannot be handled the returned MSL
         * channel will have {@code null} for its message output stream.</p>
         *
         * @param {MessageContext} msgCtx message context.
         * @param {{builder: MessageBuilder, tokenTicket: ?TokenTicket}}
         *        builderTokenTicket request message builder and master token /
         *        lock ticket.
         * @param {number} timeout renewal lock acquisition timeout in milliseconds.
         * @param {number} msgCount number of messages sent or received so far.
         * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
         *        callback the callback will be given the established MSL
         *        channel or {@code null} if cancelled or if the maximum message
         *        count is hit; notified of timeout or any thrown exceptions.
         * @throws MslException if there was an error creating or processing
         *         a message.
         * @throws IOException if there was an error reading or writing a
         *         message.
         * @throws InterruptedException if the thread is interrupted while
         *         trying to acquire a master token's read lock.
         */
        execute: function execute(msgCtx, builderTokenTicket, timeout, msgCount, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                // Do not do anything if cannot send and receive two more messages.
                //
                // Make sure to release the master token lock.
                if (msgCount + 2 > MslConstants.MAX_MESSAGES) {
                    var tokenTicket = builderTokenTicket.tokenTicket;
                    this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                    this._maxMessagesHit = true;
                    return null;
                }

                // Send the request and receive the response. This adds two to our
                // message count.
                //
                // This will release the master token lock.
                this._ctrl.sendReceive(this, this._ctx, msgCtx, this._input, this._output, builderTokenTicket, this._expectResponse, this._openedStreams, timeout, {
                    result: function(result) {
                        InterruptibleExecutor(callback, function() {
                            if (!result)
                                return null;
                            var request = result.request;
                            var response = result.response;
                            msgCount += 2;

                            // If we did not receive a response then we're done. Return the
                            // new message output stream.
                            if (!response)
                                return new MslChannel(response, request);
                            
                            // If the response is an error see if we can handle the error and
                            // retry.
                            var responseHeader = response.getMessageHeader();
                            if (!responseHeader)
                                prepareError(result);
                            else
                                processResponse(result);
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);

            /**
             * Close the message output stream.
             *
             * @param {SendReceiveResult} result the send/receive result.
             * @param {function(boolean)} func a callback function that will
             *        receive true if the close was successful, timed out, or
             *        threw an I/O exception or false if cancelled or aborted.
             */
            function closeRequest(result, func) {
                var request = result.request;
                request.close(self._timeout, {
                    result: function(success) {
                        func.call(self, success);
                    },
                    timeout: function() {
                        // We don't care about timeout.
                        func.call(self, true);
                    },
                    error: function(e) {
                        // If we were cancelled then return false.
                        if (cancelled(e)) func.call(self, false);
                        // Otherwise we don't care about an I/O exception on close.
                        func.call(self, true);
                    }
                });
            }

            /**
             * Close the message output stream and message input stream.
             *
             * @param {SendReceiveResult} result the send/receive result.
             * @param {function(boolean)} func a callback function that will
             *        receive true if the close was successful, timed out, or
             *        threw an I/O exception or false if cancelled or aborted.
             */
            function closeRequestAndResponse(result, func) {
                // Close the request.
                closeRequest(result, function(success) {
                    // If cancelled or aborted return immediately.
                    if (!success) {
                        func.call(self, false);
                        return;
                    }

                    // Close the response.
                    var response = result.response;
                    response.close(self._timeout, {
                        result: function(success) {
                            func.call(self, success);
                        },
                        timeout: function() {
                            // We don't care about timeout.
                            func.call(self, true);
                        },
                        error: function(e) {
                            // If we were cancelled then return false.
                            if (cancelled(e)) func.call(self, false);
                            // Otherwise we don't care about an I/O exception on close.
                            func.call(self, true);
                        }
                    });
                });
            }

            function prepareError(result) {
                InterruptibleExecutor(callback, function() {
                    // Close the request and response. The response is an error and
                    // the request is not usable.
                    closeRequestAndResponse(result, function(success) {
                        // If cancelled then return null.
                        if (!success) callback.result(null);
                        // Otherwise continue.
                        else handleError(result);
                    });
                }, self);
            }

            function handleError(result) {
                InterruptibleExecutor(callback, function() {
                    // Build the error response. This will acquire the master token
                    // lock.
                    var response = result.response;
                    var errorHeader = response.getErrorHeader();
                    this._ctrl.buildErrorResponse(this, this._ctx, msgCtx, result, errorHeader, timeout, {
                        result: function(errTokenTicket) {
                            InterruptibleExecutor(callback, function() {
                                // If there is no error response then return the error.
                                if (!errTokenTicket)
                                    return new MslChannel(response, null);

                                var errMsg = errTokenTicket.errorResult;
                                var tokenTicket = errTokenTicket.tokenTicket;

                                // In trusted network mode send the response in a new request.
                                // In peer-to-peer mode reuse the connection.
                                var requestBuilder = errMsg.builder;
                                var builderTokenTicket = { builder: requestBuilder, tokenTicket: tokenTicket };
                                var resendMsgCtx = errMsg.msgCtx;
                                if (!this._ctx.isPeerToPeer()) {
                                    // The master token lock acquired from buildErrorResponse()
                                    // will be released when the service executes.
                                    var service = new RequestService(this._ctrl, this._ctx, resendMsgCtx, this._remoteEntity, null, null, builderTokenTicket, this._expectResponse, msgCount, this._timeout);
                                    // Set the abort function to abort the new service before executing
                                    // the service.
                                    this.setAbort(function() { service.abort(); });
                                    service.call({
                                        result: function(newChannel) {
                                            InterruptibleExecutor(callback, function() {
                                                this._maxMessagesHit = service._maxMessagesHit;
                                                processErrorResponse(result, newChannel);
                                            }, self);
                                        },
                                        timeout: callback.timeout,
                                        error: callback.error,
                                    });
                                } else {
                                    // Send the error response. Recursively execute this
                                    // because it may take multiple messages to succeed with
                                    // sending the request.
                                    //
                                    // The master token lock will be released by the recursive
                                    // call to execute().
                                    this.execute(resendMsgCtx, builderTokenTicket, this._timeout, msgCount, {
                                        result: function(newChannel) {
                                            InterruptibleExecutor(callback, function() {
                                                // Release the error message's master token read lock.
                                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                                                processErrorResponse(result, newChannel);
                                            }, self);
                                        },
                                        timeout: function() {
                                            InterruptibleExecutor(callback, function() {
                                                // Release the error message's master token read lock.
                                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                                                callback.timeout();
                                            }, self);
                                        },
                                        error: function(e) {
                                            InterruptibleExecutor(callback, function() {
                                                // Release the error message's master token read lock.
                                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);

                                                callback.error(e);
                                            }, self);
                                        }
                                    });
                                }
                            }, self);
                        },
                        timeout: callback.timeout,
                        error: callback.error,
                    });
                }, self);

                function processErrorResponse(result, newChannel) {
                    InterruptibleExecutor(callback, function() {
                        // If the maximum message count was hit or if there is no new
                        // response then return the original error response.
                        if (this._maxMessagesHit || (newChannel && !newChannel.input))
                            return new MslChannel(result.response, null);

                        // Return the new channel, which may contain an error or be
                        // null if cancelled or interrupted.
                        return newChannel;
                    }, self);
                }
            }

            function processResponse(result) {
                InterruptibleExecutor(callback, function() {
                    var request = result.request;
                    var response = result.response;
                    var responseHeader = response.getMessageHeader();

                    // If we are in trusted network mode...
                    if (!this._ctx.isPeerToPeer()) {
                        // If we did not perform a handshake then we're done. Deliver
                        // the response.
                        if (!result.handshake)
                            return new MslChannel(response, request);

                        // We did perform a handshake and there is buffered application
                        // data. Re-send the message over a new connection.
                        //
                        // Close the request and response. The response will be
                        // discarded and we will be issuing a new request.
                        closeRequestAndResponse(result, function(success) {
                            InterruptibleExecutor(callback, function() {
                                // If unsuccessful then return null.
                                if (!success) return null;

                                // The master token lock acquired from buildResponse() will be
                                // released when the service executes.
                                var resendMsgCtx = new ResendMessageContext(null, msgCtx);
                                this._ctrl.buildResponse(this, this._ctx, msgCtx, responseHeader, timeout, {
                                    result: function(builderTokenTicket) {
                                        InterruptibleExecutor(callback, function() {
                                            var service = new RequestService(this._ctrl, this._ctx, resendMsgCtx, this._remoteEntity, null, null, builderTokenTicket, this._expectResponse, msgCount, this._timeout);
                                            // Set the abort function to abort the new service before executing
                                            // the service.
                                            this.setAbort(function() { service.abort(); });
                                            service.call(callback);
                                        }, self);
                                    },
                                    timeout: callback.timeout,
                                    error: callback.error,
                                });
                            }, self);
                        });
                        return;
                    }

                    // We are in peer-to-peer mode...
                    //
                    // If we did perform a handshake. Re-send the message over the same
                    // connection to allow the application to send its data. This may
                    // also return key response data.
                    if (result.handshake) {
                        // Close the request and response. The response will be
                        // discarded and we will be issuing a new request.
                        closeRequestAndResponse(result, function(success) {
                            InterruptibleExecutor(callback, function() {
                                // If cancelled then return null.
                                if (!success) return null;

                                // Now resend.
                                //
                                // The master token lock acquired from buildResponse() will be
                                // released by the recursive call to execute().
                                var resendMsgCtx = new ResendMessageContext(null, msgCtx);
                                this._ctrl.buildResponse(this, this._ctx, msgCtx, responseHeader, timeout, {
                                    result: function(builderTokenTicket) {
                                        this.execute(resendMsgCtx, builderTokenTicket, this._timeout, msgCount, callback);
                                    },
                                    timeout: callback.timeout,
                                    error: callback.error,
                                });
                            }, self);
                        });
                        return;
                    }

                    // Otherwise we did send our application data (which may have been
                    // zero-length) so we do not need to re-send our message.
                    //
                    // If the response contains key request data, or is renewable and
                    // contains a master token and user authentication data, then we
                    // need to return a response to perform key exchange and/or provide
                    // a user ID token.
                    var responseKeyxData = responseHeader.keyRequestData;
                    if (responseKeyxData.length > 0 ||
                        (responseHeader.isRenewable() && responseHeader.masterToken && responseHeader.userAuthenticationData))
                    {
                        // Build the response. This will acquire the master token lock.
                        var keyxMsgCtx = new KeyxResponseMessageContext(msgCtx);
                        this._ctrl.buildResponse(this, this._ctx, keyxMsgCtx, responseHeader, timeout, {
                            result: function(builderTokenTicket) {
                                InterruptibleExecutor(callback, function() {
                                    var keyxBuilder = builderTokenTicket.builder;
                                    var tokenTicket = builderTokenTicket.tokenTicket;

                                    // If the response is not a handshake message then we do not
                                    // expect a reply.
                                    response.isHandshake(this._timeout, {
                                        result: function(handshake) {
                                            InterruptibleExecutor(callback, function() {
                                                if (!handshake) {
                                                    // Close the request as we are issuing a new request.
                                                    closeRequest(result, function(success) {
                                                        InterruptibleExecutor(callback, function() {
                                                            // If cancelled return null.
                                                            if (!success) {
                                                                // Release the master token read lock.
                                                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                                                                return null;
                                                            }

                                                            // The remote entity is expecting a response. We need
                                                            // to send it even if this exceeds the maximum number of
                                                            // messages. We're guaranteed to stop sending more
                                                            // messages after this response.
                                                            //
                                                            // Return the original message input stream and the new
                                                            // message output stream to the caller.
                                                            keyxBuilder.setRenewable(false);
                                                            this._ctrl.send(this, this._ctx, keyxMsgCtx, this._output, keyxBuilder, this._timeout, {
                                                                result: function(newResult) {
                                                                    InterruptibleExecutor(callback, function() {
                                                                        // Release the master token read lock.
                                                                        this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                                                                        return new MslChannel(response, newResult.request);
                                                                    }, self);
                                                                },
                                                                timeout: function() {
                                                                    InterruptibleExecutor(callback, function() {
                                                                        // Release the master token read lock.
                                                                        this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                                                                        callback.timeout();
                                                                    }, self);
                                                                },
                                                                error: function(e) {
                                                                    InterruptibleExecutor(callback, function() {
                                                                        // Release the master token read lock.
                                                                        this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                                                                        callback.error(e);
                                                                    }, self);
                                                                }
                                                            });
                                                        }, self);
                                                    });
                                                }

                                                // Otherwise the remote entity may still have to send us the
                                                // application data in a reply.
                                                else {
                                                    // Close the request and response. The response will be
                                                    // discarded and we will be issuing a new request.
                                                    closeRequestAndResponse(result, function(success) {
                                                        InterruptibleExecutor(callback, function() {
                                                            // If cancelled return null.
                                                            if (!success) {
                                                                // Release the master token read lock.
                                                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                                                                return null;
                                                            }

                                                            // The master token lock acquired from buildResponse() will be
                                                            // released by the recursive call to execute().
                                                            self.execute(keyxMsgCtx, keyxBuilder, this._timeout, msgCount, callback);
                                                        }, self);
                                                    });
                                                }
                                            }, self);
                                        },
                                        timeout: function() {
                                            InterruptibleExecutor(callback, function() {
                                                // Release the master token read lock.
                                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                                                callback.timeout();
                                            }, self);
                                        },
                                        error: function(e) {
                                            InterruptibleExecutor(callback, function() {
                                                // Release the master token read lock.
                                                this._ctrl.releaseMasterToken(this._ctx, tokenTicket);
                                                callback.error(e);
                                            }, self);
                                        }
                                    });
                                }, self);
                            },
                            timeout: callback.timeout,
                            error: callback.error,
                        });
                        return;
                    }

                    // Return the established MSL channel to the caller.
                    return new MslChannel(response, request);
                }, self);
            }
        },

        /**
         * @param {{result: function(MslChannel), timeout: function(), error: function(Error)}}
         *        callback the callback will be given the established MSL
         *        channel or {@code null} if cancelled or interrupted; notified
         *        of timeout or any thrown exceptions.
         * @throws MslException if there was an error creating or processing
         *         a message.
         * @throws IOException if there was an error reading or writing a
         *         message.
         */
        call: function call(callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                // If we do not already have a connection then establish one.
                var lockTimeout = this._timeout;
                if (!this._input || !this._output) {
                    try {
                        // Set up the connection.
                        this._remoteEntity.setTimeout(this._timeout);

                        // Grab the input and output streams. Keep track of how
                        // much time this takes to subtract that from the lock
                        // timeout.
                        var start = Date.now();
                        var conn = this._remoteEntity.openConnection();
                        this._output = conn.output;
                        this._input = conn.input;
                        if (lockTimeout != -1) {
                           lockTimeout = this._timeout - (Date.now() - start);
                        }
                        this._openedStreams = true;
                    } catch (e) {
                        // If a message builder was provided then release the
                        // master token read lock.
                        if (this._builder)
                            this._ctrl.releaseMasterToken(this._ctx, this._tokenTicket);

                        // Close any open streams.
                        // We don't care about an I/O exception on close.
                        if (this._output) this._output.close(this._timeout, NULL_CLOSE_HANDLER);
                        if (this._input) this._input.close(this._timeout, NULL_CLOSE_HANDLER);

                        // If we were cancelled then return null.
                        if (cancelled(e)) return null;
                        throw e;
                    }
                }

                // If no builder was provided then build a new request. This will
                // acquire the master token lock.
                if (!this._builder) {
                    this._ctrl.buildRequest(this, this._ctx, this._msgCtx, this._timeout, {
                        result: function(builderTokenTicket) {
                            InterruptibleExecutor(callback, function() {
                                var builder = builderTokenTicket.builder;
                                var tokenTicket = builderTokenTicket.tokenTicket;
                                perform(builder, tokenTicket, lockTimeout);
                            }, self);
                        },
                        timeout: function() {
                            InterruptibleExecutor(callback, function() {
                                // Close the streams if we opened them.
                                // We don't care about an I/O exception on close.
                                if (this._openedStreams) {
                                    this._output.close(this._timeout, NULL_CLOSE_HANDLER);
                                    this._input.close(this._timeout, NULL_CLOSE_HANDLER);
                                }
                                callback.timeout();
                            }, self);
                        },
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // Close the streams if we opened them.
                                // We don't care about an I/O exception on close.
                                if (this._openedStreams) {
                                    this._output.close(this._timeout, NULL_CLOSE_HANDLER);
                                    this._input.close(this._timeout, NULL_CLOSE_HANDLER);
                                }

                                // If we were cancelled then return null.
                                if (cancelled(e)) return null;

                                callback.error(e);
                            }, self);
                        }
                    });
                } else {
                    perform(this._builder, this._tokenTicket, lockTimeout);
                }
            }, self);

            function perform(builder, tokenTicket, lockTimeout) {
                InterruptibleExecutor(callback, function() {
                    // Execute. This will release the master token lock.
                    var builderTokenTicket = { builder: builder, tokenTicket: tokenTicket };
                    this.execute(this._msgCtx, builderTokenTicket, lockTimeout, this._msgCount, {
                        result: function(channel) {
                            InterruptibleExecutor(callback, function() {
                                // If the channel was established clear the cached payloads.
                                if (channel && channel.output)
                                    channel.output.stopCaching();
                                
                                // Close the input stream if we opened it and there is no
                                // response. This may be necessary to transmit data
                                // buffered in the output stream, and the caller will not
                                // be given a message input stream by which to close it.
                                //
                                // We don't care about an I/O exception on close.
                                if (this._openedStreams && (!channel || !channel.input))
                                    this._input.close(lockTimeout, NULL_CLOSE_HANDLER);

                                // Return the established channel.
                                return channel;
                            }, self);
                        },
                        timeout: function() {
                            InterruptibleExecutor(callback, function() {
                                // Close the streams if we opened them.
                                // We don't care about an I/O exception on close.
                                if (this._openedStreams) {
                                    this._output.close(lockTimeout, NULL_CLOSE_HANDLER);
                                    this._input.close(lockTimeout, NULL_CLOSE_HANDLER);
                                }
                                callback.timeout();
                            }, self);
                        },
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // Close the streams if we opened them.
                                // We don't care about an I/O exception on close.
                                if (this._openedStreams) {
                                    this._output.close(lockTimeout, NULL_CLOSE_HANDLER);
                                    this._input.close(lockTimeout, NULL_CLOSE_HANDLER);
                                }

                                // If we were cancelled then return null.
                                if (cancelled(e)) return null;
                                callback.error(e);
                            }, self);
                        }
                    });
                }, self);
            }
        }
    });
    
    /**
     * <p>This service sends a message to a remote entity.</p>
     *
     * <p>This class is only used from trusted network clients and peer-to-peer
     * entities.</p>
     */
    var SendService = Class.create({
        /**
         * Create a new message send service.
         *
         * @param {MslControlImpl} ctrl parent MSL control.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {?Url} remoteEntity remote entity URL.
         * @param {?InputStream} input remote entity input stream.
         * @param {?OutputStream} output remote entity output stream.
         * @param {number} timeout connect, read/write, and renewal lock
         *        acquisition timeout in milliseconds.
         */
        init: function init(ctrl, ctx, msgCtx, remoteEntity, input, output, timeout) {
            var requestService = new RequestService(ctrl, ctx, msgCtx, remoteEntity, input, output, null, Receive.NEVER, 0, timeout);
            
            // The properties.
            var props = {
                _requestService: { value: requestService, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @param {{result: function(MessageOutputStream), timeout: function(), error: function(Error)}}
         *        callback the callback will be given the established message
         *        output stream or {@code null} if cancelled or interrupted;
         *        notified of timeout or any thrown exceptions.
         * @throws MslException if there was an error creating or processing
         *         a message.
         * @throws IOException if there was an error reading or writing a
         *         message.
         */
        call: function call(callback){
            this._requestService.call({
                result: function(channel) {
                    AsyncExecutor(callback, function() {
                        return (channel) ? channel.output : null;
                    });
                },
                timeout: callback.timeout,
                error: callback.error,
            });
        },
    });

    /**
     * <p>This service sends a message to the remote entity using a request as
     * the basis for the response.</p>
     * 
     * <p>This class will only be used trusted network servers.</p>
     */
    var PushService = RespondService.extend({    
        /**
         * Create a new message push service.
         * 
         * @param {MslControlImpl} ctrl parent MSL control.
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {InputStream} input remote entity input stream.
         * @param {OutputStream} output remote entity output stream.
         * @param {MessageInputStream} request request message input stream.
         * @param {number} timeout renewal lock acquisition timeout in milliseconds.
         */
        init: function init(ctrl, ctx, msgCtx, input, output, request, timeout) {
            init.base.call(ctrl, ctx, msgCtx, input, output, request, timeout);
        },
        
        /**
         * @param {{result: function(MslChannel), timeout: function(), error: function(Error)}}
         *        callback the callback will be given the established
         *        {@link MslChannel} on success or {@code null} if cancelled or
         *        interrupted, if the response could not be sent encrypted or
         *        integrity protected when required, or if the maximum number
         *        of messages is hit.
         * @throws MslException if there was an error creating the response.
         * @throws MslErrorResponseException if there was an error sending an
         *         automatically generated error response.
         * @throws IOException if there was an error writing the message.
         * @see java.util.concurrent.Callable#call()
         */
        call: function call(callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                var debugCtx = this._msgCtx.getDebugContext();
                
                var requestHeader = this._request.getMessageHeader();
                this._ctrl.buildDetachedResponse(this._ctx, this._msgCtx, requestHeader, {
                    result: function(builderTokenTicket) {
                        self.trustedNetworkExecute(builderTokenTicket, 0, {
                            result: function(channel) {
                                InterruptibleExecutor(callback, function() {
                                    // Clear any cached payloads.
                                    if (channel)
                                        channel.output.stopCaching();

                                    // Return the established channel.
                                    return channel;
                                }, self);
                            },
                            timeout: callback.timeout,
                            error: function(e) {
                                InterruptibleExecutor(callback, function() {
                                    // If we were cancelled then return null.
                                    if (cancelled(e)) return null;

                                    // Maybe we can send an error response.
                                    var builder = builderTokenTicket.builder;
                                    var requestMessageId = MessageBuilder.decrementMessageId(builder.getMessageId());
                                    var mslError, userMessage, toThrow;
                                    if (e instanceof MslException) {
                                        mslError = e.error;
                                        var caps = requestHeader.messageCapabilities;
                                        var languages = (caps) ? caps.languages : null;
                                        userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, languages);
                                        toThrow = e;
                                    } else if (e instanceof MslIoException) {
                                        mslError = MslError.MSL_COMMS_FAILURE;
                                        userMessage = null;
                                        toThrow = e;
                                    } else {
                                        mslError = MslError.INTERNAL_EXCEPTION;
                                        userMessage = null;
                                        toThrow = new MslInternalException("Error pushing the message.", e);
                                    }
                                    sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                        result: function(success) { callback.error(toThrow); },
                                        timeout: callback.timeout,
                                        error: function(re) {
                                            InterruptibleExecutor(callback, function() {
                                                // If we were cancelled then return null.
                                                if (cancelled(re)) return null;

                                                throw new MslErrorResponseException("Error pushing the message.", re, null);
                                            }, self);
                                        }
                                    });
                                }, self);
                            }
                        });
                    },
                    timeout: callback.timeout,
                    error: function(e) {
                        InterruptibleExecutor(callback, function() {
                            // If we were cancelled then return null.
                            if (cancelled(e)) return null;

                            // Try to send an error response.
                            var requestMessageId, mslError, userMessage, toThrow;
                            if (e instanceof MslException) {
                                requestMessageId = e.messageId;
                                mslError = e.error;
                                var caps = requestHeader.messageCapabilities;
                                var languages = (caps) ? caps.languages : null;
                                userMessage = this._ctrl.messageRegistry.getUserMessage(mslError, languages);
                                toThrow = e;
                            } else {
                                requestMessageId = null;
                                mslError = MslError.INTERNAL_EXCEPTION;
                                userMessage = null;
                                toThrow = new MslInternalException("Error building the message.", e);
                            }
                            sendError(this, this._ctrl, this._ctx, debugCtx, requestHeader, requestMessageId, mslError, userMessage, this._output, this._timeout, {
                                result: function(success) { callback.error(toThrow); },
                                timeout: callback.timeout,
                                error: function(re) {
                                    InterruptibleExecutor(callback, function() {
                                        // If we were cancelled then return null.
                                        if (cancelled(re)) return null;

                                        throw new MslErrorResponseException("Error building the message.", re, e);
                                    }, self);
                                }
                            });
                        }, self);
                    }
                });
            }, self);
        }
    });
    
    // Exports.
    module.exports.ApplicationError = ApplicationError;
    module.exports.MslChannel = MslChannel;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslControl'));

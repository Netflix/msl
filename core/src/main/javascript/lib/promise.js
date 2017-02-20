/*
 * 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2014 Mick Hakobyan
 * https://github.com/chnobean/Promise/blob/master/LICENSE
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */

/*
 * 
 * Tweaks to the original:
 *  
 *  Polyfills window.Promise (instead of window.chnobean.Promise)
 *  CONVERT_THENABLES = false
 *  ALWAYS_RESOLVE_SYNCHRONIOUSLY = true;
 *  Module
 *
 */

(function(require, module) {
	"use strict";

    /**
    * @const
    * Should thenables be detected and converter automatically. This does impacts performance.
    */
    var CONVERT_THENABLES = false;

    /**
    * @const
    * Spec says we should dispatch the calls to func(onResolved, onRejected), 
    * so it runs only after client code is done.
    * We can gain perf by not having to setTimeout.
    */
    var ALWAYS_RESOLVE_SYNCHRONIOUSLY = true;

    /**
    * Guard against variable named "undefined" being declared in global context.
    */
    var undefined;

    /**
    * @constructor
    * @param {function(function(*=), function(*=))} resolver
    */
    var Promise = module.exports = function Promise(resolver) {
        var promise = this;
        if (resolver) {
            try {
                resolver(
                    function fulfill(result) {
                        Promise_fulfill(promise, result);
                    },
                    function reject(result) {
                        Promise_reject(promise, result);
                    }
                );
            } catch(e) {
                Promise_reject(this, e);
            }
        }
    };

    /**
    * @param {function(*=)=} onFulfilled is executed when this promise is fulfilled
    * @param {function(*=)=} onRejected is executed when this promise is rejected
    */
    Promise.prototype.then = function Promise_then(onFulfilled, onRejected) {
        var promise = Promise_create();
        if (typeof onFulfilled === 'function') {
            promise._onFulfilled = onFulfilled;
        }
        if (typeof onRejected === 'function') {
            promise._onRejected = onRejected; 
        }
        Promise_whenResolved(this, promise);
        return promise;
    };

    /**
    * @param {function()} onRejected
    *
    * Sugar for promise.then(undefined, onRejected)
    */
    Promise.prototype.catch = function Promise_catch(onRejected) {
        return this.then(undefined, onRejected);
    };

    /**
    * @param {*=} result
    *
    * Creates a promise resolved for result.
    */
    Promise.resolve = function Promise_createFulfilled(result) {
        var promise = Promise_create();
        Promise_fulfill(promise, result);
        return promise;
    };

    /**
    * @param {*=} result
    *
    * Creates a promise rejected with result.
    */
    Promise.reject = function Promise_createRejected(result) {
        var promise = Promise_create();
        Promise_reject(promise, result);
        return promise;
    };

    /**
    * @param {Array.<*>} promises
    *
    * Given array of promises or results, either resolves to array of results,
    * or rejects if any of the promises reject.
    */
    Promise.all = function Promise_all(promises) {
        var promise = Promise_create(),
            length = promises.length,
            results = [],
            // start +1, so we handle when there are no promises
            remaining = 1, 
            result,
            i;

        function onFulfilled(index, result) {
            results[index] = result;
            if (!(--remaining)) {
                Promise_fulfill(promise, results, true);    
            }
        }

        function onRejected(result) {
            Promise_reject(promise, result, true);
        }

        // TODO: handle CONVERT_THENABLES
        for(i = 0; i < length; i++) {
            result = promises[i];
            if (result && result._isPromise) {
                // it's a promise
                remaining++;
                result.then(
                    onFulfilled.bind(undefined, i),
                    onRejected
                );
            } else {
                results[i] = result;
            }
        }

        if (!(--remaining)) {
            // all were resolved before we even got here
            promise._fulfilled = true;
            promise._result = results;
        }

        return promise;
    };

    // --------------------------------------------------------------------------------
    // -- private implementation
    // --------------------------------------------------------------------------------

    /**
    * Used instead of "instanceof" for performance reasons.
    */
    Promise.prototype._isPromise = true;

    /**
    * Creates a promise without running the constructor function.
    */
    function Promise_create() {
        return Object.create(Promise.prototype);
    }

    /**
    * @param {boolean=} allowSynchResolution
    * Fulfill the promise and resolve deferrals
    */
    function Promise_fulfill(promise, result, allowSynchResolution) {
        if (promise._fulfilled === undefined) {
            if (CONVERT_THENABLES) {
                Promise_fulfillThenable(promise, result);
            } else {
                promise._fulfilled = true;
                promise._result = result;
            }
            Promise_resolveDeferred(promise, allowSynchResolution);
        }
    }

    /**
    * @param {boolean=} allowSynchResolution
    * Reject the promise and resolve deferrals
    */
    function Promise_reject(promise, result, allowSynchResolution) {
        if (promise._fulfilled === undefined) {
            promise._fulfilled = false;
            promise._result = result;
            Promise_resolveDeferred(promise, allowSynchResolution);
        }
    }

    /**
    * Fulfill the promise, but check for result to be a thenable.
    * Thenable is an object that has obj.then(function resolve(){}, function reject(){}), 
    * such as this or any other Promise implementations.
    */
    function Promise_fulfillThenable(promise, result) {
        var then;
        if (!result || typeof result === 'number' || typeof result === 'boolean' || result._isPromise) {
            // if the result is a primitive type, 
            // or is a promise, use it as it is
            promise._fulfilled = true;
            promise._result = result;
        } else {
            try {
                // is this a then-able (has a ['then'] function), convert it to a Promise
                // handle "then" accessor throwing
                then = result.then;
                promise._fulfilled = true;
                if (typeof then !== 'function') {
                    // not a thenable, just use the result
                    promise._result = result;
                } else {
                    // convert the thenable to a promise
                    promise._result = new Promise(function (resolve, reject) {
                        then.call(result, resolve, reject);
                    });
                }
            } catch(e) {
                promise._fulfilled = false;
                promise._result = e;
            }
        }
    }

    /**
    * Once promise is resolved, resolve nextPromise
    */
    function Promise_whenResolved(promise, nextPromise) {
        if (promise._fulfilled !== undefined) {
            // we are resolved, resolve the given promise
            Promise_resolve(nextPromise, promise._fulfilled, promise._result);
        } else {
            // defer the resolution
            if (!promise._deferred) {
                promise._deferred = [];
            }
            promise._deferred.push(nextPromise);
        }
    }

    /**
    * @param {boolean=} allowSynchResolution
    * Resolves deffered promises
    */
    function Promise_resolveDeferred(promise, allowSynchResolution) {
        // assert(promise._fulfilled !== undefined)
        var deferred = promise._deferred,
            deferredLength,
            i;
        if (deferred) {
            promise._deferred = undefined;
            deferredLength = deferred.length;
            for(i = 0; i < deferredLength; i++) {
                Promise_resolve(deferred[i], promise._fulfilled, promise._result, allowSynchResolution);
            }
        }
    }  

    /**
    * @param {boolean=} allowSynchResolution
    * Resolves promise (called by the one before, when it's resolved)
    */
    function Promise_resolve(promise, fulfilled, result, allowSynchResolution) {
        // assert(fulfilled !== undefined)
        var handler;

        if (fulfilled && result && result._isPromise) {
            // previous promise resolved to a promise, forward the promose
            Promise_whenResolved(result, promise);
        } else {
            // resolve promise
            // what handler will we use: onFulfilled or onRejected?
            if (fulfilled) {
                handler = promise._onFulfilled;
            } else {
                handler = promise._onRejected;
            }
            // kill the onFulfilled and onRejected we got from .then(onFulfilled, onRejected)
            promise._onFulfilled = undefined;
            promise._onRejected = undefined;
            // if there is a handler, dispatch... otherwise just settle in-line
            if (handler) {
                if (allowSynchResolution || ALWAYS_RESOLVE_SYNCHRONIOUSLY) {
                    // this flag indicates that this stack originated from the setTimeout
                    // no need to set another Timeout, and just run in same stack
                    Promise_handleResolution(promise, handler, result);
                } else {
                    // stack starts from user code, setTimeout so we start a new stack with only our code
                    // Spec quote: onFulfilled or onRejected must not be called until the 
                    //             execution context stack contains only platform code.
                    setTimeout(Promise_handleResolution.bind(undefined, promise, handler, result), 0);
                }
            } else {
                if (fulfilled) {
                    Promise_fulfill(promise, result, allowSynchResolution);
                } else {
                    Promise_reject(promise, result, allowSynchResolution);
                }
            }
        }
    }

    /**
    * Call the handler: onFulfilled(result) or onRejected(result). And fulfill or reject based on outcome.
    */
    function Promise_handleResolution(promise, handler, result) {
        try {
            var newResult = handler(result);
            if (newResult === promise) {
                throw new TypeError();
            }
            Promise_fulfill(promise, newResult, true);
        } catch(e) {
            Promise_reject(promise, e, true);
        }
    }
})(require, (typeof module !== 'undefined') ? module : mkmodule('Promise'));
/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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

const ConditionVariable = require('../../../../../core/src/main/javascript/util/ConditionVariable.js');
const Random = require('../../../../../core/src/main/javascript/util/Random.js');

describe("ConditionVariable", function() {
    var TIMEOUT = 150;
    var DELAY = 1;
    var NAME = "name";
    
    /**
     * Create a new signal counter.
     * 
     * The number of successful signals will be counted in in the signaled
     * property. The number of cancellations will be counted in the cancelled
     * property.
     * 
     * The lastName property will be set when a specific callback is signaled
     * or cancelled.
     * 
     * A new ConditionVariable.wait() callback with the specified name can be
     * created by calling the getCallback() function.
     */
    function SignalCounter() {
        var self = this;
        this.signaled = 0;
        this.cancelled = 0;
        this.lastName = undefined;
        this.getCallback = function getCallback(name) {
            return {
                result: function(signaled) {
                    self.lastName = name;
                    if (signaled) ++self.signaled;
                    else ++self.cancelled;
                },
                timeout: function() {
                    expect(function() { throw new Error(name + " timedout"); }).not.toThrow();
                },
                error: function(e) {
                    expect(function() { throw e; }).not.toThrow();
                }
            };
        };
    }
    
    var random = new Random();
    var nameCount = 0;
    var cv, counter;
    
    /** Return the next signal name. */
    function nextName() {
        return NAME + nameCount++;
    }
    
    beforeEach(function() {
        cv = new ConditionVariable();
        counter = new SignalCounter();
        nameCount = 0;
    });
    
    it("wait and signal", function() {
        runs(function() {
            var t = cv.wait(TIMEOUT, counter.getCallback(NAME));
            expect(t).toBeDefined();
            setTimeout(function() { cv.signal(); }, DELAY);
            expect(counter.signaled).toEqual(0);
        });
        waitsFor(function() { return counter.signaled == 1; }, "signaled", 100);
    });
    
    it("wait and signal all", function() {
        runs(function() {
            var t = cv.wait(TIMEOUT, counter.getCallback(NAME));
            expect(t).toBeDefined();
            setTimeout(function() { cv.signalAll(); }, DELAY);
            expect(counter.signaled).toEqual(0);
        });
        waitsFor(function() { return counter.signaled == 1; }, "signaled", 100);
    });
    
    it("multiple wait and signal", function() {
        var names = [];
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                names.push(name);
                var t = cv.wait(TIMEOUT, counter.getCallback(name));
                expect(t).toBeDefined();
            }
            expect(counter.signaled).toEqual(0);
        });
        waitsFor(function() { return names.length == 3; }, "names", 100);

        runs(function() {
            setTimeout(function() { cv.signal(); }, DELAY);
        });
        waitsFor(function() { return counter.signaled == 1; }, "first", 100);
        
        runs(function() {
            var expectedName = names.shift();
            expect(counter.lastName).toEqual(expectedName);
            setTimeout(function() { cv.signal(); }, DELAY);
        });
        waitsFor(function() { return counter.signaled == 2; }, "second", 100);
        
        runs(function() {
            var expectedName = names.shift();
            expect(counter.lastName).toEqual(expectedName);
            setTimeout(function() { cv.signal(); }, DELAY);
        });
        waitsFor(function() { return counter.signaled == 3; }, "third", 100);
        
        runs(function() {
            var expectedName = names.shift();
            expect(counter.lastName).toEqual(expectedName);
        });
    });
    
    it("multiple wait and signal all", function() {
        var names = [];
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                names.push(name);
                var t = cv.wait(TIMEOUT, counter.getCallback(name));
                expect(t).toBeDefined();
            }
            expect(counter.signaled).toEqual(0);
            setTimeout(function() { cv.signalAll(); }, DELAY);
        });
        waitsFor(function() { return names.length == 3 && counter.signaled == 3; }, "signaled", 100);
        
        runs(function() {
            var lastName = names.pop();
            expect(counter.lastName).toEqual(lastName);
        });
    });
    
    it("wait forever", function() {
        var passed = false;
        runs(function() {
            var signaled = false;
            cv.wait(-1, {
                result: function(x) { signaled = x; },
                timeout: function() { expect(function() { throw Error("timedout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            setTimeout(function() {
                expect(signaled).toBeFalsy();
                passed = true;
            }, DELAY);
        });
        waitsFor(function() { return passed; }, "passed", 100);
    });
    
    it("cancel", function() {
        runs(function() {
            var ticket = cv.wait(TIMEOUT, counter.getCallback(NAME));
            setTimeout(function() { cv.cancel(ticket); }, DELAY);
        });
        waitsFor(function() { return counter.cancelled == 1; }, "cancelled", 100);
    });
    
    it("cancel multiple", function() {
        var names = [];
        var tickets = [];
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                names.push(name);
                var t = cv.wait(TIMEOUT, counter.getCallback(name));
                expect(t).toBeDefined();
                tickets.push(t);
            }
            expect(counter.cancelled).toEqual(0);
        });
        waitsFor(function() { return names.length == 3 && tickets.length == 3; }, "names & tickets", 100);

        runs(function() {
            setTimeout(function() { cv.cancel(tickets.shift()); }, DELAY);
        });
        waitsFor(function() { return counter.cancelled == 1; }, "first", 100);
        
        runs(function() {
            var expectedName = names.shift();
            expect(counter.lastName).toEqual(expectedName);
            setTimeout(function() { cv.cancel(tickets.shift()); }, DELAY);
        });
        waitsFor(function() { return counter.cancelled == 2; }, "second", 100);
        
        runs(function() {
            var expectedName = names.shift();
            expect(counter.lastName).toEqual(expectedName);
            setTimeout(function() { cv.cancel(tickets.shift()); }, DELAY);
        });
        waitsFor(function() { return counter.cancelled == 3; }, "third", 100);
        
        runs(function() {
            var expectedName = names.shift();
            expect(counter.lastName).toEqual(expectedName);
        });
    });
    
    it("timeout", function() {
        var timedout = false;
        runs(function() {
            cv.wait(TIMEOUT, {
                result: function() {},
                timeout: function() { timedout = true; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return timedout; }, "timedout", 200);
    });
    
    it("stress", function() {
        var tickets = [];
        var numWaiters = 0;
        var expectedSignaled = 0;
        var expectedCancelled = 0;
        var MAX_WAITERS = 100;
        
        function addOperation() {
            if (numWaiters == MAX_WAITERS) {
                expectedCancelled += tickets.length;
                tickets = [];
                cv.cancelAll();
                return;
            }
            
            var r = random.nextInt(10);
            switch (r) {
                case 0:
                {
                    setTimeout(function() { addOperation(); }, 10 * DELAY);
                    return;
                }
                case 1:
                {
                    var ticket = tickets.shift();
                    if (ticket)
                        ++expectedSignaled;
                    cv.signal();
                    break;
                }
                case 2:
                {
                    expectedSignaled += tickets.length;
                    tickets = [];
                    cv.signalAll();
                    break;
                }
                case 3:
                {
                    var ticket = tickets.shift();
                    if (ticket) {
                        ++expectedCancelled;
                        cv.cancel(ticket);
                    }
                    break;
                }
                case 4:
                {
                    expectedCancelled += tickets.length;
                    tickets = [];
                    cv.cancelAll();
                    break;
                }
                default:
                {
                    var name = nextName();
                    var ticket = cv.wait(TIMEOUT, counter.getCallback(name));
                    tickets.push(ticket);
                    ++numWaiters;
                    break;
                }
            }
            addOperation();
        }
        
        runs(function() {
            addOperation();
        });
        waitsFor(function() { return (counter.signaled + counter.cancelled) == MAX_WAITERS; }, "complete", 1000);
        
        runs(function() {
            expect(numWaiters).toEqual(MAX_WAITERS);
            expect(counter.signaled).toEqual(expectedSignaled);
            expect(counter.cancelled).toEqual(expectedCancelled);
            expect(counter.signaled + counter.cancelled).toEqual(numWaiters);
        });
    });
});
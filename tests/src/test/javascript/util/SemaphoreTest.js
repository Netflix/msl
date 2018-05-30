/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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

describe("Semaphore", function() {
    var Semaphore = require('msl-core/util/Semaphore.js');
    var Random = require('msl-core/util/Random.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    
    var RESOURCE_COUNT = 3;
    var TIMEOUT = 150;
    var WAIT = 200;
    var DELAY = 1;
    var NAME = "name";
    
    /**
     * Create a new acquisition counter.
     * 
     * The number of acquisitions will be counted in the acquired property. The
     * number of cancellations will be counted in the cancelled property.
     * 
     * The lastName property will be set when a specific resource is acquired
     * or cancelled.
     * 
     * A new Semaphore.wait() callback with the specified name can be created
     * by calling the getCallback() function.
     */
    function SemaphoreCounter() {
        var self = this;
        this.acquired = 0;
        this.cancelled = 0;
        this.lastName = undefined;
        this.getCallback = function getCallback(name) {
            return {
                result: function(acquired) {
                    self.lastName = name;
                    if (acquired) ++self.acquired;
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
    var sem, counter;
    
    /** Return the next signal name. */
    function nextName() {
        return NAME + nameCount++;
    }
    
    beforeEach(function() {
        sem = new Semaphore(RESOURCE_COUNT);
        counter = new SemaphoreCounter();
        nameCount = 0;
    });
    
    it("acquire immediately", function() {
        runs(function() {
            var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
            expect(t).toEqual(0);
            expect(counter.acquired).toEqual(0);
        });
        waitsFor(function() { return counter.acquired == 1; }, "acquired", WAIT);
    });
    
    it("acquire maximum", function() {
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT; ++i) {
                var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
                expect(t).toEqual(0);
                expect(counter.acquired).toEqual(0);
            }
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
    });
    
    it("wait one and signal", function() {
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT; ++i) {
                var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
                expect(t).toEqual(0);
                expect(counter.acquired).toEqual(0);
            }
            var tw = sem.wait(TIMEOUT, counter.getCallback(NAME));
            expect(tw).toBeTruthy();
            expect(counter.acquired).toEqual(0);
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
        
        runs(function() {
            setTimeout(function() { sem.signal(); }, DELAY);
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT + 1; }, "signaled", WAIT);
    });
    
    it("wait one and signal all", function() {
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT; ++i) {
                var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
                expect(t).toEqual(0);
                expect(counter.acquired).toEqual(0);
            }
            var tw = sem.wait(TIMEOUT, counter.getCallback(NAME));
            expect(tw).toBeTruthy();
            expect(counter.acquired).toEqual(0);
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
        
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT; ++i)
                setTimeout(function() { sem.signal(); }, DELAY);
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT + 1; }, "signaled", WAIT);
    });
    
    it("signal prematurely", function() {
        expect(function() {
            sem.signal();
        }).toThrow(new MslInternalException());
    });
    
    it("signal excessively", function() {
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT + 1; ++i)
                sem.wait(TIMEOUT, counter.getCallback(NAME));
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
        
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT + 1; ++i)
                setTimeout(function() { sem.signal(); }, DELAY);
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT + 1; }, "signaled", WAIT);
        
        runs(function() {
            expect(function() {
                sem.signal();
            }).toThrow(new MslInternalException());
        });
    });
    
    it("multiple wait and signal", function() {
        var names = [];
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT; ++i) {
                var name = nextName();
                names.push(name);
                var t = sem.wait(TIMEOUT, counter.getCallback(name));
                expect(t).toEqual(0);
            }
            expect(counter.acquired).toEqual(0);
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
    
        runs(function() {
            var expectedName = names.pop();
            expect(counter.lastName).toEqual(expectedName);
            names = [];
            
            for (var i = 0; i < RESOURCE_COUNT; ++i) {
                var name = nextName();
                names.push(name);
                var t = sem.wait(TIMEOUT, counter.getCallback(name));
                expect(t).toBeTruthy();
            }
            expect(counter.acquired).toEqual(RESOURCE_COUNT);
        });
        waitsFor(function() { return names.length == RESOURCE_COUNT; }, "waiting", WAIT);
        
        runs(function() {
            var expectedAcquisitions = RESOURCE_COUNT;
            function next() {
                if (names.length == 0)
                    return;
                
                var expectedName = names.shift();
                expect(counter.lastName).toEqual(expectedName);
                expect(counter.acquired).toEqual(expectedAcquisitions);
                sem.signal();
                ++expectedAcquisitions;
                setTimeout(next, 0);
            }
            sem.signal();
            ++expectedAcquisitions;
            setTimeout(next, 0);
        });
        waitsFor(function() { return names.length == 0; }, "signaling", WAIT);
        
        runs(function() {
            expect(counter.acquired).toEqual(2 * RESOURCE_COUNT);
        });
    });
    
    it("wait forever", function() {
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT; ++i) {
                var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
                expect(t).toEqual(0);
                expect(counter.acquired).toEqual(0);
            }
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
        
        var passed = false;
        runs(function() {
            var signaled = false;
            sem.wait(-1, {
                result: function(x) { signaled = x; },
                timeout: function() { expect(function() { throw Error("timedout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            setTimeout(function() {
                expect(signaled).toBeFalsy();
                passed = true;
            }, DELAY);
        });
        waitsFor(function() { return passed; }, "passed", WAIT);
    });
    
    it("cancel zero", function() {
        sem.cancel(0);

        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT + 1; ++i)
                var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
        
        runs(function() {
            sem.cancel(0);
            expect(counter.acquired).toEqual(RESOURCE_COUNT);
            sem.signal();
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT + 1; }, "acquired", WAIT);
    });
    
    it("cancel", function() {
        var ticket;
        runs(function() {
            for (var i = 0; i < RESOURCE_COUNT; ++i)
                var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
            ticket = sem.wait(TIMEOUT, counter.getCallback(NAME));
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT && ticket !== undefined; }, "acquired", WAIT);
        
        runs(function() {
            sem.cancel(ticket);
            expect(counter.acquired).toEqual(RESOURCE_COUNT);
            for (var i = 0; i < RESOURCE_COUNT; ++i)
                sem.signal();
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT && counter.cancelled == 1; }, "cancelled", WAIT);
    });
    
    it("cancel all", function() {
        runs(function() {
            for (var i = 0; i < 2 * RESOURCE_COUNT; ++i)
                var t = sem.wait(TIMEOUT, counter.getCallback(NAME));
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT; }, "acquired", WAIT);
        
        runs(function() {
            sem.cancelAll();
        });
        waitsFor(function() { return counter.acquired == RESOURCE_COUNT && counter.cancelled == RESOURCE_COUNT; }, "cancelled", WAIT);
    });
    
    it("stress", function() {
        var tickets = [];
        var numWaiters = 0;
        var expectedAcquired = 0;
        var expectedCancelled = 0;
        var MAX_WAITERS = 100;
        
        function addOperation() {
            if (numWaiters == MAX_WAITERS) {
                expectedCancelled += tickets.length;
                tickets = [];
                sem.cancelAll();
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
                    var ticket1 = tickets.shift();
                    if (ticket1) {
                        ++expectedAcquired;
                        sem.signal();
                    }
                    break;
                }
                case 2:
                {
                    var ticket2 = tickets.shift();
                    if (ticket2) {
                        ++expectedCancelled;
                        sem.cancel(ticket2);
                    }
                    break;
                }
                case 3:
                {
                    expectedCancelled += tickets.length;
                    tickets = [];
                    sem.cancelAll();
                    break;
                }
                default:
                {
                    var name = nextName();
                    var ticketDefault = sem.wait(TIMEOUT, counter.getCallback(name));
                    if (ticketDefault != 0) {
                        tickets.push(ticketDefault);
                        ++numWaiters;
                    } else {
                        ++expectedAcquired;
                    }
                    break;
                }
            }
            addOperation();
        }
        
        runs(function() {
            addOperation();
        });
        waitsFor(function() { return numWaiters == MAX_WAITERS; }, "complete", 5 * WAIT);
        
        runs(function() {
            expect(counter.acquired).toEqual(expectedAcquired);
            expect(counter.cancelled).toEqual(expectedCancelled);
        });
    });
});
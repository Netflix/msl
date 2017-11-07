/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
describe("ReadWriteLock", function() {
    var Random = require('msl-core/util/Random.js');
    var ReadWriteLock = require('msl-core/util/ReadWriteLock.js');
    
    var TIMEOUT = 75;
    var WAIT = 100;
    var DELAY = 1;
    var NAME = "name";
    
    /**
     * Create a new locker.
     * 
     * The readAcquired and writeAcquired properties will be incremented when
     * the read or write lock is acquired, respectively. The lock ticket will
     * be appended to the lockTickets property.
     * 
     * The readCancelled and writeCancelled properties will be incremented when
     * the read or write lock is cancelled, respectively.
     * 
     * The lastName property will be set when a specific callback acquires the
     * lock or is cancelled.
     * 
     * A new ReadWriteLock.readLock() or .writeLock() callback can be created
     * by calling the getReadCallback() or getWriteCallback() functions
     * respectively. The callback can be reused for multiple calls to
     * ReadWriteLock.
     */
    function Locker() {
        var self = this;
        this.readAcquired = 0;
        this.writeAcquired = 0;
        this.lockTickets = [];
        this.readCancelled = 0;
        this.writeCancelled = 0;
        this.lastName = undefined;
        this.getReadCallback = function getReadCallback(name) {
            return {
                result: function(lockTicket) {
                    self.lastName = name;
                    if (lockTicket === undefined) {
                        ++self.readCancelled;
                        return;
                    }
                    self.lockTickets.push(lockTicket);
                    ++self.readAcquired;
                },
                timeout: function() {
                    expect(function() { throw new Error(name + " timedout"); }).not.toThrow();
                },
                error: function(e) {
                    expect(function() { throw e; }).not.toThrow();
                }
            };
        };
        this.getWriteCallback = function getWriteCallback(name) {
            return {
                result: function(lockTicket) {
                    self.lastName = name;
                    if (lockTicket === undefined) {
                        ++self.writeCancelled;
                        return;
                    }
                    self.lockTickets.push(lockTicket);
                    ++self.writeAcquired;
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
    var rwlock, locker;
    
    /** Return the next signal name. */
    function nextName() {
        return NAME + nameCount++;
    }
    
    beforeEach(function() {
        rwlock = new ReadWriteLock();
        locker = new Locker();
        nameCount = 0;
    });
    
    it("read lock", function() {
        runs(function() {
            rwlock.readLock(TIMEOUT, locker.getReadCallback(NAME));
        });
        waitsFor(function() { return locker.readAcquired == 1; }, "read lock", WAIT);

        runs(function() {
            expect(locker.lastName).toEqual(NAME);
        });
    });
    
    it("write lock", function() {
        runs(function() {
            rwlock.readLock(TIMEOUT, locker.getWriteCallback(NAME));
        });
        waitsFor(function() { return locker.writeAcquired == 1; }, "write lock", WAIT);

        runs(function() {
            expect(locker.lastName).toEqual(NAME);
        });
    });
    
    it("multiple read locks", function() {
        var expectedName;
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                expectedName = nextName();
                rwlock.readLock(TIMEOUT, locker.getReadCallback(expectedName));
            }
        });
        waitsFor(function() { return locker.readAcquired == 3; }, "read locks", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(expectedName);
        });
    });
    
    it("multiple write locks", function() {
        var names = [];
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                names.push(name);
                rwlock.writeLock(TIMEOUT, locker.getWriteCallback(name));
            }
        });
        waitsFor(function() { return locker.writeAcquired == 1; }, "first lock", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(names.shift());
            rwlock.unlock(locker.lockTickets.shift());
        });
        waitsFor(function() { return locker.writeAcquired == 2; }, "second lock", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(names.shift());
            rwlock.unlock(locker.lockTickets.shift());
        });
        waitsFor(function() { return locker.writeAcquired == 3; }, "third lock", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(names.shift());
        });
    });
    
    it("write lock waiting on readers", function() {
        var writeName;
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                rwlock.readLock(TIMEOUT, locker.getReadCallback(name));
            }
            writeName = nextName();
            rwlock.writeLock(TIMEOUT, locker.getWriteCallback(writeName));
        });
        waitsFor(function() { return locker.readAcquired == 3; }, "read locks", WAIT);
        
        runs(function() {
            expect(locker.lastName).not.toEqual(writeName);
            expect(locker.lockTickets.length).toEqual(locker.readAcquired);
            setTimeout(function() {
                while (locker.lockTickets.length > 0)
                    rwlock.unlock(locker.lockTickets.shift());
            }, DELAY);
        });
        waitsFor(function() { return locker.writeAcquired == 1; }, "write lock", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(writeName);
        });
    });
    
    it("read locks waiting on writer", function() {
        var writeName, names = [];
        runs(function() {
            writeName = nextName();
            rwlock.writeLock(TIMEOUT, locker.getWriteCallback(writeName));
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                names.push(name);
                rwlock.readLock(TIMEOUT, locker.getReadCallback(name));
            }
        });
        waitsFor(function() { return locker.writeAcquired == 1 && names.length == 3; }, "write lock", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(writeName);
            expect(locker.readAcquired).toEqual(0);
            expect(locker.lockTickets.length).toEqual(1);
            rwlock.unlock(locker.lockTickets.shift());
        });
        waitsFor(function() { return locker.readAcquired == names.length; }, "read locks", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(names[names.length - 1]);
            expect(locker.lockTickets.length).toEqual(names.length);
        });
    });
    
    it("cancel read lock blocked on writer", function() {
        var writeName, readName, ticket;
        runs(function() {
            writeName = nextName();
            rwlock.writeLock(TIMEOUT, locker.getWriteCallback(writeName));
            readName = nextName();
            ticket = rwlock.readLock(TIMEOUT, locker.getReadCallback(readName));
            expect(ticket).toBeDefined();
        });
        waitsFor(function() { return locker.writeAcquired == 1; }, "write lock", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(writeName);
            rwlock.cancel(ticket);
        });
        waitsFor(function() { return locker.readCancelled == 1; }, "cancelled", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(readName);
            expect(locker.writeAcquired).toEqual(1);
            expect(locker.readAcquired).toEqual(0);
        });
    });
    
    it("cancel write lock blocked on reader", function() {
        var readName, writeName, ticket;
        runs(function() {
            readName = nextName();
            rwlock.readLock(TIMEOUT, locker.getReadCallback(readName));
            writeName = nextName();
            ticket = rwlock.writeLock(TIMEOUT, locker.getWriteCallback(writeName));
            expect(ticket).toBeDefined();
        });
        waitsFor(function() { return locker.readAcquired == 1; }, "read lock", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(readName);
            rwlock.cancel(ticket);
        });
        waitsFor(function() { return locker.writeCancelled == 1; }, "cancelled", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(writeName);
            expect(locker.readAcquired).toEqual(1);
            expect(locker.writeAcquired).toEqual(0);
        });
    });
    
    it("cancel all readers and writers blocked on writer", function() {
        var writeName;
        var names = [], tickets = [];
        var expectedCancelledWriters = 0, expectedCancelledReaders = 0;
        var MAX_WAITERS = 10;
        runs(function() {
            writeName = nextName();
            rwlock.writeLock(TIMEOUT, locker.getWriteCallback(writeName));
            for (var i = 0; i < MAX_WAITERS; ++i) {
                var r = random.nextInt(2);
                var name = nextName();
                names.push(name);
                var ticket;
                if (r == 1) {
                    ticket = rwlock.writeLock(2 * TIMEOUT, locker.getWriteCallback(name));
                    ++expectedCancelledWriters;
                } else {
                    ticket = rwlock.readLock(2 * TIMEOUT, locker.getReadCallback(name));
                    ++expectedCancelledReaders;
                }
                tickets.push(ticket);
            }
        });
        waitsFor(function() { return locker.writeAcquired == 1; }, "write lock and all waiters", WAIT);
        
        var expectedName, numCancelling;
        runs(function() {
            expect(names.length).toEqual(MAX_WAITERS);
            expect(tickets.length).toEqual(names.length);
            expect(expectedCancelledWriters).toBeGreaterThan(0);
            expect(expectedCancelledReaders).toBeGreaterThan(0);
            expect(expectedCancelledWriters + expectedCancelledReaders).toEqual(names.length);
            numCancelling = Math.floor(tickets.length / 2);
            setTimeout(function() {
                for (var i = 0; i < numCancelling; ++i) {
                    expectedName = names.shift();
                    var ticket = tickets.shift();
                    rwlock.cancel(ticket);
                }
            }, DELAY);
        });
        waitsFor(function() { return locker.readCancelled + locker.writeCancelled == numCancelling; }, "individual cancellations", WAIT);
        
        runs(function() {
            expect(locker.lastName).toEqual(expectedName);
            expect(locker.readAcquired).toEqual(0);
            expect(locker.readCancelled).toBeGreaterThan(0);
            expect(locker.writeAcquired).toEqual(1);
            expect(locker.writeCancelled).toBeGreaterThan(0);
            setTimeout(function() {
                rwlock.cancelAll();
            }, DELAY);
        });
        waitsFor(function() { return locker.readCancelled + locker.writeCancelled == MAX_WAITERS; }, "remaining cancellations", WAIT);
        
        runs(function() {
            // Cancelling all is not done in order of acquisition attempt so we
            // cannot compare the last name.
            expect(locker.readAcquired).toEqual(0);
            expect(locker.writeAcquired).toEqual(1);
        });
    });
    
    it("write lock timed out waiting on readers", function() {
        var timedout = false;
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                rwlock.readLock(TIMEOUT, locker.getReadCallback(name));
            }
            rwlock.writeLock(TIMEOUT, {
                result: function() {},
                timeout: function() { timedout = true; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return timedout; }, "timedout", WAIT);
        
        runs(function() {
            expect(locker.readAcquired).toEqual(3);
            expect(locker.writeAcquired).toEqual(0);
        });
    });
    
    it("read and write locks timed out waiting on writer", function() {
        var numTimedout = 0;
        var callback = {
            result: function() { expect(function() { throw "lock acquired"; }).not.toThrow(); },
            timeout: function() { ++numTimedout; },
            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        };
        
        var MAX_WAITERS = 10;
        runs(function() {
            rwlock.writeLock(TIMEOUT, locker.getWriteCallback(nextName()));
            for (var i = 0; i < MAX_WAITERS; ++i) {
                var r = random.nextInt(2);
                if (r == 1) {
                    rwlock.writeLock(TIMEOUT, callback);
                } else {
                    rwlock.readLock(TIMEOUT, callback);
                }
            }
        });
        waitsFor(function() { return locker.writeAcquired == 1 && numTimedout == MAX_WAITERS; }, "timeouts", WAIT);
        
        runs(function() {
            expect(locker.readAcquired).toEqual(0);
            expect(locker.writeAcquired).toEqual(1);
        });
    });
    
    it("stress", function() {
        var tickets = [];
        var expectedReaders = 0;
        var expectedWriters = 0;
        var MAX_LOCKERS = 100;
        
        function addOperation() {
            if (expectedReaders + expectedWriters == MAX_LOCKERS) {
                setTimeout(function() {
                    tickets = [];
                    rwlock.cancelAll();
                    while (locker.lockTickets.length > 0) {
                        var lockTicket = locker.lockTickets.shift();
                        rwlock.unlock(lockTicket);
                    }
                }, DELAY);
                return;
            }
            
            var r = random.nextInt(7);
            switch (r) {
                case 0:
                {
                    setTimeout(function() { addOperation(); }, 10 * DELAY);
                    return;
                }
                case 1:
                {
                    setTimeout(function() {
                        var ticket = tickets.pop();
                        rwlock.cancel(ticket);
                    }, DELAY);
                    break;
                }
                case 2:
                {
                    setTimeout(function() {
                        tickets = [];
                        rwlock.cancelAll();
                    }, DELAY);
                    break;
                }
                case 3:
                {
                    setTimeout(function() {
                        if (locker.lockTickets.length == 0)
                            return;
                        var lockTicket = locker.lockTickets.shift();
                        rwlock.unlock(lockTicket);
                    }, DELAY);
                    break;
                }
                case 4:
                {
                    setTimeout(function() {
                        var name = nextName();
                        var ticket = rwlock.readLock(2 * TIMEOUT, locker.getReadCallback(name));
                        tickets.push(ticket);
                    }, DELAY);
                    ++expectedReaders;
                    break;
                }
                case 5:
                {
                    setTimeout(function() {
                        var name = nextName();
                        var ticket = rwlock.writeLock(2 * TIMEOUT, locker.getWriteCallback(name));
                        tickets.push(ticket);
                    }, DELAY);
                    ++expectedWriters;
                    break;
                }
            }
            addOperation();
        }
    
        runs(function() {
            addOperation();
        });
        waitsFor(function() { return (locker.readAcquired + locker.writeAcquired + locker.readCancelled + locker.writeCancelled) == MAX_LOCKERS; }, "complete", 30 * WAIT);
        
        runs(function() {
            expect(locker.readAcquired).toBeGreaterThan(0);
            expect(locker.readCancelled).toBeGreaterThan(0);
            expect(locker.writeAcquired).toBeGreaterThan(0);
            expect(locker.writeCancelled).toBeGreaterThan(0);
            expect(locker.readAcquired + locker.readCancelled).toEqual(expectedReaders);
            expect(locker.writeAcquired + locker.writeCancelled).toEqual(expectedWriters);
        });
    });
});
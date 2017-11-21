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
describe("BlockingQueue", function() {
    var BlockingQueue = require('msl-core/util/BlockingQueue.js');
    var Random = require('msl-core/util/Random.js');
    var Arrays = require('msl-core/util/Arrays.js');
    
    var TIMEOUT = 150;
    var WAIT = 200;
    var DELAY = 1;
    var NAME = "name";
    
    /**
     * Create a new consumer.
     * 
     * The received items will be pushed onto the items property. If cancelled
     * the cancelled property will be incremented instead.
     * 
     * The lastName property will be set when a specific callback receives an
     * item or is cancelled.
     * 
     * A new BlockingQueue.poll() callback can be created by calling the
     * getCallback() function. The callback can be reused for multiple calls to
     * BlockingQueue.poll().
     */
    function Consumer() {
        var self = this;
        this.items = [];
        this.lastName = undefined;
        this.cancelled = 0;
        this.getCallback = function getCallback(name) {
            return {
                result: function(x) {
                    self.lastName = name;
                    if (x !== undefined)
                        self.items.push(x);
                    else
                        ++self.cancelled;
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
    
    /**
     * Asynchronously adds the provided items to the provided BlockingQueue, in
     * order.
     * 
     * @param {BlockingQueue} queue the blocking queue.
     * @param {Array.<?>} items the items.
     */
    function deliver(queue, items) {
        function add(index) {
            if (index == items.length)
                return;
            queue.add(items[index]);
            setTimeout(function() { add(index + 1); }, DELAY);
        }
        setTimeout(function() { add(0); }, DELAY);
    }
    
    /**
     * Synchronously adds the provided items to the provided BlockingQueue, in
     * order.
     * 
     * @param {BlockingQueue} queue the blocking queue.
     * @param {Array.<?>} items the items.
     */
    function produce(queue, items) {
        for (var i = 0; i < items.length; ++i)
            queue.add(items[i]);
    }
    
    /**
     * Returns a new array of the requested length containing a sequential
     * ordering of numbers 0...length-1.
     * 
     * @param {number} length the number of items to create.
     * @return {Array.<number>} the array of items.
     */
    function getItems(length) {
        var items = [];
        for (var i = 0; i < length; ++i)
            items.push(i);
        return items;
    }
    
    var random = new Random();
    var nameCount = 0;
    var queue, consumer;
    
    /** Return the next signal name. */
    function nextName() {
        return NAME + nameCount++;
    }
    
    beforeEach(function() {
        queue = new BlockingQueue();
        consumer = new Consumer();
        nameCount = 0;
    });
    
    it("poll and add", function() {
        var items = getItems(1);
        runs(function() {
            var t = queue.poll(TIMEOUT, consumer.getCallback(NAME));
            expect(t).toBeDefined();
            deliver(queue, items);
        });
        waitsFor(function() { return Arrays.equal(consumer.items, items); }, "items", WAIT);
    });
    
    it("add and poll", function() {
        var items = getItems(1);
        runs(function() {
            produce(queue, items);
            var t = queue.poll(TIMEOUT, consumer.getCallback(NAME));
            expect(t).toBeDefined();
        });
        waitsFor(function() { return Arrays.equal(consumer.items, items); }, "items", WAIT);
    });
    
    it("multiple poll and add", function() {
        var items = getItems(3);
        var names = [];
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                names.push(name);
                var t = queue.poll(TIMEOUT, consumer.getCallback(name));
                expect(t).toBeDefined();
            }
            expect(consumer.items.length).toEqual(0);
        });
        waitsFor(function() { return names.length == 3; }, "names", WAIT);
        
        runs(function() {
            setTimeout(function() { queue.add(items[0]); }, DELAY);
        });
        waitsFor(function() { return consumer.items.length == 1; }, "first", WAIT);
        
        runs(function() {
            var expectedName = names.shift();
            expect(consumer.lastName).toEqual(expectedName);
            expect(consumer.items[0]).toEqual(items[0]);
            setTimeout(function() { queue.add(items[1]); }, DELAY);
        });
        waitsFor(function() { return consumer.items.length == 2; }, "second", WAIT);
        
        runs(function() {
            var expectedName = names.shift();
            expect(consumer.lastName).toEqual(expectedName);
            expect(consumer.items[1]).toEqual(items[1]);
            setTimeout(function() { queue.add(items[2]); }, DELAY);
        });
        waitsFor(function() { return consumer.items.length == 3; }, "third", WAIT);
        
        runs(function() {
            var expectedName = names.shift();
            expect(consumer.lastName).toEqual(expectedName);
            expect(consumer.items).toEqual(items);
        });
    });
    
    it("multiple add and poll", function() {
        var items = getItems(3);
        runs(function() {
            produce(queue, items);
            expect(consumer.items.length).toEqual(0);
        });
        
        runs(function() {
            setTimeout(function() { queue.poll(TIMEOUT, consumer.getCallback(NAME)); }, DELAY);
        });
        waitsFor(function() { return consumer.items.length == 1; }, "first", WAIT);
        
        runs(function() {
            expect(consumer.items[0]).toEqual(items[0]);
            setTimeout(function() { queue.poll(TIMEOUT, consumer.getCallback(NAME)); }, DELAY);
        });
        waitsFor(function() { return consumer.items.length == 2; }, "second", WAIT);
        
        runs(function() {
            expect(consumer.items[1]).toEqual(items[1]);
            setTimeout(function() { queue.poll(TIMEOUT, consumer.getCallback(NAME)); }, DELAY);
        });
        waitsFor(function() { return consumer.items.length == 3; }, "third", WAIT);
        
        runs(function() {
            expect(consumer.items).toEqual(items);
        });
    });
    
    it("poll forever", function() {
        var passed = false;
        runs(function() {
            queue.poll(-1, consumer.getCallback(NAME));
            setTimeout(function() {
                expect(consumer.items.length).toEqual(0);
                passed = true;
            }, DELAY);
        });
        waitsFor(function() { return passed; }, "passed", 100);
    });
    
    it("cancel", function() {
        runs(function() {
            var ticket = queue.poll(TIMEOUT, consumer.getCallback(NAME));
            setTimeout(function() { queue.cancel(ticket); }, DELAY);
        });
        waitsFor(function() { return consumer.cancelled == 1; }, "cancelled", WAIT);
    });
    
    it("cancel multiple", function() {
        var names = [];
        var tickets = [];
        runs(function() {
            for (var i = 0; i < 3; ++i) {
                var name = nextName();
                names.push(name);
                var t = queue.poll(TIMEOUT, consumer.getCallback(name));
                expect(t).toBeDefined();
                tickets.push(t);
            }
            expect(consumer.items.length).toEqual(0);
        });
        waitsFor(function() { return names.length == 3 && tickets.length == 3; }, "names & tickets", WAIT);
        
        runs(function() {
            setTimeout(function() { queue.cancel(tickets.shift()); }, DELAY);
        });
        waitsFor(function() { return consumer.cancelled == 1; }, "first", WAIT);
        
        runs(function() {
            var expectedName = names.shift();
            expect(consumer.lastName).toEqual(expectedName);
            setTimeout(function() { queue.cancel(tickets.shift()); }, DELAY);
        });
        waitsFor(function() { return consumer.cancelled == 2; }, "second", WAIT);
        
        runs(function() {
            var expectedName = names.shift();
            expect(consumer.lastName).toEqual(expectedName);
            setTimeout(function() { queue.cancel(tickets.shift()); }, DELAY);
        });
        waitsFor(function() { return consumer.cancelled == 3; }, "third", WAIT);
        
        runs(function() {
            var expectedName = names.shift();
            expect(consumer.lastName).toEqual(expectedName);
        });
    });
    
    it("timeout", function() {
        var timedout = false;
        runs(function() {
            queue.poll(TIMEOUT, {
                result: function() {},
                timeout: function() { timedout = true; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return timedout; }, "timedout", WAIT);
    });
    
    it("stress", function() {
        var tickets = [];
        var numConsumers = 0;
        var expectedItems = [];
        var MAX_CONSUMERS = 100;
        var items = getItems(100);
        
        function addOperation() {
            if (numConsumers == MAX_CONSUMERS) {
                tickets = [];
                queue.cancelAll();
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
                    var ticket1 = tickets.pop();
                    if (ticket1)
                        queue.cancel(ticket1);
                    break;
                }
                case 2:
                {
                    tickets = [];
                    queue.cancelAll();
                    break;
                }
                case 3:
                case 4:
                {
                    var item = items.shift();
                    expectedItems.push(item);
                    queue.add(item);
                    break;
                }
                default:
                {
                    var name = nextName();
                    var ticketDefault = queue.poll(TIMEOUT, consumer.getCallback(name));
                    tickets.push(ticketDefault);
                    ++numConsumers;
                    break;
                }
            }
            addOperation();
        }
        
        runs(function() {
            addOperation();
        });
        waitsFor(function() { return (consumer.items.length + consumer.cancelled) == MAX_CONSUMERS; }, "complete", 15 * WAIT);
        
        runs(function() {
            expect(numConsumers).toEqual(MAX_CONSUMERS);
            expect(consumer.cancelled).toBeGreaterThan(0);
            expectedItems.length = consumer.items.length;
            expect(consumer.items).toEqual(expectedItems);
            expect(consumer.items.length + consumer.cancelled).toEqual(numConsumers);
        });
    });
});
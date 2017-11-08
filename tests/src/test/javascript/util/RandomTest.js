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

/**
 * Random unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("Random", function() {
    var Random = require('msl-core/util/Random.js');
    
    var ITERATIONS = 100000;
    var random = new Random();
    
    it("boolean", function() {
        var diff = 0;
        for (var i = 0; i < ITERATIONS; ++i)
            diff += (random.nextBoolean()) ? 1 : -1;
        expect(Math.abs(diff)).toBeLessThan(ITERATIONS * 0.01);
    });
    
    it("int" , function() {
        var positive = 0,
            negative = 0,
            xor = 0;
        for (var i = 0; i < ITERATIONS; ++i) {
            var val = random.nextInt();
            xor ^= val;
            (val > 0) ? ++positive : ++negative;
        }
        expect(positive).toBeGreaterThan(ITERATIONS * 0.49);
        expect(negative).toBeGreaterThan(ITERATIONS * 0.49);
        expect(positive - negative).toBeLessThan(ITERATIONS * 0.01);
        var diff = 0;
        for (var j = 0; j < 32; ++j)
            diff += (xor & (1 << j)) ? 1 : -1;
        expect(Math.abs(diff)).toBeLessThan(8);
    });
    
    it("int(n)", function() {
        var buckets = 10;
        var distribution = [];
        for (var b = 0; b < buckets; ++b)
            distribution[b] = 0;
        for (var i = 0; i < ITERATIONS; ++i) {
            var val = random.nextInt(buckets);
            ++distribution[val];
        }
        var average = ITERATIONS / buckets;
        for (var j = 0; j < buckets; ++j) {
            expect(distribution[j]).toBeGreaterThan(average * 0.9);
            expect(distribution[j]).toBeLessThan(average * 1.1);
        }
    });
    
    it("long", function() {
        var positive = 0,
        negative = 0,
        xor = 0;
        for (var i = 0; i < ITERATIONS; ++i) {
            var val = random.nextLong();
            xor ^= val;
            (val > 0) ? ++positive : ++negative;
        }
        expect(positive).toBeGreaterThan(ITERATIONS * 0.49);
        expect(negative).toBeGreaterThan(ITERATIONS * 0.49);
        expect(positive - negative).toBeLessThan(ITERATIONS * 0.01);
        var diff = 0;
        for (var j = 0; j < 32; ++j)
            diff += (xor & (1 << j)) ? 1 : -1;
        expect(Math.abs(diff)).toBeLessThan(8);
    });
    
    it("bytes", function() {
        var b = new Uint8Array(65536);
        random.nextBytes(b);
        
        var xor = 0;
        for (var i = 0; i < b.length; ++i) {
            xor ^= b[i];
        }
        var diff = 0;
        for (var j = 0; j < 8; ++j)
            diff += (xor & (1 << j)) ? 1 : -1;
        expect(Math.abs(diff)).toBeLessThan(3);
    });
    
    it("large bytes", function() {
        var b = new Uint8Array(2.5 * 65536);
        random.nextBytes(b);
        
        var xor = 0;
        for (var i = 0; i < b.length; ++i) {
            xor ^= b[i];
        }
        var diff = 0;
        for (var j = 0; j < 8; ++j)
            diff += (xor & (1 << j)) ? 1 : -1;
        expect(Math.abs(diff)).toBeLessThan(3);
    });
});
/**
 * Copyright (c) 2016-2019 Netflix, Inc.  All rights reserved.
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
describe("MslEncoderUtils", function() {
    var Base64 = require('msl-core/util/Base64.js');
    var MslObject = require('msl-core/io/MslObject.js');
    var MslArray = require('msl-core/io/MslArray.js');
    var Random = require('msl-core/util/Random.js');
    var MslEncoderUtils = require('msl-core/io/MslEncoderUtils.js');
    
    var KEY_BOOLEAN = "boolean";
    var KEY_NUMBER = "number";
    var KEY_STRING = "string";
    var KEY_OBJECT = "object";
    var KEY_ARRAY = "array";
    
    var MAX_ELEMENTS = 12;
    var MAX_DEPTH = 3;
    var MAX_STRING_CHARS = 25;
    
    /**
     * @param {Random} random random source.
     * @return {string} a random string of random length.
     */
    function randomString(random) {
        var raw = new Uint8Array(1 + random.nextInt(MAX_STRING_CHARS - 1));
        random.nextBytes(raw);
        return Base64.encode(raw);
    }
    
    /**
     * @param {Random} random source.
     * @return {MslObject} a MSL object containing no MSL objects or MSL arrays.
     */
    function createFlatMslObject(random) {
        var mo = new MslObject();
        for (var i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
            switch (random.nextInt(3)) {
                case 0:
                    mo.put(KEY_BOOLEAN + i, random.nextBoolean());
                    break;
                case 1:
                    mo.put(KEY_NUMBER + i, random.nextInt());
                    break;
                case 2:
                    mo.put(KEY_STRING + i, randomString(random));
                    break;
            }
        }
        return mo;
    }

    /**
     * @param {Random} random random source.
     * @param {number} depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return {MslObject} a MSL object that may contain MSL objects or MSL arrays.
     */
    function createDeepMslObject(random, depth) {
        var mo = new MslObject();
        for (var i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
            switch (random.nextInt(5)) {
	            case 0:
	                mo.put(KEY_BOOLEAN + i, random.nextBoolean());
	                break;
	            case 1:
	                mo.put(KEY_NUMBER + i, random.nextInt());
	                break;
	            case 2:
	                mo.put(KEY_STRING + i, randomString(random));
	                break;
	            case 4:
	                mo.put(KEY_OBJECT + i, (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslObject(random));
	                break;
	            case 5:
	                mo.put(KEY_ARRAY + i, (depth > 1) ? createDeepMslArray(random, depth - 1) : createFlatMslArray(random));
	                break;
            }
        }
        return mo;
    }
    
    /**
     * @param {Random} random random source.
     * @return {MslArray} a MSL array containing no MSL objects or MSL arrays.
     */
    function createFlatMslArray(random) {
        var ma = new MslArray();
        for (var i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    ma.put(-1, random.nextBoolean());
                    break;
                case 1:
                    ma.put(-1, random.nextInt());
                    break;
                case 2:
                    ma.put(-1, randomString(random));
                    break;
                case 3:
                    ma.put(-1, null);
                    break;
            }
        }
        return ma;
    }
    
    /**
     * @param {Random} random random source.
     * @param {number} depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return {MslArray} a MSL array that may contain MSL objects or MSL arrays.
     */
    function createDeepMslArray(random, depth) {
        var ma = new MslArray();
        for (var i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
            switch (random.nextInt(6)) {
                case 0:
                    ma.put(-1, random.nextBoolean());
                    break;
                case 1:
                    ma.put(-1, random.nextInt());
                    break;
                case 2:
                    ma.put(-1, randomString(random));
                    break;
                case 3:
                    ma.put(-1, null);
                    break;
                case 4:
                    ma.put(-1, (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslObject(random));
                    break;
                case 5:
                    ma.put(-1, (depth > 1) ? createDeepMslArray(random, depth - 1) : createFlatMslArray(random));
                    break;
            }
        }
        return ma;
    }
    
    var random;
    var flatMo, deepMo;
    
    beforeEach(function() {
        if (!random) {
            random = new Random();
            flatMo = createFlatMslObject(random);
            deepMo = createDeepMslObject(random, MAX_DEPTH);
        }
    });
    
    it("merge nulls", function() {
        var mo1 = null;
        var mo2 = null;
        var merged = MslEncoderUtils.merge(mo1, mo2);
        expect(merged).toBeNull();
    });
    
    it("merge first null", function() {
        var mo1 = null;
        var mo2 = deepMo;
        var merged = MslEncoderUtils.merge(mo1, mo2);
        expect(merged).toEqual(mo2);
    });
    
    it("merge second null", function() {
        var mo1 = deepMo;
        var mo2 = null;
        var merged = MslEncoderUtils.merge(mo1, mo2);
        expect(merged).toEqual(mo1);
    });
    
    it("merge overwriting", function() {
        var mo1 = createFlatMslObject(random);
        var mo2 = createFlatMslObject(random);
        
        // Insert some shared keys.
        mo1.put("key1", true);
        mo2.put("key1", "value1");
        mo1.put("key2", 17);
        mo2.put("key2", 34);
        
        // Ensure second overwites first.
        var merged = MslEncoderUtils.merge(mo1, mo2);
        for (var key in merged) {
            var value = merged[key];
            if (key == "key1" || key == "key2") {
                expect(value).toEqual(mo2[key]);
            } else if (mo2[key] !== undefined) {
                expect(value).toEqual(mo2[key]);
            } else {
                expect(value).toEqual(mo1[key]);
            }
        }
    });
});
/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
    var KEY_BOOLEAN = "boolean";
    var KEY_NUMBER = "number";
    var KEY_STRING = "string";
    var KEY_NULL = "null";
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
        var raw = new Uint8Array(random.nextInt(MAX_STRING_CHARS) + 1);
        random.nextBytes(raw);
        return base64$encode(raw);
    }
    
    /**
     * @param {Random} random source.
     * @return {MslObject} a MSL object containing no MSL objects or MSL arrays.
     */
    function createFlatMslObject(random) {
        var jo = {};
        for (var i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    jo[KEY_BOOLEAN + i] = random.nextBoolean();
                    break;
                case 1:
                    jo[KEY_NUMBER + i] = random.nextInt();
                    break;
                case 2:
                    jo[KEY_STRING + i] = randomString(random);
                    break;
                case 3:
                    jo[KEY_NULL + i] = null;
                    break;
            }
        }
        return jo;
    }

    /**
     * @param {Random} random random source.
     * @param {number} depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return {Object} a MSL object that may contain MSL objects or MSL arrays.
     */
    function createDeepMslObject(random, depth) {
        var jo = {};
        for (var i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(6)) {
                case 0:
                    jo[KEY_BOOLEAN + i] = random.nextBoolean();
                    break;
                case 1:
                    jo[KEY_NUMBER + i] = random.nextInt();
                    break;
                case 2:
                    jo[KEY_STRING + i] = randomString(random);
                    break;
                case 3:
                    jo[KEY_NULL + i] = null;
                    break;
                case 4:
                    jo[KEY_OBJECT + i] = (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslObject(random);
                    break;
                case 5:
                    jo[KEY_ARRAY + i] = (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslArray(random);
            }
        }
    }
    
    /**
     * @param {Random} random random source.
     * @return {Array} a MSL array containing no MSL objects or MSL arrays.
     */
    function createFlatMSLArray(random) {
        var ja = [];
        for (var i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    ja.push(random.nextBoolean());
                    break;
                case 1:
                    ja.push(random.nextInt());
                    break;
                case 2:
                    ja.push(randomString(random));
                    break;
                case 3:
                    ja.push(null);
                    break;
            }
        }
        return ja;
    }
    
    /**
     * @param {Random} random random source.
     * @param {number} depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return {Object} a MSL array that may contain MSL objects or MSL arrays.
     */
    function createDeepMslArray(random, depth) {
        var ja = [];
        for (var i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(6)) {
                case 0:
                    ja.push(random.nextBoolean());
                    break;
                case 1:
                    ja.push(random.nextInt());
                    break;
                case 2:
                    ja.push(randomString(random));
                    break;
                case 3:
                    ja.push(null);
                    break;
                case 4:
                    ja.push((depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslObject(random));
                    break;
                case 5:
                    ja.push((depth > 1) ? createDeepMslArray(random, depth - 1) : createFlatMslArray(random));
                    break;
            }
        }
        return ja;
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
        var merged = MslEncoderUtils$merge(mo1, mo2);
        expect(merged).toBeNull();
    });
    
    it("merge first null", function() {
        var mo1 = null;
        var mo2 = deepMo;
        var merged = MslEncoderUtils$merge(mo1, mo2);
        expect(merged).toEqual(mo2);
    });
    
    it("merge second null", function() {
        var mo1 = deepMo;
        var mo2 = null;
        var merged = MslEncoderUtils$merge(mo1, mo2);
        expect(merged).toEqual(mo1);
    });
    
    it("merge overwriting", function() {
        var mo1 = createFlatMslObject(random);
        var mo2 = createFlatMslObject(random);
        
        // Insert some shared keys.
        mo1["key1"] = true;
        mo2["key1"] = "value1";
        mo1["key2"] = 17;
        mo2["key2"] = 34;
        
        // Ensure second overwites first.
        var merged = MslEncoderUtils$merge(mo1, mo2);
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
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
describe("JsonUtils", function() {
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
     * @return {Object} a JSON object containing no JSON objects or JSON arrays.
     */
    function createFlatJSONObject(random) {
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
     * @return {Object} a JSON object that may contain JSON objects or JSON arrays.
     */
    function createDeepJSONObject(random, depth) {
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
                    jo[KEY_OBJECT + i] = (depth > 1) ? createDeepJSONObject(random, depth - 1) : createFlatJSONObject(random);
                    break;
                case 5:
                    jo[KEY_ARRAY + i] = (depth > 1) ? createDeepJSONObject(random, depth - 1) : createFlatJSONArray(random);
            }
        }
    }
    
    /**
     * @param {Random} random random source.
     * @return {Array} a JSON array containing no JSON objects or JSON arrays.
     */
    function createFlatJSONArray(random) {
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
     * @return {Object} a JSON array that may contain JSON objects or JSON arrays.
     */
    function createDeepJSONArray(random, depth) {
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
                    ja.push((depth > 1) ? createDeepJSONObject(random, depth - 1) : createFlatJSONObject(random));
                    break;
                case 5:
                    ja.push((depth > 1) ? createDeepJSONArray(random, depth - 1) : createFlatJSONArray(random));
                    break;
            }
        }
        return ja;
    }
    
    var random;
    var flatJo, deepJo;
    
    beforeEach(function() {
        if (!random) {
            random = new Random();
            flatJo = createFlatJSONObject(random);
            deepJo = createDeepJSONObject(random, MAX_DEPTH);
        }
    });
    
    it("merge nulls", function() {
        var jo1 = null;
        var jo2 = null;
        var merged = JsonUtils$merge(jo1, jo2);
        expect(merged).toBeNull();
    });
    
    it("merge first null", function() {
        var jo1 = null;
        var jo2 = deepJo;
        var merged = JsonUtils$merge(jo1, jo2);
        expect(merged).toEqual(jo2);
    });
    
    it("merge second null", function() {
        var jo1 = deepJo;
        var jo2 = null;
        var merged = JsonUtils$merge(jo1, jo2);
        expect(merged).toEqual(jo1);
    });
    
    it("merge overwriting", function() {
        var jo1 = createFlatJSONObject(random);
        var jo2 = createFlatJSONObject(random);
        
        // Insert some shared keys.
        jo1["key1"] = true;
        jo2["key1"] = "value1";
        jo1["key2"] = 17;
        jo2["key2"] = 34;
        
        // Ensure second overwites first.
        var merged = JsonUtils$merge(jo1, jo2);
        for (var key in merged) {
            var value = merged[key];
            if (key == "key1" || key == "key2") {
                expect(value).toEqual(jo2[key]);
            } else if (jo2[key] !== undefined) {
                expect(value).toEqual(jo2[key]);
            } else {
                expect(value).toEqual(jo1[key]);
            }
        }
    });
});
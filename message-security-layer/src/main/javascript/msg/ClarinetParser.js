/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
 * A clarinet parser parses the provided sequence of JSON values into
 * JavaScript values using the clarinet library.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var ClarinetParser = util.Class.create({
    /**
     * @param {string} json the sequence of JSON values.
     */
    init: function init(json) {
        var parser = clarinet.parser();
        var values = new Array();
        var stack = new Array();
        var currentObject;
        var currentArray;
        var currentKey;
        var lastIndex = 0;

        // Attach my methods to the parser.

        var error = false;
        /**
         * @param {Error} e the error.
         */
        parser.onerror = function onError(e) {
            // Stop parsing. We must only do this once to prevent a
            // recursive call into ourselves if ending in a bad state.
            if (!error) {
                error = true;
                parser.end();
            }
        };

        /**
         * @param {string} key the first key in the object.
         */
        parser.onopenobject = function onOpenObject(key) {
            if (currentObject) {
                currentObject[currentKey] = {};
                stack.push(currentObject);
                currentObject = currentObject[currentKey];
            } else if (currentArray) {
                var newObj = {};
                stack.push(currentArray);
                currentArray.push(newObj);
                currentObject = newObj;
                currentArray = undefined;
            } else {
                currentObject = {};
            }
            currentKey = key;
        };

        parser.oncloseobject = function onCloseObject() {
            var prev = stack.pop();
            if (!prev) {
                values.push(currentObject);
                lastIndex = parser.index;
                currentObject = undefined;
            } else {
                if (typeof prev === 'object') {
                    currentObject = prev;
                } else {
                    currentObject = undefined;
                    currentArray = prev;
                }
            }
        };

        parser.onopenarray = function onOpenArray() {
            if (currentObject) {
                currentObject[currentKey] = [];
                stack.push(currentObject);
                currentArray = currentObject[currentKey];
                currentObject = undefined;
            } else if (currentArray) {
                var newArr = [];
                stack.push(currentArray);
                currentArray.push(newArr);
                currentArray = newArr;
            } else {
                currentArray = [];
            }
        };

        parser.onclosearray = function onCloseArray() {
            var prev = stack.pop();
            if (!prev) {
                values.push(currentArray);
                lastIndex = parser.index;
                currentArray = undefined;
            } else {
                if (typeof prev === 'object') {
                    currentObject = prev;
                    currentArray = undefined;
                } else {
                    currentArray = prev;
                }
            }
        };

        /**
         * @param {string} key the key.
         */
        parser.onkey = function onKey(key) {
            currentKey = key;
        };

        /**
         * @param {*} the value.
         */
        parser.onvalue = function onValue(value) {
            if (currentObject) {
                currentObject[currentKey] = value;
            } else if (currentArray) {
                currentArray.push(value);
            } else {
                values.push(value);
                lastIndex = parser.index;
            }
        };

        // Parse.
        parser.write(json).close();

        // The properties.
        var props = {
                _values: { value: values, writable: false, enumerable: false, configurable: false },
                _lastIndex: { value: lastIndex, writable: true, enumerable: false, configurable: false },
        };
        Object.defineProperties(this, props);
    },

    /**
     * @return {boolean} true if there are more values available.
     */
    more: function more() {
        return this._values.length > 0;
    },

    /**
     * @return {string|number|object|array|boolean|null} the next value or
     *         undefined if there is none.
     */
    nextValue: function nextValue() {
        if (this._values.length == 0)
            return undefined;
        return this._values.shift();
    },

    /**
     * @return {number} the index of the last character successfully parsed
     *         into a value.
     */
    lastIndex: function lastIndex() {
        return this._lastIndex;
    },
});

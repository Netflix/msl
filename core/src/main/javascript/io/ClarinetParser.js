/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var MslConstants = require('../MslConstants.js');
	
	var clarinet = require('../lib/clarinet.js');
	
	var ClarinetParser = module.exports = Class.create({
	    /**
	     * Create a new clarinet parser that is ready to accept input.
	     */
	    init: function init() {
	        // Create the parser.
	        //
	        // Override the buffer check position as we will be working with
	        // large amounts of data.
	        var parser = clarinet.parser();
	        parser.bufferCheckPosition = MslConstants.MAX_LONG_VALUE;
	        
            var state = {
                values: [],
                stack: [],
                currentObject: undefined,
                currentArray: undefined,
                currentKey: undefined,
            };
	
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
	            if (state.currentObject) {
	                state.currentObject[state.currentKey] = {};
	                state.stack.push(state.currentObject);
	                state.currentObject = state.currentObject[state.currentKey];
	            } else if (state.currentArray) {
	                var newObj = {};
	                state.stack.push(state.currentArray);
	                state.currentArray.push(newObj);
	                state.currentObject = newObj;
	                state.currentArray = undefined;
	            } else {
	                state.currentObject = {};
	            }
	            state.currentKey = key;
	        };
	
	        parser.oncloseobject = function onCloseObject() {
	            var prev = state.stack.pop();
	            if (!prev) {
	                state.values.push(state.currentObject);
	                state.currentObject = undefined;
                    parser.pause();
	            } else {
	                if (typeof prev === 'object') {
	                    state.currentObject = prev;
	                } else {
	                    state.currentObject = undefined;
	                    state.currentArray = prev;
	                }
	            }
	        };
	
	        parser.onopenarray = function onOpenArray() {
	            if (state.currentObject) {
	                state.currentObject[state.currentKey] = [];
	                state.stack.push(state.currentObject);
	                state.currentArray = state.currentObject[state.currentKey];
	                state.currentObject = undefined;
	            } else if (state.currentArray) {
	                var newArr = [];
	                state.stack.push(state.currentArray);
	                state.currentArray.push(newArr);
	                state.currentArray = newArr;
	            } else {
	                state.currentArray = [];
	            }
	        };
	
	        parser.onclosearray = function onCloseArray() {
	            var prev = state.stack.pop();
	            if (!prev) {
	                state.values.push(state.currentArray);
	                state.currentArray = undefined;
                    parser.pause();
	            } else {
	                if (typeof prev === 'object') {
	                    state.currentObject = prev;
	                    state.currentArray = undefined;
	                } else {
	                    state.currentArray = prev;
	                }
	            }
	        };
	
	        /**
	         * @param {string} key the key.
	         */
	        parser.onkey = function onKey(key) {
	            state.currentKey = key;
	        };
	
	        /**
	         * @param {*} the value.
	         */
	        parser.onvalue = function onValue(value) {
	            if (state.currentObject) {
	                state.currentObject[state.currentKey] = value;
	            } else if (state.currentArray) {
	                state.currentArray.push(value);
	            } else {
	                state.values.push(value);
	                parser.pause();
	            }
	        };
	
	        // The properties.
	        var props = {
	            _parser: { value: parser, writable: false, enumerable: false, configurable: false },
	            _state: { value: state, writable: false, enumerable: false, configurable: false },
	        };
	        Object.defineProperties(this, props);
	    },
	    
	    /**
	     * Write more JSON data into the parser and attempt to parse another
	     * value. The provided string does not have to be fully-formed JSON--
	     * the fully-formed JSON may be provided via multiple calls to this
	     * function.
	     * 
	     * @param {string} s JSON string data.
	     */
	    write: function write(s) {
	        // Increase the count of unparsed characters.
	        var state = this._state;
	        
	        // Write the JSON into the parser which will hopefully result in a
	        // value being extracted.
	        this._parser.resume();
	        this._parser.write(s);
	    },
	
	    /**
	     * @return {string|number|object|array|boolean|null} the next value or
	     *         undefined if there is none.
	     */
	    nextValue: function nextValue() {
	        var state = this._state;
	        
	        // If there aren't any values already parsed and there are unparsed
	        // characters then resume processing.
	        if (state.values.length == 0 && this._parser.pending.length > 0) {
	            this._parser.resume();
	            this._parser.parse();
	        }
	        
	        // If there is an already parsed value return it.
	        if (state.values.length > 0)
	            return state.values.shift();
	        
	        // Otherwise return undefined.
	        return undefined;
	    },
	    
	    /**
	     * @return {number} the number of characters that remain unparsed.
	     */
	    unparsedCount: function unparsedCount() {
	        return this._parser.pending.length;
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('ClarinetParser'));

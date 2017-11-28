/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
 * <p>A factory for Promise. This is necessary because Promise exists in
 * some environments but needs to be imported or defined in others.</p>
 */
(function(require, module) {
    "use strict";

    /**
     * The Promise class.
     * 
     * @type {function}
     */
    var impl;
    
    /**
     * <p>Set the Promise class definition. Calls to {@link #create()} will
     * instantiate a new instance of this class.</p>
     * 
     * @param {function} i the class definition.
     */
    var setImpl = function setImpl(i) {
        impl = i;
    };
    
    /**
     * <p>Returns a new Promise instance.</p>
     * 
     * @param {function} executor the Promise executor function.
     * @return {object} a new Promise.
     */
    var create = function create(executor) {
        return new impl(executor);
    };

    /* global Promise: false */
    if (typeof Promise !== 'undefined')
        setImpl(Promise);
    
    // Exports.
    module.exports.setImpl = setImpl;
    module.exports.create = create;
})(require, (typeof module !== 'undefined') ? module : mkmodule('PromiseFactory'));
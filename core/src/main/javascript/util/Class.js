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
(function(require, module) {
	"use strict";
	
	/**
	 * Gets whether the argument obj is a direct instance of Object
	 * @param obj {*}
	 * @return {Boolean}
	 */
	function isObjectLiteral(obj) {
	    //If the object is not null, it's of type object
	    //and its constructor is the Object constructor.
	    //This will return false for an instance created via var inst = new Class.create();
	    //Since the instance's constructor will be set to its actual constructor
	    //Also for HTML Elements since their constructor will be of type HTMLElement
	    return obj !== null &&
	        typeof obj === 'object' &&
	        obj.constructor === Object;
	}
	
	/**
	 * Extend an object with other objects like extend but if properties are also objects in both recursively extend them as well
	 *
	 * @param {Boolean} arg0 onlyIfNew Optional; true to copy a property only if it doesn't already exist on the target
	 * @param {Object} arg0|arg1 Target object (arg1 if onlyIfNew passed in)
	 * @param {Object} arg1|arg2...argN Objects to extend target object with
	 */
	function extendDeep() {
	    var target = arguments[0],
	        i = 1,
	        length = arguments.length,
	        onlyIfNew = false,
	        options, name, src, copy
	    ;
	
	    if (typeof target === "boolean") {
	        onlyIfNew = target;
	        target = arguments[1];
	        i = 2;
	    }
	
	    for ( ; i < length; i++ ) {
	
	        if ( (options = arguments[ i ]) != null ) {
	            // Only deal with non-null/undefined values
	
	            // Extend the base object
	            for ( name in options ) {
	                if (onlyIfNew && name in target) {
	                    // Property already in target
	                    continue;
	                }
	
	                copy = options[ name ];
	
	                if ( target === copy ) {
	                    // Prevent never-ending loop
	                    continue;
	
	                } else if ( copy !== undefined ) {
	                    // Don't bring in undefined values
	
	                    src = target[ name ];
	
	                    //typeof null returns 'object', so if one is null instead of overwriting with
	                    //null it overwrites with a new object
	                    if (src !== null &&
	                        copy !== null &&
	                        typeof src === 'object' &&
	                        typeof copy === 'object') {
	                        target[ name ] = extendDeep(onlyIfNew, {}, src, copy);
	                    } else {
	                        target[ name ] = copy;
	                    }
	                }
	            }
	        }
	    }
	
	    // Return the modified object
	    return target;
	}
	
	/**
	 * @class Class Provides simple class creation and inheritance
	 *
	 * Based on work from John Resig, base2, and Prototype. Class uses namespace
	 * safe method access allowing renaming of Class.
	 *
	 * Create an empty Class:
	 *
	 * var MyEmptyClass = Class.create();
	 *
	 * Create a typical Class instance:
	 *
	 * var MyClass = Class.create({
	 *     init: function () {
	 *         // This method serves as the constructor
	 *     },
	 *     aPrototypeMethod: function () {
	 *         // All methods and properties are assigned to MyClass.prototype
	 *     }
	 * });
	 *
	 * Extend a Class instance:
	 *
	 * var YourClass = MyClass.extend({
	 *     init: function init() {
	 *         // Base class properties are overwritten. Base methods can be invoked
	 *         // using <funcname>.base.
	 *         init.base.call(this, arg1, arg2);
	 *     },
	 *     f: function f() {
	 *         f.base.call(this, arg1, arg2);
	 *     },
	 * });
	 *
	 */
    var _doNotInit = {},
        propertiesSafeToExtend = {
            actions: true
        },
        baseDefault = function (){};

    //All functions get a base property
    //"All your base are belong to us"... :)
    Function.prototype.base = baseDefault;

    /**
     * This hack is here because a mixin can't be applied to
     * 2 different classes as it would overwrite the base property.
     * For the most part, this is not a common scenario.
     * If you're worried about the performance
     * aspect, it won't be horribly slow, to make faster have the mixin
     * be returned from a factory.
     *
     * @param derivedFn
     * @param baseFn
     * @returns {Function}
     */
    function mixinBaseHack(derivedFn, baseFn){
        return function mixinWrapper(){
            var base = derivedFn.base,
                result;

            derivedFn.base = baseFn;
            result = derivedFn.apply(this, arguments);
            derivedFn.base = base;
            return result;
        };
    }

    /**
     * Mixin the properties of source into the receiver
     * @param receiver  {Object} the object to receive new properties/methods
     * @param source    {Object} the source of the new properties/methods
     * @param objectPropertiesToExtend      {Object} key to boolean map of object properties that are ok to extend
     * @param objectPropertiesToExtend.extendAll    {Boolean} *optional. Defaults to false.  Pass in true and all object properties get deeply extended.
     */
    function mixin(receiver, source, objectPropertiesToExtend) {

        var fnType = 'function', name, getter, setter, value, currentValue, extendAllObjectProperties;

        //provide a default
        objectPropertiesToExtend = objectPropertiesToExtend || propertiesSafeToExtend;
        extendAllObjectProperties = !!objectPropertiesToExtend.extendAll;

        // Copy the properties over onto the new receiver
        for (name in source) {

            getter = source.__lookupGetter__(name);
            setter = source.__lookupSetter__(name);

            if (getter || setter) {
                getter && receiver.__defineGetter__(name, getter);
                setter && receiver.__defineSetter__(name, setter);
            }
            else {
                value = source[name];
                currentValue = receiver[name];

                if (typeof value === fnType &&
                    typeof currentValue === fnType &&
                    value !== currentValue) {

                    //if value already has a base then we need to wrap it
                    if (value.base !== Function.prototype.base){
                        value = mixinBaseHack(value, currentValue);
                    }

                    value.base = currentValue;


                }
                //By default extending all object properties almost worked but ran into some hairy issues
                //with bowser jr.  When a class is extended, and the derived properties contain references to
                //class instances this gets sticky and can fail.  For now a case by case basis is the safe way.
                else if ((extendAllObjectProperties || objectPropertiesToExtend[name]) &&
                    isObjectLiteral(value) &&
                    isObjectLiteral(currentValue)) {

                    //extend this object into the receiver
                    value = extendDeep({}, currentValue, value);
                }

                receiver[name] = value;
            }
        }
    }

    /**
     * Overrides the Function.bind contract to ensure that another class
     * constructor is emitted when called instead of a wrapper function.
     *
     * Normally bind just creates a wrapper function around an inner function.
     * This behavior is undesirable though as class methods like extend are
     * lost.
     *
     * @public
     * @returns {Function} A Class instance
     */
    function _bind() {
        var slice = Array.prototype.slice,
            bindArgs = slice.call(arguments, 1);
        return this.extend({
            init: function init() {
                var args = slice.call(arguments, 0);
                init.base.apply(this, bindArgs.concat(args));
            }
        });
    }


    /**
     * Extends a Class instance with properties to create a sub-class. Executes
     * in scope of a Class instance.
     * @public
     * @param {Object} props Object descriptor with key/value pairs
     * @param {Object} objectPropertiesToExtend object properties you want extended.
     * @returns {Function} A Class instance
     */
    function _extend(props, objectPropertiesToExtend) {
        var prototype = new this(_doNotInit);

        mixin(prototype, props, objectPropertiesToExtend);

        return _create(prototype);
    }

    /**
     * Extends a Class's prototype with properties.  Executes in the scope of a
     * Class instance
     * @public
     * @param props {Object}
     * @param objectPropertiesToExtend {Object} a key/boolean mapping of object properties to extend
     * @return {Function} the Class instance
     */
    function _mixin(props, objectPropertiesToExtend) {
        mixin(this.prototype, props, objectPropertiesToExtend);
        return this;
    }

    /**
     * Creates a new Class instance, optionally including a prototype
     * object.  This method is not applied to returned Class instances;
     * use Class.extend to sub-class Class instances.
     * @public
     * @param {Object} props Object descriptor with key/value pairs
     * @returns {Function} A Class instance
     */
    function _create(props) {
        var Class = function () {
            var init = this.init;

            // All construction is actually done in the init method
            if (init && arguments[0] !== _doNotInit) {
                init.apply(this, arguments);
            }
        };

        // Ensure that the Chrome profiler shows relevant class names, instead
        // of 'Class' when memory debugging is enabled.  eval the className as
        // the function of the dummy class constructor.

        //var className = props && props.classId || "UNKNOWN";
        //eval("var " + className + " = function() { var init = this.init; if (init && arguments[0] !== _doNotInit) { init.apply(this, arguments); } }; Class = " + className + ";");

        // Populate our constructed prototype object
        if (props) {
            Class.prototype = props;
        }

        // Enforce the constructor to be what we expect
        //if you don't do this then all instance's constructor will be the native object
        Class.prototype.constructor = Class;

        // And make this class extendable
        Class.extend = _extend;

        // And overload the bind function to create a subclass
        Class.bind = _bind;

        //add in mixin functionality
        Class.mixin = _mixin;

        return Class;
    }

    // Exports.
    module.exports.create = _create;
    module.exports.mixin = mixin;
    
    /**
     * Create a new extendable Class instance from a super Class
     * that wasn't created through Class.
     * @param {Function} superClass
     * @param {Object} prototype Class prototype
     * @return {Function} A Class instance
     */
    module.exports.extend = function(superClass, prototype) {
        var subClass = _create();
        subClass.prototype = new superClass();
        return subClass.extend(prototype);
    };
})(require, (typeof module !== 'undefined') ? module : mkmodule('Class'));
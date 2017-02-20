/**
 * Copyright (c) 2012-2016 Netflix, Inc.  All rights reserved.
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
(function(scope) {
	"use strict";
	
	/**
	 * <p>Define {@code require} that can be used to access symbols. If
	 * {@code require} is already defined then it is not redefined. If it is not
	 * defined, then it is defined to return the type matching the file name in
	 * the provided path, if found in the top-level scope.</p>
	 * 
	 * <p>e.g. {@code require('../a/b/C.js')} to access type {@code C}.</p>
	 */
	if (typeof require === 'undefined') {
		scope.require = function(path) {
			var begin = path.lastIndexOf('/') + 1;
			var end = path.lastIndexOf('.js');
			if (end < 0 || end < begin) throw new Error("Cannot identify type from path [" + path + "].");
			var type = path.substring(begin, end);
			return scope[type];
		}
	}
	
	/**
	 * <p>Define {@code mkmodule(type)} to return a handle to the module object
	 * that can be used to export symbols. If {@code module} is already defined
	 * then the function simply returns {@code module}. If it is not defined,
	 * then a variable named {@code type} will be created in the top-level
	 * scope and referenced as {@code module.exports}.</p>
	 * 
	 * <p>e.g. {@code module.exports = ...} to export a module and
	 * {@code module.exports.a = ...} to export properties of a module.</p>
	 * 
	 * @param {string} type the symbol that will be used for the exports.
	 */
	scope.mkmodule = function(type) {
		return { 
			set exports(value) {
				scope[type] = value;
			},
			get exports() {
				return scope[type];
			}
		};
	};
})(this);
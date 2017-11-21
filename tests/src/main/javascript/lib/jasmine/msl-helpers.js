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
var isNodeJS = typeof window == "undefined" && typeof exports == "object";

if (isNodeJS) {
    // Setup MSL for Node.js.
    var MslSetup = require('msl-core/util/MslSetup.js');
    var NodeMslSetup = require('../../util/NodeMslSetup.js');
    MslSetup.execute(new NodeMslSetup());
    
    // Capture and output thrown errors.
    process.on('unhandledRejection', function(r) {
        console.log(r);
        if (r.stack) console.log(r.stack);
    });
}

jasmine.Env.prototype.parameterize = function(description, paramDefinitions, specDefinitions) {
  var suite = new jasmine.Suite(this, description, specDefinitions, this.currentSuite);
  
  var parentSuite = this.currentSuite;
  if (parentSuite) {
    parentSuite.add(suite);
  } else {
    this.currentRunner_.add(suite);
  }
  
  this.currentSuite = suite;
  
  var declarationError = null;
  try {
      var paramList = paramDefinitions.call(suite);
      for (var i = 0; i < paramList.length; ++i) {
          var params = paramList[i];
          var paramDescription = JSON.stringify(params);
          var paramSpecDefinitions = function() {
              specDefinitions.apply(this, params);
          };
          describe(paramDescription, paramSpecDefinitions);
      }
  } catch(e) {
      declarationError = e;
  }
  
  if (declarationError) {
    this.it("encountered a declaration exception", function() {
      throw declarationError;
    });
  }
  
  this.currentSuite = parentSuite;
  
  return suite;
};

jasmine.Env.prototype.xparameterize = function(desc, paramDefinitions, specDefinitions) {
  return {
    execute: function() {
    }
  };
};

/**
 * Defines a parameterized suite of specifications.
 * 
 * Stores the description and all defined specs in the Jasmine environment as one suite of specs. Variables declared
 * are accessible by calls to beforeEach, it, and afterEach. Describe blocks can be nested, allowing for specialization
 * of setup in some tests.
 *
 * @example
 * // TODO: a simple suite
 *
 * // TODO: a simple suite with a nested describe block
 *
 * @param {String} description A string, usually the class under test.
 * @param {Function} paramDefinitions function that returns an array of parameter arrays.
 * @param {Function} specDefinitions function that defines several specs, accepting the parameters.
 */
var parameterize = function(description, paramDefinitions, specDefinitions) {
    return jasmine.getEnv().parameterize(description, paramDefinitions, specDefinitions);
};
if (isNodeJS) module.exports.parameterize = parameterize;

/**
 * Disables a parameterized suite of specifications.  Used to disable some suites in a file, or files, temporarily during development.
 *
 * @param {String} description A string, usually the class under test.
 * @param {Function} paramDefinitions function that returns an array of parameter arrays.
 * @param {Function} specDefinitions function that defines several specs, accepting the parameters.
 */
var xparameterize = function(description, paramDefinitions, specDefinitions) {
  return jasmine.getEnv().xparameterize(description, paramDefinitions, specDefinitions);
};
if (isNodeJS) module.exports.xparameterize = xparameterize;

/**
 * Matcher that checks that the expected exception was thrown by the actual.
 *
 * @param {Error} expected expected exception.
 * @param {number} messageId expected MSL message ID.
 */
jasmine.Matchers.prototype.toThrow = function(expected, messageId) {
  var MslException = require('msl-core/MslException.js');
  var MslError = require('msl-core/MslError.js');
  
  var result = false;
  var exception;
  if (typeof this.actual != 'function') {
    throw new Error('Actual is not a function');
  }
  try {
    this.actual();
  } catch (e) {
    exception = e;
  }
  if (exception) {
    result = (expected === jasmine.undefined ||
              (!(expected instanceof MslException) && this.env.equals_(exception.message || exception, expected.message || expected)) ||
               ((expected.name == 'MslException' || exception.name == expected.name) &&
                (expected.error == MslError.NONE || exception.error == expected.error) &&
                (messageId == undefined || messageId == null || exception.messageId == messageId)));
  }

  var not = this.isNot ? "not " : "";

  this.message = function() {
    if (exception && (expected === jasmine.undefined || !result)) {
      var expectedInfo;
      if (expected) {
          if (expected.name) {
              expectedInfo = expected.name;
              if (expected.error != MslError.NONE) expectedInfo += ' ' + expected.message;
              if (messageId != undefined && messageId != null) expectedInfo += ' [messageId:' + messageId + ']';
          } else {
              expectedInfo = expected;
          }
      }
      var exceptionInfo = exception;
      if (exception.name) {
          exceptionInfo = exception.name;
          if (exception.error != MslError.NONE) exceptionInfo += ' ' + exception.message;
          if (exception.messageId != undefined && exception.messageId != null) exceptionInfo += ' [messageId:' + exception.messageId + ']';
      }
      return ["Expected function " + not + "to throw ",
              (expectedInfo) ? expectedInfo : "an exception",
              ", but it threw ",
              exceptionInfo].join('');
    } else {
      return "Expected function to throw an exception.";
    }
  };
  if (exception)
      this.stack = exception.stack;

  return result;
};

/**
 * Override matcher function to include stack trace.
 *
 * @param {string} matcher name.
 * @param {function} matcher function.
 */
jasmine.Matchers.matcherFn_ = function(matcherName, matcherFunction) {
  return function() {
    var matcherArgs = jasmine.util.argsToArray(arguments);
    var result = matcherFunction.apply(this, arguments);

    if (this.isNot) {
      result = !result;
    }

    if (this.reportWasCalled_) return result;

    var message;
    if (!result) {
      if (this.message) {
        message = this.message.apply(this, arguments);
        if (jasmine.isArray_(message)) {
          message = message[this.isNot ? 1 : 0];
        }
      } else {
        var englishyPredicate = matcherName.replace(/[A-Z]/g, function(s) { return ' ' + s.toLowerCase(); });
        message = "Expected " + jasmine.pp(this.actual) + (this.isNot ? " not " : " ") + englishyPredicate;
        if (matcherArgs.length > 0) {
          for (var i = 0; i < matcherArgs.length; i++) {
            if (i > 0) message += ",";
            message += " " + jasmine.pp(matcherArgs[i]);
          }
        }
        message += ".";
      }
    }
    var expectationResult = new jasmine.ExpectationResult({
      matcherName: matcherName,
      passed: result,
      expected: matcherArgs.length > 1 ? matcherArgs : matcherArgs[0],
      actual: this.actual,
      message: message,
    });
    if (this.stack) {
      expectationResult.trace = { stack: this.stack };
    }
    this.spec.addMatcherResult(expectationResult);
    return jasmine.undefined;
  };
};

/**
 * Override equals function to use equals methods on objects.
 *
 * @param {?} a first value.
 * @param {?} b second value.
 * @param {Array<?>} mismatchKeys out parameter that returns any mismatched
 *        keys.
 * @param {Array<?>} mismatchValues out parameter that returns any mismatched
 *        values.
 */
jasmine.Env.prototype.equals_ = function(a, b, mismatchKeys, mismatchValues) {
    mismatchKeys = mismatchKeys || [];
    mismatchValues = mismatchValues || [];

    for (var i = 0; i < this.equalityTesters_.length; i++) {
      var equalityTester = this.equalityTesters_[i];
      var result = equalityTester(a, b, this, mismatchKeys, mismatchValues);
      if (result !== jasmine.undefined) return result;
    }

    if (a === b) return true;

    if (a === jasmine.undefined || a === null || b === jasmine.undefined || b === null) {
      return (a == jasmine.undefined && b == jasmine.undefined);
    }

    if (jasmine.isDomNode(a) && jasmine.isDomNode(b)) {
      return a === b;
    }

    if (a instanceof Date && b instanceof Date) {
      return a.getTime() == b.getTime();
    }

    if (a.jasmineMatches) {
      return a.jasmineMatches(b);
    }

    if (b.jasmineMatches) {
      return b.jasmineMatches(a);
    }

    if (a instanceof jasmine.Matchers.ObjectContaining) {
      return a.matches(b);
    }

    if (b instanceof jasmine.Matchers.ObjectContaining) {
      return b.matches(a);
    }

    if (jasmine.isString_(a) && jasmine.isString_(b)) {
      return (a == b);
    }

    if (jasmine.isNumber_(a) && jasmine.isNumber_(b)) {
      return (a == b);
    }

    if (a instanceof RegExp && b instanceof RegExp) {
      return this.compareRegExps_(a, b, mismatchKeys, mismatchValues);
    }

    if (typeof a === "object" && typeof b === "object") {
      if (typeof a['equals'] === 'function')
          return a.equals(b);
      if (typeof b['equals'] === 'function')
          return b.equals(a);
      return this.compareObjects_(a, b, mismatchKeys, mismatchValues);
    }

    //Straight check
    return (a === b);
  };
var isCommonJS = typeof window == "undefined" && typeof exports == "object";

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
if (isCommonJS) exports.parameterize = parameterize;

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
if (isCommonJS) exports.xparameterize = xparameterize;

/**
 * Matcher that checks that the expected exception was thrown by the actual.
 *
 * @param {Error} [expected]
 * @param {number} [messageId]
 */
jasmine.Matchers.prototype.toThrow = function(expected, messageId) {
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

  return result;
};
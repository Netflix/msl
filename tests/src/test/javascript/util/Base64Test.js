/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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

const Base64 = require('../../../../../core/src/main/javascript/util/Base64.js');

const textEncoding = require('../../../../../core/src/main/javascript/lib/textEncoding.js');

/**
 * Base64 tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("Base64", function() {
    /** UTF-8 charset. */
    var CHARSET = "utf-8";
    
    /** Standard Base64 examples. */
    var EXAMPLES = [
        {data: textEncoding.getBytes("The long winded author is going for a walk while the light breeze bellows in his ears.", CHARSET),
         base64: "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4="},
        {data: textEncoding.getBytes("Sometimes porcupines need beds to sleep on.", CHARSET),
         base64: "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg=="},
        {data: textEncoding.getBytes("Even the restless dreamer enjoys home-cooked foods.", CHARSET),
         base64: "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu"},
    ];
    /** URL-safe Base64 examples. */
    var URL_EXAMPLES = [
        {data: textEncoding.getBytes("The long winded author is going for a walk while the light breeze bellows in his ears.", CHARSET),
         base64: "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4"},
        {data: textEncoding.getBytes("Sometimes porcupines need beds to sleep on.", CHARSET),
         base64: "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg"},
        {data: textEncoding.getBytes("Even the restless dreamer enjoys home-cooked foods.", CHARSET),
         base64: "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu"}
    ];
    
    it("standard", function() {
       for (var i = 0; i < EXAMPLES.length; ++i) {
    	   // Prepare.
           var example = EXAMPLES[i];
           var data = example.data;
           var base64 = example.base64;
           
           // Encode/decode.
           var encoded = Base64.encode(data);
           var decoded = Base64.decode(base64);
           
           // Validate.
           expect(encoded).toEqual(base64);
           expect(decoded).toEqual(data);
       }
    });
    
    it("whitespace", function() {
        for (var i = 0; i < EXAMPLES.length; ++i) {
        	// Prepare.
            var example = EXAMPLES[i];
            var data = example.data;
            var base64 = example.base64;
            
            // Modify.
            var half = base64.length / 2;
            var modifiedBase64 = "  \t" + base64.substring(0, half) + "\r\n \r\n\t" + base64.substring(half) + " \t \n";
            
            // Encode/decode.
            var encoded = Base64.encode(data);
            var decoded = Base64.decode(modifiedBase64);
            
            // Validate.
            expect(encoded).toEqual(base64);
            expect(decoded).toEqual(data);
        }
    });
    
    it("url-safe", function() {
        for (var i = 0; i < URL_EXAMPLES.length; ++i) {
     	   // Prepare.
            var example = URL_EXAMPLES[i];
            var data = example.data;
            var base64 = example.base64;
            
            // Encode/decode.
            var encoded = Base64.encode(data, true);
            var decoded = Base64.decode(base64, true);
            
            // Validate.
            expect(encoded).toEqual(base64);
            expect(decoded).toEqual(data);
        }
    });
});
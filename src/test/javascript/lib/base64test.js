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

/**
 * Base64 tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("base64", function() {
    /** UTF-8 charset. */
    var CHARSET = "utf-8";
    
    /** Standard Base64 examples. */
    var EXAMPLES = [
        {data: textEncoding$getBytes("The long winded author is going for a walk while the light breeze bellows in his ears.", CHARSET),
         base64: "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4="},
        {data: textEncoding$getBytes("Sometimes porcupines need beds to sleep on.", CHARSET),
         base64: "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg=="},
        {data: textEncoding$getBytes("Even the restless dreamer enjoys home-cooked foods.", CHARSET),
         base64: "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu"},
    ];
    /** URL-safe Base64 examples. */
    var URL_EXAMPLES = [
        {data: textEncoding$getBytes("The long winded author is going for a walk while the light breeze bellows in his ears.", CHARSET),
         base64: "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4"},
        {data: textEncoding$getBytes("Sometimes porcupines need beds to sleep on.", CHARSET),
         base64: "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg"},
        {data: textEncoding$getBytes("Even the restless dreamer enjoys home-cooked foods.", CHARSET),
         base64: "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu"}
    ];
    
    it("standard", function() {
       for (var i = 0; i < EXAMPLES.length; ++i) {
           var example = EXAMPLES[i];
           var encoded = base64$encode(example.data);
           var decoded = base64$decode(example.base64);
           expect(encoded).toEqual(example.base64);
           expect(decoded).toEqual(example.data);
       }
    });
    
    it("url-safe", function() {
        for (var i = 0; i < URL_EXAMPLES.length; ++i) {
            var example = URL_EXAMPLES[i];
            var encoded = base64$encode(example.data, true);
            var decoded = base64$decode(example.base64, true);
            expect(encoded).toEqual(example.base64);
            expect(decoded).toEqual(example.data);
        }
    });
});
/**
 * Copyright (c) 2013-2018 Netflix, Inc.  All rights reserved.
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
describe("Base64", function() {
    var Base64 = require('msl-core/util/Base64.js');
    var Base64Secure = require('msl-core/util/Base64Secure.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');
    
    /** Binary Base64 example. */
    var BINARY_B64 = "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";
    
    /** Standard Base64 examples. */
    var EXAMPLES = [
        {data: TextEncoding.getBytes("The long winded author is going for a walk while the light breeze bellows in his ears.", TextEncoding.Encoding.UTF_8),
         base64: "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4="},
        {data: TextEncoding.getBytes("Sometimes porcupines need beds to sleep on.", TextEncoding.Encoding.UTF_8),
         base64: "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg=="},
        {data: TextEncoding.getBytes("Even the restless dreamer enjoys home-cooked foods.", TextEncoding.Encoding.UTF_8),
         base64: "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu"},
         {data: new Uint8Array([71, 73, 70, 56, 57, 97, 61, 0, 68, 0, -9, -88, 0, -102, 44, 51, -1, -64, -64, -17, -64, -64, 117, 88, 103, -4, -7, -9, -103, 51, 0, -1, -20, -20, -1, -96, -96, -27, -52, -65, -49, -97, -121, 15, -17, -17, 127, 127, 127, -17, 15, 15, -33, 31, 31, -1, 38, 38, 95, -97, -97, -1, 89, 89, -65, 63, 63, 53, -91, -62, -1, -1, -1, -84, 22, 25, -78, 38, 0, -8, 19, 16, -62, 38, 32, -33, 96, 80, 80, -124, -101, -8, 3, 0, -75, 11, 12, -33, 15, 0, 62, -102, -75, -121, 66, 77, 127, 96, 80, -46, -91, -113, -52, 25, 0, -91, 44, 0, -20, -39, -49, -27, 12, 0, -21, 9, 0, -1, -39, -39, -57, 12, 12, 15, 15, 15, -1, 121, 121, 126, 77, 90, -5, 9, 8, -27, 77, 64, -5, 95, 95, -1, 51, 51, -49, -112, 120, -14, -27, -33, -61, 6, 6, -65, 9, 8, -1, -77, -77, -39, -78, -97, -1, 6, 6, -84, 41, 0, -1, -58, -58, 12, 9, 8, -7, -14, -17, -55, 115, 96, -72, 35, 0, -97, 47, 0, -1, 95, 95, -1, -116, -116, -59, 28, 0, -33, 51, 51, -1, 112, 112, -49, 25, 25, -64, 19, 16, -65, -112, 120, -9, 89, 89, -1, -10, -10, -25, 63, 63, -41, 38, 38, -17, 76, 76, 50, 38, 32, -33, -65, -81, -65, -65, -65, 63, 63, 63, -59, 77, 64, 99, 110, -127, 95, 0, 0, 95, 95, 95, -53, 48, 48, -40, 19, 0, 89, 67, 56, -128, -128, -128, -13, 82, 82, 115, 86, 72, -60, 57, 48, 16, 16, 16, -111, 55, 64, -14, 6, 0, -49, 64, 64, -54, -122, 112, 111, 111, 111, -93, 33, 38, -63, 29, 24, -49, 47, 47, 31, 31, 31, -33, 0, 0, -46, 22, 0, -53, -112, 120, -65, 31, 0, 25, 19, 16, -13, -48, -48, -29, 57, 57, 38, 29, 24, 89, 121, -114, -113, -113, -113, -1, -87, -87, -53, 19, 19, -65, 48, 48, 83, 70, 64, -74, 38, 32, 62, 29, 24, -5, -35, -35, 64, 64, 64, -103, -109, -112, -1, -68, -68, 127, 80, 80, -81, -81, -81, -58, 86, 72, 122, 115, 112, -109, 38, 32, -73, 112, 112, -77, -122, 112, 116, 80, 80, 124, 112, 112, -81, 79, 79, -48, -48, -48, -17, -17, -17, 76, 57, 48, -68, -87, -96, 111, 48, 40, -21, -80, -80, -1, -32, -32, -1, -48, -48, -121, 48, 40, 75, 48, 40, -55, 124, 104, -97, 95, 95, 108, 99, 116, -21, 70, 70, -49, -49, -49, -32, -32, -32, 98, 38, 32, -1, 32, 32, 125, 44, 40, 64, 48, 40, -87, -109, -120, -90, 124, 104, 31, -33, -33, -43, -84, -105, -30, -59, -73, -57, 96, 80, 79, 79, 79, -100, 121, 104, 112, 112, 112, -1, -128, -128, -1, -106, -106, -41, 96, 96, -52, -103, 127, 44, -80, -49, -65, 0, 0, 0, 0, 0, 0, -1, -1, -1, 0, 0, -1, 102, 102, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, -7, 4, 1, 0, 0, -88, 0, 44, 0, 0, 0, 0, 61, 0, 68, 0, 0, 8, -1, 0, 81, 9, 28, 72, -80, -96, -63, -125, 8, 19, 42, 92, -56, -80, -95, -64, 27, 7, 12, 56, -100, 72, 113, -95, -119, 20, -89, 50, 70, -84, -56, -79, -94, 9, 31, 25, 67, 106, -108, -40, -79, 36, 66, 3, 7, 68, -86, 28, 105, -78, 37, 42, 35, 51, 86, -54, 100, -23, -78, -94, -99, 32, 51, 115, -98, -38, 88, -109, 33, 34, -116, 58, -125, -14, -20, 105, -16, 99, -48, -93, 33, -121, 18, 69, -119, -76, 105, 82, -110, 46, 97, 58, -99, -6, -76, -27, 12, -100, 84, -77, -18, -124, 58, -15, 6, 80, -83, 96, -107, 42, 52, 10, -74, 108, -43, -124, 6, 62, -103, 93, 27, -78, -59, -100, -125, 70, -38, -80, -99, 123, -28, -124, 0, -125, 87, -25, -82, 77, -30, 102, -44, -88, -69, 3, -67, -22, 53, 107, 69, -120, 95, -65, -128, 15, 121, 26, 92, -74, 8, -110, -61, -121, 1, 7, 48, -27, 0, 2, -29, -87, 45, -128, -60, -128, 28, 89, -32, 100, 83, -108, 45, 95, 14, 122, 100, 51, -25, -50, -88, 62, -125, 14, 61, 90, 102, -110, 19, -89, 71, 109, 24, 32, -31, -81, -25, -43, -72, 43, -73, -50, 88, 56, -10, 40, -38, -94, 68, -39, 78, -115, -69, -72, 110, -58, -114, 125, -113, -6, 18, 60, -8, -16, -49, 17, 26, 20, 7, 125, 124, 109, 102, -33, 0, -98, 108, 80, -47, 92, -72, 100, 83, 97, 74, -107, -1, 122, 32, 125, 122, 117, -83, 105, 76, 115, -90, -80, 38, 56, -128, 1, -35, -97, -101, -118, 32, 94, 60, -7, -23, -84, -87, 58, -126, 29, 123, -125, -124, -26, -17, -59, -9, 29, 125, -11, -39, 87, -98, 113, -94, 29, -107, -124, 97, -79, -87, -80, 1, 0, -35, 5, -40, -100, 124, 4, 22, 88, -118, 2, 11, 48, -128, -97, 11, 61, -24, -108, 92, 108, 30, 116, 32, 10, 0, 16, 2, 8, -33, -124, 3, 90, 88, 32, -122, 26, 22, 87, 3, -121, 43, 93, -25, 91, 6, 0, -106, -24, -34, -119, -50, -91, -88, -30, -118, 25, 78, -9, 98, -121, 25, -91, 23, 27, 5, -93, 80, 16, -95, -115, 35, -30, 88, -101, -114, 59, -14, -40, 34, 110, 47, -42, -43, -33, 19, -94, 120, -128, 36, -119, 17, -98, -40, -127, 22, 20, 54, -71, 35, -117, -45, -7, -26, -63, 127, -94, 12, 112, -27, -103, 18, -88, -128, -38, 100, 21, 122, 105, 33, -104, -85, -7, 70, 102, -103, 103, 118, 71, 36, 103, -33, 49, -96, -128, -101, 77, -62, 9, 25, 0, 25, 112, -39, -99, -103, 71, 54, -41, 72, 108, -33, -103, -62, -56, -98, 124, 126, 9, -120, 41, 126, 81, 64, 99, -103, -93, 12, 90, 103, 6, 0, -8, -106, -88, 41, 12, 44, -64, 104, -93, 5, 94, 2, -23, 40, -109, 82, 106, 105, -124, -53, 41, 39, 31, 110, -99, 126, 10, 106, 41, -93, 14, -1, 90, 105, 115, -124, 6, -41, -127, -86, 107, -82, -58, 1, 7, -96, -75, -6, 42, -84, 126, -55, 122, -86, 4, 3, 108, -128, 43, 98, -73, -127, 86, 64, 1, 36, -84, -42, -23, -85, -79, -46, 58, 107, 112, 106, 14, 112, -25, -79, -85, -102, 82, 65, 1, 33, 20, -41, -64, 3, -115, 70, 27, -36, 0, -45, -118, 114, 45, -74, -56, 18, 7, 90, 9, 21, -16, 58, -35, -73, 110, -118, 107, -86, 40, 29, 100, 122, -84, 20, -122, -128, -110, 43, 126, -8, -63, -69, -93, -68, -28, -82, -31, 1, -70, 82, -4, 65, 71, 39, 92, -92, -85, 26, -65, -17, -126, 107, -95, -68, 3, -93, -21, -41, 29, -92, 84, -52, -121, -62, -59, 113, 80, 2, -61, -85, -7, 43, -98, -72, 79, 72, -20, -41, 27, 89, 84, 76, -118, 31, 126, -95, -111, -20, 106, 34, -40, -64, 49, 110, -2, -114, -38, 65, 6, -25, -94, 59, 9, 41, 81, -80, 65, 74, 21, 92, -88, -68, 50, 104, 33, 20, -32, -18, -53, -96, 53, 16, -58, -88, 34, 115, 38, 7, 10, 19, 76, -80, 115, 65, 11, -101, -94, -127, 8, 34, 104, -16, 50, 15, 21, -32, -106, 52, 103, 50, -88, -47, 68, -45, -92, -24, 1, -11, 116, 28, 20, 96, -58, -53, -53, 78, 17, -25, -42, -121, 93, 64, -54, -41, -113, -112, -14, 1, 8, 35, 16, 116, -128, 36, -59, -103, -63, 45, -57, 63, 20, -1, 64, -58, -38, 108, -113, -30, 4, 41, 98, 48, -79, 9, 41, 125, -124, 18, 74, 38, 4, 5, 2, -59, 24, -72, -39, 80, -64, 15, 28, -109, 96, 53, 104, -127, 95, -80, 72, 40, 106, -104, -84, 68, 40, 32, -64, 96, 80, -59, -113, -125, -90, -63, -74, 59, 108, 49, -99, 6, 27, 107, -99, 52, 24, 58, 40, 30, 10, 21, 38, 115, 82, -73, 65, 57, -64, 81, -15, 32, 24, 88, 0, 90, -33, 60, -124, -96, 58, 104, 36, 72, 94, 28, 103, 67, 92, -96, -36, 16, -102, -56, -82, 56, 17, 103, 100, 81, 7, 1, 7, 33, 16, 10, 17, 87, 124, 32, 123, -17, -90, -112, -80, 109, 1, 34, 84, 32, 66, 1, 60, -88, -19, -70, 95, 88, 124, 112, 69, 30, -89, -55, -32, 68, 25, -50, -53, -66, 4, -11, 8, 17, -128, 64, 2, -15, 43, -50, 125, 9, 33, -20, 80, -63, 14, 100, -72, -36, -7, -122, -96, -120, -118, 81, 65, 6, -112, -63, 2, -4, -14, 71, -125, 28, 52, -60, 126, -8, -53, 31, -9, 94, 118, -104, 68, -104, 12, 7, -54, 27, -59, 5, -70, -112, -65, 80, 96, 66, 116, 20, -127, 96, 7, 39, -56, 47, -65, -56, 64, 9, 111, 67, 1, 41, -100, 0, -69, 14, -46, -51, 36, 34, -108, -96, -17, -16, -29, -105, 56, -32, 108, 2, 94, 32, 5, 7, -13, -105, 0, 4, -48, -81, 37, 49, 116, -34, 11, 124, 88, -80, -126, 48, -115, 98, 15, -92, 96, -62, 4, 22, 64, -118, 14, -50, -113, 40, 2, 9, -94, -20, -122, 88, -60, -75, 21, 34, -119, 56, -60, 65, -4, 26, 8, -59, -126, 72, 81, 113, 84, -60, -36, 40, 34, 65, 10, 60, 8, 2, 5, -108, -112, 29, 13, 64, -40, 69, -125, 124, 49, 20, 84, -68, -128, 14, 62, 64, 10, 20, -120, 65, 110, -96, -69, 93, 27, 19, -14, 70, -39, 89, -62, 100, 103, -24, -31, 30, 29, -46, -57, 80, -96, 16, 7, -124, -8, -31, 32, 31, 120, -65, -4, 17, -95, 18, -112, 88, 100, 71, -126, -72, 70, 73, 2, 113, 9, 47, -76, -92, 38, 91, 18, 16, 0, 59]),
         base64: BINARY_B64},
    ];
    /** URL-safe Base64 examples. */
    var URL_EXAMPLES = [
        {data: TextEncoding.getBytes("The long winded author is going for a walk while the light breeze bellows in his ears.", TextEncoding.Encoding.UTF_8),
         base64: "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4"},
        {data: TextEncoding.getBytes("Sometimes porcupines need beds to sleep on.", TextEncoding.Encoding.UTF_8),
         base64: "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg"},
        {data: TextEncoding.getBytes("Even the restless dreamer enjoys home-cooked foods.", TextEncoding.Encoding.UTF_8),
         base64: "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu"}
    ];
    /** Invalid Base64 examples. */
    var INVALID_EXAMPLES = [
        "AAAAA",
        "AAAAAAA",
        "%$#@=",
        "ZZZZZZZZZZ=",
        "ZZZZZZZZZ==",
        "U29tZXRpbWVzIHBvcmN1cGluZX=gbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg==",
        "RXZlbiB0aGUgcmVzdGxlc3MgZHJ=YW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu",
        "RXZlbiB0aGUgcmVzdGxlc3MgZHJ=Y",
        "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgY幸B3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4=",
    ];
    
    beforeEach(function() {
        Base64.setImpl(new Base64Secure());
    });
    
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
    
    it("invalid padding", function() {
        for (var i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            var example = EXAMPLES[i];
            var base64 = example.base64;
            
            // Modify.
            var modifiedBase64 = base64 + '=';
            
            // Decode.
            var invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (e) {
                if (e instanceof Error)
                    invalid = true;
            }
            expect(invalid).toBeTruthy();
        }
    });
    
    it("injected padding", function() {
        for (var i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            var example = EXAMPLES[i];
            var base64 = example.base64;
            
            // Modify.
            var half = base64.length / 2;
            var modifiedBase64 = base64.substr(0, half) + '=' + base64.substr(half);
            
            // Decode.
            var invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (e) {
                if (e instanceof Error)
                    invalid = true;
            }
            expect(invalid).toBeTruthy();
        }
    });
    
    it("invalid character", function() {
        for (var i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            var example = EXAMPLES[i];
            var base64 = example.base64;
            
            // Modify.
            var half = base64.length / 2;
            var modifiedBase64 = base64.substr(0, half) + '|' + base64.substr(half);
            
            // Decode.
            var invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (e) {
                if (e instanceof Error)
                    invalid = true;
            }
            expect(invalid).toBeTruthy();
        }
    });
    
    it("out of range character", function() {
        for (var i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            var example = EXAMPLES[i];
            var base64 = example.base64;
            
            // Modify.
            var half = base64.length / 2;
            var modifiedBase64 = base64.substr(0, half) + String.fromCharCode(128) + base64.substr(half);
            
            // Decode.
            var invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (e) {
                if (e instanceof Error)
                    invalid = true;
            }
            expect(invalid).toBeTruthy();
        }
    });
    
    it("invalid length", function() {
        for (var i = 0; i < EXAMPLES.length; ++i) {
            // Prepare.
            var example = EXAMPLES[i];
            var base64 = example.base64;
            
            // Modify.
            var modifiedBase64 = base64.substr(1);
            
            // Decode.
            var invalid = false;
            try {
                Base64.decode(modifiedBase64);
            } catch (e) {
                if (e instanceof Error)
                    invalid = true;
            }
            expect(invalid).toBeTruthy();
        }
    });
    
    it("invalid", function() {
        for (var i = 0; i < INVALID_EXAMPLES.length; ++i) {
            var base64 = INVALID_EXAMPLES[i];
            var invalid = false;
            try {
                Base64.decode(base64);
            } catch (e) {
                if (e instanceof Error)
                    invalid = true;
            }
            expect(invalid).toBeTruthy();
        }
    });
});
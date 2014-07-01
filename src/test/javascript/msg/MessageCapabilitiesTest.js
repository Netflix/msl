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
 * Message capabilities unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageCapabilities", function() {
    /** JSON key compression algorithms. */
    var KEY_COMPRESSION_ALGOS = "compressionalgos";
    
    // Shortcuts
    var CompressionAlgorithm = MslConstants$CompressionAlgorithm;
    
    var ALGOS = [ CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW ];
    var LANGUAGES = [ "en-US", "es" ];
    
    it("ctors", function() {
        var caps = new MessageCapabilities(ALGOS, LANGUAGES);
        expect(caps.compressionAlgorithms).toEqual(ALGOS);
        expect(caps.languages).toEqual(LANGUAGES);
        var jsonString = JSON.stringify(caps);
        expect(jsonString).not.toBeNull();
        
        var joCaps = MessageCapabilities$parse(JSON.parse(jsonString));
        expect(joCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
        expect(joCaps.languages).toEqual(caps.languages);
        var joJsonString = JSON.stringify(joCaps);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("ctors with null algorithms", function() {
        var caps = new MessageCapabilities(null, LANGUAGES);
        var algos = caps.compressionAlgorithms;
        expect(algos).not.toBeNull();
        expect(algos.length).toEqual(0);
        expect(caps.languages).toEqual(LANGUAGES);
        var jsonString = JSON.stringify(caps);
        expect(jsonString).not.toBeNull();
        
        var joCaps = MessageCapabilities$parse(JSON.parse(jsonString));
        expect(joCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
        expect(joCaps.languages).toEqual(caps.languages);
        var joJsonString = JSON.stringify(joCaps);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("unknown compression algorithm", function() {
        var caps = new MessageCapabilities(ALGOS, LANGUAGES);
        var jsonString = JSON.stringify(caps);
        var jo = JSON.parse(jsonString);
        
        var ja = jo[KEY_COMPRESSION_ALGOS];
        ja.push("CATZ");
        jo[KEY_COMPRESSION_ALGOS] = ja;
        
        var joCaps = MessageCapabilities$parse(jo);
        expect(joCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
    });
    
    it("ctors with null languages", function() {
        var caps = new MessageCapabilities(ALGOS, null);
        expect(caps.compressionAlgorithms).toEqual(ALGOS);
        var languages = caps.languages;
        expect(languages).not.toBeNull();
        expect(languages.length).toEqual(0);
        var jsonString = JSON.stringify(caps);
        expect(jsonString).not.toBeNull();
        
        var joCaps = MessageCapabilities$parse(JSON.parse(jsonString));
        expect(joCaps.compressionAlgorithms).toEqual(caps.compressionAlgorithms);
        expect(joCaps.languages).toEqual(caps.languages);
        var joJsonString = JSON.stringify(joCaps);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("equals compression algorithm", function() {
        var algosA = Arrays$copyOf(ALGOS);
        var algosB = [];
        
        var capsA = new MessageCapabilities(algosA, LANGUAGES);
        var capsB = new MessageCapabilities(algosB, LANGUAGES);
        var capsA2 = MessageCapabilities$parse(JSON.parse(JSON.stringify(capsA)));
        
        expect(capsA.equals(capsA)).toBeTruthy();
        expect(capsA.uniqueKey()).toEqual(capsA.uniqueKey());
        
        expect(capsA.equals(capsB)).toBeFalsy();
        expect(capsB.equals(capsA)).toBeFalsy();
        expect(capsA.uniqueKey()).not.toEqual(capsB.uniqueKey());
        
        expect(capsA.equals(capsA2)).toBeTruthy();
        expect(capsA2.equals(capsA)).toBeTruthy();
        expect(capsA2.uniqueKey()).toEqual(capsA.uniqueKey());
    });
    
    it("equals languages", function() {
        var langsA = [ "en-US" ];
        var langsB = [ "es" ];
        
        var capsA = new MessageCapabilities(ALGOS, langsA);
        var capsB = new MessageCapabilities(ALGOS, langsB);
        var capsA2 = MessageCapabilities$parse(JSON.parse(JSON.stringify(capsA)));
        
        expect(capsA.equals(capsA)).toBeTruthy();
        expect(capsA.uniqueKey()).toEqual(capsA.uniqueKey());
        
        expect(capsA.equals(capsB)).toBeFalsy();
        expect(capsB.equals(capsA)).toBeFalsy();
        expect(capsA.uniqueKey()).not.toEqual(capsB.uniqueKey());
        
        expect(capsA.equals(capsA2)).toBeTruthy();
        expect(capsA2.equals(capsA)).toBeTruthy();
        expect(capsA2.uniqueKey()).toEqual(capsA.uniqueKey());
    });

    it("intersection with self", function() {
        var capsA = new MessageCapabilities(ALGOS, LANGUAGES);
        var capsB = new MessageCapabilities(ALGOS, LANGUAGES);
        var intersection = MessageCapabilities$intersection(capsA, capsB);
        
        expect(intersection).toEqual(capsA);
        expect(intersection).toEqual(capsB);
    });
    
    if("intersection", function() {
        var gzipOnly = [ CompressionAlgorithm.GZIP ];
        var oneLanguage = [ LANGUAGES[0] ];
        
        var capsA = new MessageCapabilities(ALGOS, oneLanguage);
        var capsB = new MessageCapabilities(gzipOnly, LANGUAGES);
        var intersectionAB = MessageCapabilities$intersection(capsA, capsB);
        var intersectionBA = MessageCapabilities$intersection(capsB, capsA);
        
        expect(intersectionAB).toEqual(intersectionBA);
        expect(gzipOnly).toEqual(intersectionAB.compressionAlgorithms);
        expect(Arrays$containEachOther(oneLanguage, intersectionAB.languages));
    });
    
    it("intersection with null capabilities", function() {
        var caps = new MessageCapabilities(ALGOS, LANGUAGES);
        var intersectionA = MessageCapabilities$intersection(null, caps);
        var intersectionB = MessageCapabilities$intersection(caps, null);
        
        expect(intersectionA).toBeNull();
        expect(intersectionB).toBeNull();
    });
});

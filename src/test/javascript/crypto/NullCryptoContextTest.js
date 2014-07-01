/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
 * Null crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("NullCryptoContext", function() {
	var random = new Random();
	
	it("encrypt/decrypt", function() {
		var message = new Uint8Array(32);
		random.nextBytes(message);
		
		var cryptoContext = new NullCryptoContext();
		var ciphertext;
		runs(function() {
			cryptoContext.encrypt(message, {
				result: function(c) { ciphertext = c; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return ciphertext; }, "ciphertext not received", 100);
		
		runs(function() {
			expect(ciphertext).not.toBeNull();
			expect(ciphertext).toEqual(message);
		});
		
		var plaintext;
		runs(function() {
			cryptoContext.decrypt(ciphertext, {
				result: function(p) { plaintext = p; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return plaintext; }, "plaintext not received", 100);
		
		runs(function() {
			expect(plaintext).not.toBeNull();
			expect(plaintext).toEqual(message);
		});
	});
	
	it("sign/verify", function() {
		var messageA = new Uint8Array(32);
		random.nextBytes(messageA);
		
		var cryptoContext = new NullCryptoContext();
		var signatureA;
		runs(function() {
			cryptoContext.sign(messageA, {
				result: function(s) { signatureA = s; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return signatureA; }, "signature not received", 100);
		
		runs(function() {
			expect(signatureA).not.toBeNull();
			expect(signatureA.length).toEqual(0);
		});
		
		var verified;
		runs(function() {
			cryptoContext.verify(messageA, signatureA, {
				result: function(v) { verified = v; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return verified !== undefined; }, "verified not received", 100);
		
		runs(function() {
			expect(verified).toBeTruthy();
		});
		
		var messageB = new Uint8Array(32);
		random.nextBytes(messageB);
		
		var signatureB;
		runs(function() {
			cryptoContext.sign(messageB, {
				result: function(s) { signatureB = s; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return signatureB; }, "signature not received", 100);
	
		runs(function() {
			expect(signatureB).toEqual(signatureA);
		});
		
		var verifiedB = undefined, verifiedA;
		runs(function() {
			cryptoContext.verify(messageB, signatureB, {
				result: function(v) { verifiedB = v; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
			cryptoContext.verify(messageB, signatureA, {
				result: function(v) { verifiedA = v; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return verifiedB !== undefined && verifiedB !== undefined; }, "verified values not received", 100);
		
		runs(function() {
			expect(verifiedB).toBeTruthy();
			expect(verifiedA).toBeTruthy();
		});
	});
});
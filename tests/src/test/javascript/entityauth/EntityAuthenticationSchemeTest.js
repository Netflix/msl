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
describe("EntityAuthenticationScheme", function() {
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    
    it("names", function() {
        expect(EntityAuthenticationScheme.PSK.name).toEqual("PSK");
        expect(EntityAuthenticationScheme.X509.name).toEqual("X509");
        expect(EntityAuthenticationScheme.RSA.name).toEqual("RSA");
        expect(EntityAuthenticationScheme.NONE.name).toEqual("NONE");
        expect(EntityAuthenticationScheme.MIGRATION.name).toEqual("MIGRATION");
    });
    
	it("schemes that support encryption", function() {
		expect(EntityAuthenticationScheme.PSK.encrypts).toBeTruthy();
	});
	
	it("schemes that do not support encryption", function() {
		expect(EntityAuthenticationScheme.X509.encrypts).toBeFalsy();
		expect(EntityAuthenticationScheme.RSA.encrypts).toBeFalsy();
        expect(EntityAuthenticationScheme.NONE.encrypts).toBeFalsy();
        expect(EntityAuthenticationScheme.MIGRATION.encrypts).toBeFalsy();
	});
	
	it("schemes that support integrity protection", function() {
        expect(EntityAuthenticationScheme.PSK.protectsIntegrity).toBeTruthy();
        expect(EntityAuthenticationScheme.X509.protectsIntegrity).toBeTruthy();
        expect(EntityAuthenticationScheme.RSA.protectsIntegrity).toBeTruthy();
	});
	
	it("schemes that do not support integrity protection", function() {
        expect(EntityAuthenticationScheme.NONE.protectsIntegrity).toBeFalsy();
        expect(EntityAuthenticationScheme.MIGRATION.protectsIntegrity).toBeFalsy();
	});
});
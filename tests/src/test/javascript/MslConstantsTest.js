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
describe("MslConstants", function() {
    var MslConstants = require('msl-core/MslConstants.js');

    describe("MslConstants.DEFAULT_CHARSET", function() {
        it("encoding is UTF-8", function() {
            expect(MslConstants.DEFAULT_CHARSET).toEqual("utf-8");
        });
    });

    describe("MslConstants.ResponseCode", function() {
        it("fail equals 1", function() {
            expect(MslConstants.ResponseCode.FAIL).toEqual(1);
        });
        it("transient failure equals 2", function() {
            expect(MslConstants.ResponseCode.TRANSIENT_FAILURE).toEqual(2);
        });
        it("entity reauth equals 3", function() {
            expect(MslConstants.ResponseCode.ENTITY_REAUTH).toEqual(3);
        });
        it("user reauth equals 4", function() {
            expect(MslConstants.ResponseCode.USER_REAUTH).toEqual(4);
        });
        it("keyx required equals 5", function() {
            expect(MslConstants.ResponseCode.KEYX_REQUIRED).toEqual(5);
        });
        it("entity data reauth equals 6", function() {
            expect(MslConstants.ResponseCode.ENTITYDATA_REAUTH).toEqual(6);
        });
        it("user data reauth equals 7", function() {
            expect(MslConstants.ResponseCode.USERDATA_REAUTH).toEqual(7);
        });
        it("expired equals 8", function() {
            expect(MslConstants.ResponseCode.EXPIRED).toEqual(8);
        });
        it("replayed equals 9", function() {
            expect(MslConstants.ResponseCode.REPLAYED).toEqual(9);
        });
        it("sso token rejected equals 10", function() {
            expect(MslConstants.ResponseCode.SSOTOKEN_REJECTED).toEqual(10);
        });
    });
});
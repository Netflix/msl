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
describe("textEncoding", function () {
    var TextEncoding = require('msl-core/util/TextEncoding.js');
    var TextEncodingUtf8 = require('msl-core/util/TextEncodingUtf8.js');
    
    beforeEach(function() {
        TextEncoding.setImpl(new TextEncodingUtf8());
    });

    describe("TextEncoding.getString", function () {

        it("empty", function () {
            var arr = new Uint8Array([]);
            var str = "";

            expect(TextEncoding.getString(arr)).toEqual(str);
        });

        it("one latin byte", function () {
            var arr = new Uint8Array([65]);
            var str = "A";

            expect(TextEncoding.getString(arr)).toEqual(str);
        });

        it("latin", function () {
            var arr = new Uint8Array([104, 101, 108, 108, 111, 44, 32, 103, 114, 97, 110, 100, 109, 97]);
            var str = "hello, grandma";

            expect(TextEncoding.getString(arr)).toEqual(str);
        });

        it("cyrillic", function () {
            var arr = new Uint8Array([104, 101, 108, 108, 111, 44, 32, 208, 177, 208, 176, 208, 177, 209, 131, 209, 136, 208, 186, 208, 176]);
            var str = "hello, бабушка";

            expect(TextEncoding.getString(arr)).toEqual(str);
        });

        it("japanese", function () {
            var arr = new Uint8Array([104, 101, 108, 108, 111, 44, 32, 231, 165, 150, 230, 175, 141, 33]);
            var str = "hello, 祖母!";

            expect(TextEncoding.getString(arr)).toEqual(str);
        });

        it("japanese long", function () {
            var arr = new Uint8Array([
                230, 157, 165, 232, 166, 154, 232, 178, 183, 227, 131, 137, 229, 191, 156, 231, 167, 139, 227, 131,
                141, 227, 130, 164, 229, 183, 165, 229, 133, 137, 227, 129, 155, 227, 129, 167, 227, 129, 160, 229,
                130, 153, 230, 177, 159, 227, 131, 178, 227, 131, 134, 230, 188, 129, 233, 155, 132, 227, 129, 169,
                227, 131, 137, 227, 130, 137, 230, 138, 128, 229, 160, 128, 227, 129, 184, 227, 129, 134, 227, 129,
                170, 229, 168, 129, 53, 232, 173, 176, 227, 130, 179, 230, 142, 178, 229, 164, 169, 229, 188, 129,
                227, 129, 145, 227, 130, 139, 230, 187, 139, 53, 231, 156, 159, 227, 129, 169, 231, 164, 190, 229,
                137, 141, 229, 144, 140, 227, 130, 164, 227, 131, 149, 229, 156, 176
            ]);
            var str = "来覚買ド応秋ネイ工光せでだ備江ヲテ漁雄どドら技堀へうな威5議コ掲天弁ける滋5真ど社前同イフ地";

            expect(TextEncoding.getString(arr)).toEqual(str);
        });

    });

    describe("TextEncoding.getBytes", function () {

        it("empty", function () {
            var arr = new Uint8Array([]);
            var str = "";

            expect(TextEncoding.getBytes(str)).toEqual(arr);
        });

        it("one latin byte", function () {
            var arr = new Uint8Array([65]);
            var str = "A";

            expect(TextEncoding.getBytes(str)).toEqual(arr);
        });

        it("latin", function () {
            var arr = new Uint8Array([104, 101, 108, 108, 111, 44, 32, 103, 114, 97, 110, 100, 109, 97]);
            var str = "hello, grandma";

            expect(TextEncoding.getBytes(str)).toEqual(arr);
        });

        it("cyrillic", function () {
            var arr = new Uint8Array([104, 101, 108, 108, 111, 44, 32, 208, 177, 208, 176, 208, 177, 209, 131, 209, 136, 208, 186, 208, 176]);
            var str = "hello, бабушка";

            expect(TextEncoding.getBytes(str)).toEqual(arr);
        });

        it("japanese short", function () {
            var arr = new Uint8Array([104, 101, 108, 108, 111, 44, 32, 231, 165, 150, 230, 175, 141, 33]);
            var str = "hello, 祖母!";

            expect(TextEncoding.getBytes(str)).toEqual(arr);
        });

        it("japanese long", function () {
            var arr = new Uint8Array([
                230, 157, 165, 232, 166, 154, 232, 178, 183, 227, 131, 137, 229, 191, 156, 231, 167, 139, 227, 131,
                141, 227, 130, 164, 229, 183, 165, 229, 133, 137, 227, 129, 155, 227, 129, 167, 227, 129, 160, 229,
                130, 153, 230, 177, 159, 227, 131, 178, 227, 131, 134, 230, 188, 129, 233, 155, 132, 227, 129, 169,
                227, 131, 137, 227, 130, 137, 230, 138, 128, 229, 160, 128, 227, 129, 184, 227, 129, 134, 227, 129,
                170, 229, 168, 129, 53, 232, 173, 176, 227, 130, 179, 230, 142, 178, 229, 164, 169, 229, 188, 129,
                227, 129, 145, 227, 130, 139, 230, 187, 139, 53, 231, 156, 159, 227, 129, 169, 231, 164, 190, 229,
                137, 141, 229, 144, 140, 227, 130, 164, 227, 131, 149, 229, 156, 176
            ]);
            var str = "来覚買ド応秋ネイ工光せでだ備江ヲテ漁雄どドら技堀へうな威5議コ掲天弁ける滋5真ど社前同イフ地";

            expect(TextEncoding.getBytes(str)).toEqual(arr);
        });

    });

});
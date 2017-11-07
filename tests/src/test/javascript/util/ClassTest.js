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
describe("Class", function() {
    var Class = require('msl-core/util/Class.js');

    var Animal = Class.create({
        init: function(type, name) {
            var props = {
                classname: { value: "AnimalClass", writable: false, enumerable: false, configurable: true },
                type: { value: type, writable: false, enumerable: true, configurable: false },
                name: { value: name, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        toString: function() {
            return this.classname + ': [' + this.type + '] ' + this.getName() + ' runs by ' + this.run();
        },
        getName: function() {
            return this.name;
        },
        run: function() {
            return "";
        },
    });
    var Cat = Animal.extend({
        init: function init(name, color) {
            init.base.call(this, "Cat", name);
            var props = {
                classname: { value: "CatClass", writable: false, enumerable: false, configurable: true },
                color: { value: color, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        getName: function() {
            return this.name + ' (' + this.color + ')';
        },
        run: function() {
            return "pouncing";
        },
        pet: function() {
            return "purr";
        },
    });
    var Dog = Animal.extend({
        init: function init(name, breed) {
            init.base.call(this, "Dog", name);
            var props = {
                classname: { value: "DogClass", writable: false, enumerable: false, configurable: true },
                breed: { value: breed, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        getName: function() {
            return this.name + ' (' + this.breed + ')';
        },
        run: function() {
            return "dashing";
        },
    });

    it("dog", function() {
        var dog = new Dog("Fido", "Basset Hound");
        expect(dog.run()).toEqual("dashing");
        expect(dog.pet).toBeUndefined();
        expect(dog.toString()).toEqual("DogClass: [Dog] Fido (Basset Hound) runs by dashing");
        expect(dog instanceof Animal).toBeTruthy();
        expect(dog instanceof Cat).toBeFalsy();
        expect(dog instanceof Dog).toBeTruthy();
    });

    it("cat", function() {
        var cat = new Cat("Nya", "black");
        expect(cat.run()).toEqual("pouncing");
        expect(cat.pet()).toEqual("purr");
        expect(cat.toString()).toEqual("CatClass: [Cat] Nya (black) runs by pouncing");
        expect(cat instanceof Cat).toBeTruthy();
        expect(cat instanceof Dog).toBeFalsy();
        expect(cat instanceof Animal).toBeTruthy();
    });
});
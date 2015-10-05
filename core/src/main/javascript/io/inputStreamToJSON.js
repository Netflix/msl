/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
 *
 * Creates a JSON array from an InputStream as defined in the MSL code
 */
var inputStreamToJSON = function (is, timeout, cbObj) {
    simpleReadWithReset(is, timeout, function (err, data) {
        if (err) {
            cbObj.error(err);
        } else if (data) {
            if (is.getJSON !== undefined && typeof is.getJSON === "function") {
                cbObj.result(is.getJSON());
            } else {
                cbObj.result(parse(data));
            }
        } else {
            // we've reached the end of the stream
            cbObj.result(null);
        }
    });

    // reset not currently working as mark/reset is not currently working
    // so this function actually mutates the input stream unfortunately
    function simpleReadWithReset(is, timeout, next) {
        //is.mark();
        is.read(-1, timeout, {
            result: function (data) {
                //is.reset();

                // On end of stream return null for the parser.
                if (!data || !data.length) {
                    next(null, null);
                } else {
                    next(null, data);
                }
            },
            timeout: function () {
                cbObj.timeout();
            },
            error: function (e) {
                next(e, null);
            }
        });
    }

    // parse the raw data
    function parse(data) {
        var parser = new ClarinetParser(textEncoding$getString(data, "utf-8")),
            json = [],
            value;

        value = parser.nextValue();

        while(value !== undefined) {
            json.push(value);
            value = parser.nextValue();
        }

        return json;
    }
};

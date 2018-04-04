/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

var KeyFormat = require('msl-core/crypto/KeyFormat.js');
var MslConstants = require('msl-core/MslConstants.js');
var PublicKey = require('msl-core/crypto/PublicKey.js');
var TextEncoding = require('msl-core/util/TextEncoding.js');
var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');

var AdvancedRequest = require('./msg/AdvancedRequest.js');
var SimpleClient$create = require('./SimpleClient.js').create;
var SimpleConstants = require('./SimpleConstants.js');
var SimpleEchoRequest = require('./msg/SimpleEchoRequest.js');
var SimpleFilterStreamFactory = require('./msg/SimpleFilterStreamFactory.js');
var SimpleLogRequest = require('./msg/SimpleLogRequest.js');
var SimpleMessageDebugContext = require('./msg/SimpleMessageDebugContext.js');
var SimpleProfileRequest = require('./msg/SimpleProfileRequest.js');
var SimpleQueryRequest = require('./msg/SimpleQueryRequest.js');
var SimpleQuitRequest = require('./msg/SimpleQuitRequest.js');

function getQueryParam(key, defaultValue) {
    var queryString = window.location.search;
    var regex = new RegExp(key + '=([^&?]*)');
    var matches = queryString.match(regex);
    if (matches) return matches[1];
    return defaultValue;
}

function errorCallback(msgOrError) {
    var error = document.getElementById('error');
    var errortext = document.getElementById('errortext');

    var msg;
    if (typeof msgOrError === 'string') {
        console.log(msgOrError);
        msg = "<b>Error:</b> " + msgOrError;
    } else if (msgOrError instanceof Error) {
        console.log(msgOrError.stack);
        msg = "<b>Exception:</b><br/><textarea cols='108' rows='12' readonly='readonly'>" + msgOrError.stack + "</textarea>";
    } else {
        console.log(msgOrError);
        msg = "<b>Unknown error:</b> " + msgOrError;
    }
    errortext.innerHTML = msg;
    error.style.visibility = 'visible';
    error.style.position = 'relative';
}

var client;
var dbgCtx;
function main() {
    var exampleUrl = 'http://localhost:' + SimpleConstants.SERVER_PORT + '/msl-example-server/';
    var targetUrl = getQueryParam('url', exampleUrl);
    document.querySelector("#url").setAttribute("value", targetUrl);

    var entityIdentity = getQueryParam('identity', SimpleConstants.CLIENT_ID);
    document.querySelector("#identity").setAttribute("value", entityIdentity);

    SimpleConstants.EMAIL_PASSWORDS.forEach(function (emailPassword) {
        var email = emailPassword[0];
        var password = emailPassword[1];
        var admin = (email == SimpleConstants.ADMIN_USERNAME) ? "Y" : "-";

        var emailData = document.createElement("td");
        emailData.appendChild(document.createTextNode(email));

        var passwordData = document.createElement("td");
        passwordData.appendChild(document.createTextNode(password));

        var adminData = document.createElement("td");
        adminData.appendChild(document.createTextNode(admin));
        adminData.setAttribute("align", "center");

        var row = document.createElement("tr");
        row.appendChild(emailData);
        row.appendChild(passwordData);
        row.appendChild(adminData);
        document.querySelector("#users").appendChild(row);
    });

    SimpleConstants.QUERY_DATA.forEach(function (userWord) {
        var user = userWord[0];
        var word = userWord[1];
        var displayWord = word + ((user) ? " (" + user + ")" : "");
        var opt = document.createElement("option");
        var text = document.createTextNode(displayWord);
        opt.setAttribute("value", word);
        opt.appendChild(text);
        document.querySelector("#word").appendChild(opt);
    });

    // Enable selected tab.
    setRequestType('echo');

    // Grab sent and received text areas.
    var sentText = document.getElementById('sent');
    var receivedText = document.getElementById('received');

    // Create message debug context.
    dbgCtx = new SimpleMessageDebugContext(sentText, receivedText);

    // Create client.
    var identityField = document.getElementById('identity');
    var identity = identityField.value;
    var factory = new SimpleFilterStreamFactory(sentText, receivedText);
	SimpleClient$create(identity, factory, {
	    result: function(c) {
	        client = c;
	        ready();
	    },
	    error: errorCallback,
	});
}

function displayRsaKeyForm() {
    var keyform = document.getElementById('rsa-key-form');
    keyform.style.visibility = 'visible';
}

function addRsaKey() {
    var keyform = document.getElementById('rsa-key-form');

    // Grab key identity and data.
    var identity = document.getElementById('rsa-key-id').value;
    var keyB64 = document.getElementById('rsa-pubkey').value;

    // Remove whitespace from the key data.
    keyB64 = keyB64.replace(/\s+/g, '');

    // Import the public key.
    PublicKey.import(keyB64, WebCryptoAlgorithm.RSASSA_SHA256, WebCryptoUsage.VERIFY, KeyFormat.SPKI, {
        result: function (pubkey) {
            client.addRsaPublicKey(identity, pubkey);
            keyform.style.visibility = 'hidden';
        },
        error: function(msgOrErr) {
            errorCallback(msgOrErr);
            keyform.style.visibility = 'hidden';
        }
    });
}

function resetState() {
    client.reset();
    checkUsername();
    clearSentReceived();
}

function setIdentity() {
    var identityField = document.getElementById('identity');
    var identity = identityField.value;
    client.setIdentity(identity, errorCallback);
    checkUsername();
}

function checkUsername() {
    var usernameField = document.getElementById('username');
    var passwordField = document.getElementById('password');
    var logoutButton = document.getElementById('logout');

    // If the given user is logged in then clear and disable the password field, and enable the logout button.
    var username = usernameField.value;
    if (client.isLoggedIn(username)) {
        passwordField.value = '';
        passwordField.disabled = true;
        logoutButton.disabled = false;
    } else {
        passwordField.disabled = false;
        logoutButton.disabled = true;
    }
}

function logoutUser() {
    var usernameField = document.getElementById('username');
    var username = usernameField.value;
    client.logout(username);
    checkUsername();
}

function setRequestType(type) {
    var i;
    
    // Unselect the request tabs.
    var tabs = document.getElementsByClassName('tab');
    for (i = 0; i < tabs.length; ++i)
        tabs[i].className = "";

    // Select the request tab.
    var tab = document.getElementById(type);
    tab.className = "tab selected";

    // Disable all fields.
    var fieldElements = document.getElementsByClassName('field');
    for (i = 0; i < fieldElements.length; ++i) {
        var field = fieldElements[i];
        field.style.visibility = 'hidden';
        field.style.position = 'absolute';
    }

    // Enable the selected field.
    var enabledElements = document.getElementsByClassName(type);
    for (i = 0; i < enabledElements.length; ++i) {
        var enabled = enabledElements[i];
        enabled.style.position = 'relative';
        enabled.style.visibility = 'visible';
    }

    // Set the request type.
    var typeField = document.getElementById('type');
    typeField.value = type;
}

function ready() {
    var performButton = document.getElementById('perform');
    performButton.disabled = false;
}

function sendRequest() {
    // Grab the request data.
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    var type = document.getElementById('type').value;
    var text = document.getElementById('text').value;
    var severity = document.getElementById('severity').value;
    var word = document.getElementById('word').value;
    var url = document.getElementById('url').value;

    // Null username and password if empty.
    if (username.trim().length == 0) username = null;
    if (password.trim().length == 0) password = null;

    // Create the request.
    var request;
    switch (type) {
        case 'echo':
            request = new SimpleEchoRequest(text);
            break;
        case 'log':
            var timestamp = new Date().getTime();
            request = new SimpleLogRequest(timestamp, severity, text);
            break;
        case 'profile':
            request = new SimpleProfileRequest();
            break;
        case 'query':
            request = new SimpleQueryRequest(word);
            break;
        case 'quit':
            request = new SimpleQuitRequest();
            break;
        case 'advanced':
            var recipient = document.getElementById('recipient').value;
            if (!recipient || recipient.trim() == '') recipient = null;
            var isEncrypted = document.getElementById('encrypted').checked;
            var isIntegrityProtected = document.getElementById('integrity-protected').checked;
            var isNonReplayable = document.getElementById('non-replayable').checked;
            var isRequestingTokens = document.getElementById('requesting-tokens').checked;
            var data = TextEncoding.getBytes(document.getElementById('data').value);
            request = new AdvancedRequest(recipient, isEncrypted, isIntegrityProtected, isNonReplayable, isRequestingTokens, data);
            break;
        default:
            errorCallback("Request type [" + type + "] is not recognized.");
            return;
    }

    // Clear the response field.
    var responseText = document.getElementById('response');
    responseText.innerHTML = '';

    // Send the request.
    var performButton = document.getElementById('perform');
    var originalValue = performButton.value;
    var originalClick = performButton.onclick;
    client.send(url, username, password, request, dbgCtx, {
        result: function(channel) {
            performButton.value = originalValue;
            performButton.onclick = originalClick;

            // Check if cancelled or interrupted.
            if (!channel)
                return;

            // Handle errors.
            var mis = channel.input;
            var errorHeader = mis.getErrorHeader();
            if (errorHeader) {
                var errorMsg = errorHeader.errorCode + " (" + errorHeader.internalCode + "): " + errorHeader.errorMessage;
                if (errorHeader.userMessage)
                    errorMsg += "<br/>" + errorHeader.userMessage;
                errorCallback(errorMsg);
            } else {
                // Otherwise display the response.
                showResponse(mis);
    
                // Check the username in case we logged in.
                checkUsername();
            }
            
            // Close the channel.
            if (channel.input)
                channel.input.close(-1, {
                    result: function() {},
                    timeout: function() {},
                    error: function(e) {}
                });
            if (channel.output)
                channel.output.close(-1, {
                    result: function() {},
                    timeout: function() {},
                    error: function(e) {}
                });
        },
        error: function(e) {
            performButton.value = originalValue;
            performButton.onclick = originalClick;
            errorCallback(e);
        }
    });
    performButton.value = "Cancel";
    performButton.onclick = cancelRequest;
}

function cancelRequest() {
    client.cancel();
}

function clearSentReceived() {
    document.getElementById('sent').innerHTML = '';
    document.getElementById('received').innerHTML = '';
}

function showResponse(mis) {
    var responseText = document.getElementById('response');
    mis.read(-1, SimpleConstants.TIMEOUT_MS, {
        result: function(bytes) {
            // Stop on end-of-stream.
            if (!bytes)
                return;

            // Convert the bytes to text and update the response field.
            var s = TextEncoding.getString(bytes, MslConstants.DEFAULT_CHARSET);
            responseText.innerHTML += s;

            // Continue reading.
            showResponse(mis);
        },
        timeout: function(bytes) {
            // Convert the bytes to text and update the response field.
            var s = TextEncoding.getString(bytes, MslConstants.DEFAULT_CHARSET);
            responseText.innerHTML += s;

            // Notify of timeout.
            errorCallback("Timed out reading the response.");
        },
        error: errorCallback
    });
}

function createClickHandler(type) {
    return function () {
        setRequestType(type);
    };
}

function handleError() {
    var error = document.getElementById('error');
    error.style.visibility = 'hidden';
    error.style.position = 'absolute';
}

// set up event handlers
window.onload = main;
document.querySelector("#username").onchange = checkUsername;
document.querySelector("#identity").onchange = setIdentity;
document.querySelector("#echo").onclick = createClickHandler("echo");
document.querySelector("#log").onclick = createClickHandler("log");
document.querySelector("#profile").onclick = createClickHandler("profile");
document.querySelector("#query").onclick = createClickHandler("query");
document.querySelector("#quit").onclick = createClickHandler("quit");
document.querySelector("#advanced").onclick = createClickHandler("advanced");

document.querySelector("#errorinput").onclick = handleError;
document.querySelector("#import-rsa").onclick = displayRsaKeyForm;
document.querySelector("#rsa-input").onclick = addRsaKey;
document.querySelector("#reset").onclick = resetState;
document.querySelector("#logout").onclick = logoutUser;
document.querySelector("#perform").onclick = sendRequest;
document.querySelector("#clear").onclick = clearSentReceived;



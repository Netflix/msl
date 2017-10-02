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
(function(require, module) {
"use strict";

var Base64 = require('../util/Base64.js');
var KeyFormat = require('../crypto/KeyFormat.js');

/** @const */
var DEBUG=false;
//================================================================================
// util.js

/** @const */
//var DEBUG_BREAK_ON_ERROR = true;
var DEBUG_BREAK_ON_ERROR = false;

function debugLog(message) {
  console.log(message);
}

function debugAssert(b, message) {
  if (!b) {
    if (DEBUG_BREAK_ON_ERROR) {
      debugger;
    }
    //console.log(message || 'Assertion failed', { 'StackTrace': getStackTrace(my.debugAssert) });
    debugLog(message || 'Assertion failed');
  }
}

function hexDump(abv, idx, len) {
    var hexDigits = "0123456789ABCDEF";
    function hexByte(b) {
        return hexDigits.charAt((b >> 4) & 0xF) + hexDigits.charAt(b & 0xF);
    }
    var start = idx || 0;
    var end = len ? start + len : abv.length;
    var s = "";
    if (end > abv.length) return s;
    for (var i = start; i < end; ++i) {
        s += hexByte(abv[i]);
    }
    return s;
}

//================================================================================
// abvStream.js

/** @type {{Util:Object}} */

var AbvStream = (function () {
function My(input, position) {
    if (input instanceof AbvStream) {
        DEBUG && debugAssert(!position);
        this.abv = input.abv;
        this.position = input.position;
    } else {
        this.abv = input;
        this.position = position || 0;
    }
}

My.prototype = {
    readByte: function () {
        return this.abv[this.position++];
    },
    
    writeByte: function (byte) {
        DEBUG && debugAssert(this.getRemaining() >= 1);
        this.abv[this.position++] = byte;
    },
    
    peekByte: function (position) {
        DEBUG && debugAssert(position >= 0 && position <= this.abv.length);
        return this.abv[position];
    },
    
    copyBytes: function(srcAbv, srcOffset, nBytes) {
        DEBUG && debugAssert(this.getRemaining() >= nBytes);
        var dstU8 = new Uint8Array(this.abv.buffer, this.position, nBytes);
        var srcU8 = new Uint8Array(srcAbv.buffer, srcOffset, nBytes);
        dstU8.set(srcU8);
        this.position += nBytes;
    },
    
    seek: function (position) {
        DEBUG && debugAssert(position >= 0 && position <= this.abv.length);
        this.position = position;
    },

    skip: function (bytesToSkip) {
        DEBUG && debugAssert(bytesToSkip <= this.getRemaining());
        this.position += bytesToSkip;
    },

    getPosition: function () {
        return this.position;
    },
    
    setPosition: function (position) {
        DEBUG && debugAssert(position <= this.abv.length);
        this.position = position;
    },

    getRemaining: function () {
        return this.abv.length - this.position;
    },

    getLength: function () {
        return this.abv.length;
    },

    isEndOfStream: function () {
        return this.position >= this.abv.length;
    },
    
    show: function () {
        var output = "AbvStream: pos ";
        output += this.getPosition().toString() + " of " + this.getLength().toString();
        return output;
    }
};

return My;
}());
//================================================================================
// asn1.js

/** @enum {number} */
var tagClass = {
        UNIVERSAL: 0,
        APPLICATION: 1,
        CONTEXT_SPECIFIC: 2,
        PRIVATE: 3,
    };

/** @enum {number} */
var tagVal = {
        BER: 0,
        BOOLEAN: 1,
        INTEGER: 2,
        BIT_STRING: 3,
        OCTET_STRING: 4,
        NULL: 5,
        OBJECT_IDENTIFIER: 6,
        OBJECT_DESCRIPTOR: 7,
        INSTANCE_OF_EXTERNAL: 8,
        REAL: 9,
        ENUMERATED: 10,
        EMBEDDED_PPV: 11,
        UTF8_STRING: 12,
        RELATIVE_OID: 13,
        // 14 & 15 undefined
        SEQUENCE: 16,
        SET: 17,
        NUMERIC_STRING: 18,
        PRINTABLE_STRING: 19,
        TELETEX_STRING: 20,
        T61_STRING: 20,
        VIDEOTEX_STRING: 21,
        IA5_STRING: 22,
        UTC_TIME: 23,
        GENERALIZED_TIME: 24,
        GRAPHIC_STRING: 25,
        VISIBLE_STRING: 26,
        ISO64_STRING: 26,
        GENERAL_STRING: 27,
        UNIVERSAL_STRING: 28,
        CHARACTER_STRING: 29,
        BMP_STRING: 30
    };

/** @const */
var tagText = [];
tagText[tagVal.BER                 ] = 'BER';
tagText[tagVal.BOOLEAN             ] = 'BOOLEAN';
tagText[tagVal.INTEGER             ] = 'INTEGER';
tagText[tagVal.BIT_STRING          ] = 'BIT STRING';
tagText[tagVal.OCTET_STRING        ] = 'OCTET STRING';
tagText[tagVal.NULL                ] = 'NULL';
tagText[tagVal.OBJECT_IDENTIFIER   ] = 'OBJECT IDENTIFIER';
tagText[tagVal.OBJECT_DESCRIPTOR   ] = 'ObjectDescriptor';
tagText[tagVal.INSTANCE_OF_EXTERNAL] = 'INSTANCE OF, EXTERNAL';
tagText[tagVal.REAL                ] = 'REAL';
tagText[tagVal.ENUMERATED          ] = 'ENUMERATED';
tagText[tagVal.EMBEDDED_PPV        ] = 'EMBEDDED PPV';
tagText[tagVal.UTF8_STRING         ] = 'UTF8String';
tagText[tagVal.RELATIVE_OID        ] = 'RELATIVE-OID';
tagText[tagVal.SEQUENCE            ] = 'SEQUENCE';
tagText[tagVal.SET                 ] = 'SET, SET OF';
tagText[tagVal.NUMERIC_STRING      ] = 'NumericString';
tagText[tagVal.PRINTABLE_STRING    ] = 'PrintableString';
tagText[tagVal.TELETEX_STRING      ] = 'TeletexString, T61String';
tagText[tagVal.VIDEOTEX_STRING     ] = 'VideotexString';
tagText[tagVal.IA5_STRING          ] = 'IA5String';
tagText[tagVal.UTC_TIME            ] = 'UTCTime';
tagText[tagVal.GENERALIZED_TIME    ] = 'GeneralizedTime';
tagText[tagVal.GRAPHIC_STRING      ] = 'GraphicString';
tagText[tagVal.VISIBLE_STRING      ] = 'VisibleString, ISO64String';
tagText[tagVal.GENERAL_STRING      ] = 'GeneralString';
tagText[tagVal.UNIVERSAL_STRING    ] = 'UniversalString';
tagText[tagVal.CHARACTER_STRING    ] = 'CHARACTER STRING';
tagText[tagVal.BMP_STRING          ] = 'BMPString';

/**
 * Asn1Token
 * @param {ArrayBufferView=} abv The backing store.
 * @param {Object=} parent The parent token (optional).
 * @param {boolean=} constr bit 6 of the identifier byte (optional).
 * @param {?number=} tag bits 1-5 of the identifier byte (optional).
 * @param {?number=} didx index of the token's data in the source Uint8Array (optional).
 * @param {?number=} dlen length the data in bytes (optional).
 * @constructor
 */
var Asn1Token = function(abv, parent, constr, tag, didx, dlen) {
    this._data = abv;                    // the backing data store
    this._parent = parent || undefined;  // the parent token
    this._constructed = constr || false; // bit 6 of the identifier byte
    this._tagClass = tagClass.UNIVERSAL; // bits 7-8 of the identifier byte                    
    this._tag = tag || 0;                // bits 1-5 of the identifier byte                    
    this._dataIdx = didx || 0;           // index of the token's data in the source Uint8Array 
    this._dataLen = dlen || 0;           // length the data in bytes
};
Asn1Token.prototype = {
    _child: undefined,    // the first child of the current token, if present   
    _next: undefined,     // the next sibling of the current token, if present  

    get data() {
        DEBUG && debugAssert(this._data);
        return new Uint8Array(
            this._data.buffer.slice(this._dataIdx, this._dataIdx + this._dataLen)
        );
    },
    
    get backingStore() {return this._data;},
    
    get constructed() {return this._constructed;},
    set constructed(c) {this._constructed =  c !=0 ? true : false;},
    
    get tagClass() {return this._tagClass;},
    set tagClass(c) {this._tagClass = c;},
    
    get tag() {return this._tag;},
    set tag(c) {this._tag = c;},
    
    get dataIdx() {return this._dataIdx;},
    set dataIdx(c) {this._dataIdx = c;},
    
    get dataLen() {return this._dataLen;},
    set dataLen(c) {this._dataLen = c;},
    
    get child() {return this._child;},
    set child(c) {
        this._child = c;
        this._child.parent = this;
    },
    
    get next() {return this._next;},
    set next(c) {this._next = c;},
    
    get parent() {return this._parent;},
    set parent(c) {this._parent = c;},
    
    // Returns the payload size of the eventual encoding of this asn1token.
    get payloadLen() {
        var payloadLen = 0;
        if (this._child) {
            var child = this._child;
            while (child) {
                payloadLen += child.length;
                child = child.next;
            }
            // Special handling for bit string. In X.509 they always have a zero
            // padding byte prepended.
            if (this._tag == tagVal.BIT_STRING) {
                payloadLen++;
            }
        } else {  // no children
            switch (this._tag) {
                case tagVal.INTEGER:  {
                    // NOTE: NOT handling negative integers or non-byte multiple
                    payloadLen = this._dataLen;
                    // If the MSBit of the fitst byte is set, an extra zero byte
                    // will be prepended to the data.
                    if (this._data[this._dataIdx] >> 7)
                        payloadLen++;
                    break;
                }
                case tagVal.BIT_STRING:  {
                    // For X.509 bit strings are always a byte-multiple, and
                    // always have a zero padding byte prepended.
                    payloadLen = this._dataLen + 1;
                    break;
                }
                case tagVal.OCTET_STRING:  {
                    payloadLen = this._dataLen;
                    break;
                }
                case tagVal.NULL:  {
                    payloadLen = 0;
                    break;
                }
                case tagVal.OBJECT_IDENTIFIER:  {
                    // Only handling RSA Encryption OID.
                    if (oidIsRsaEncryption(this._data, this._dataIdx, this._dataLen)) {
                        payloadLen = 9;
                    } else {
                        DEBUG && debugAssert("Non RSA OID found");
                    }
                    break;
                }
                case tagVal.SET:
                case tagVal.SEQUENCE: {
                    DEBUG && debugAssert(false, "found constructed type " + tagText[this._tag] + " with no children");
                    break;
                }
                default: {
                    DEBUG && debugAssert(false, "unhandled type " + tagText[this._tag]);
                    break;
                }
            }
        }
        return payloadLen;
    },
    
    // Returns the total size of the eventual encoding of this asn1token.
    get length() {
        return derLength(this.payloadLen);
    },
    
    // Returns a Uint8Array representing the DER encoding of this asn1token.
    get der() {
        var encodingLength = this.length;
        if (!encodingLength) {
            DEBUG && debugLog("der: found zero length");
            return undefined;
        }
        var output = new Uint8Array(encodingLength);
        DEBUG && debugLog("created abv of length " + encodingLength);
        var stream = new AbvStream(output);
        if (!buildDer(this, stream)) {
            DEBUG && debugLog("der: buildDer failed");
            return undefined;
        }
        return output;
    },
    
    get nChildren() {
        var nChildren = 0;
        var token = this._child;
        while (token) {
            nChildren++;
            token = token.next;
        }
        return nChildren;
    }
    
};

// Returns the size of the eventual encoding of an Asn1Token with the given
// payload length. The returned size counts the header byte, length bytes,
// and payload.
function derLength(payloadLength) {
    var x;
    if (payloadLength > 127) {
        x = payloadLength;
        while (x) {
            x >>= 8;
            ++payloadLength;
        }
    }
    return payloadLength + 2;
}

// Writes an ASN.1 header byte and encoded length to a stream
function writeDerHeaderAndLength(asn1node, stream) {
    var tagByte = (asn1node.tagClass << 6) | (asn1node.constructed << 5) | asn1node.tag;
    stream.writeByte(tagByte);
    var payloadLen = asn1node.payloadLen;
    if (payloadLen < 128) {
        stream.writeByte(payloadLen);
    } else {
        // find length of length and write it
        var x = payloadLen;
        var nBytesInLen = 0;
        while (x) {
            ++nBytesInLen;
            x >>= 8;
        }
        stream.writeByte(0x80 | nBytesInLen);
        // write the multi-byte length
        for (var i=0; i < nBytesInLen; ++i) {
            var byteShift = nBytesInLen-i-1;
            stream.writeByte((payloadLen >> (byteShift * 8)) & 0xff);
        }
    }
}

// Builds a DER encoding of an Asn1Token, writing the bytes to the current
// position of the input stream.
function buildDer(node, stream) {
    writeDerHeaderAndLength(node, stream);
    if (node.child) {
        // Special handling for bit string, prepend a zero byte.
        if (node.tag == tagVal.BIT_STRING) {
            stream.writeByte(0);
        }
        var child = node._child;
        while (child) {
            if (!buildDer(child, stream)) {
                return false;
            }
            child = child.next;
        }
    }
    else {  // primitive node
        switch (node.tag) {
            case tagVal.INTEGER:  {
                // If the MSBit of the fitst byte is set, an extra zero byte
                // will be prepended to the data.
                if (node.backingStore[node.dataIdx] >> 7) {
                    stream.writeByte(0);
                }
                stream.copyBytes(node.backingStore, node.dataIdx, node.dataLen);
                break;
            }
            case tagVal.BIT_STRING:  {
                // For X.509 bit strings are always a byte-multiple, and
                // always have a zero padding byte prepended.
                stream.writeByte(0);
                stream.copyBytes(node.backingStore, node.dataIdx, node.dataLen);
                break;
            }
            case tagVal.OCTET_STRING:  {
                stream.copyBytes(node.backingStore, node.dataIdx, node.dataLen);
                break;
            }
            case tagVal.NULL:  {
                break;
            }
            case tagVal.OBJECT_IDENTIFIER:  {
                // We only handle RSA Encryption OID.
                DEBUG && debugAssert(oidIsRsaEncryption(node.backingStore, node.dataIdx, node.dataLen));
                stream.copyBytes(node.backingStore, node.dataIdx, node.dataLen);
                break;
            }
            case tagVal.SET:
            case tagVal.SEQUENCE: {
                DEBUG && debugAssert(false, "found constructed type " + tagText[node.tag] + " with no children");
                break;
            }
            default: {
                DEBUG && debugAssert(false, "unhandled type " + tagText[node.tag]);
                break;
            }
        }
    }
    return true;
}


//  var Asn1Token = function(abv, parent, constr, tag, didx, dlen)

var NodeFactory = {
    createSequenceNode: function() {
        return new Asn1Token(null, null, true, tagVal.SEQUENCE, null, null);
    },
    createOidNode: function(data) {
        return new Asn1Token(data, null, false, tagVal.OBJECT_IDENTIFIER, 0, data ? data.length : 0);
    },
    createNullNode: function() {
        return new Asn1Token(null, null, false, tagVal.NULL, null, null);
    },
    createBitStringNode: function(data) {
        return new Asn1Token(data, null, false, tagVal.BIT_STRING, 0, data ? data.length : 0);
        // might need to set constructed later
    },
    createIntegerNode: function(data) {
        return new Asn1Token(data, null, false, tagVal.INTEGER, 0, data ? data.length : 0);
    },
    createOctetStringNode: function(data) {
        return new Asn1Token(data, null, false, tagVal.OCTET_STRING, 0, data ? data.length : 0);
    }
};

/**
 * Builder
 * @param {Object} rootNode The root node.
 * @constructor
 */
var Builder = function(rootNode) {
    this._rootNode = rootNode;
    this._currentNode = rootNode;
};
Builder.prototype = {
    addChild: function(childNode) {
        this.addTo(this._currentNode, childNode);
    },
    addSibling: function(siblingNode) {
        this.addTo(this._currentNode.parent, siblingNode);
    },
    addTo: function(parentNode, childNode) {
        this._currentNode = childNode;
        this._currentNode.parent = parentNode;
        if (!parentNode.child) {
            parentNode.child = childNode;
        }
        else {
            var node = parentNode.child;
            while (node.next) {
                node = node.next;
            }
            node.next = childNode;
        }
    },
    addToParent: function(parentNode, childNode) {
        if (this.findNode(parentNode)) {
            this.addTo(parentNode, childNode);
        }
    },
    findNode: function(node) {
        var parentNode = this._currentNode;
        while (parentNode) {
            if (node == parentNode) {
                return true;
            }
            parentNode = parentNode.parent;
        }
        return false;
    }
};

function decodeTagByte(stream) {
    var tag = stream.readByte();
    if ((tag & 0x1F) == 0x1F) {
        var newTag = 0;
        while (tag & 0x80) {
            newTag <<= 8;
            newTag |= tag & 0x7F;
        }
        tag = newTag;
    }
    return tag;
}

function decodeLength(stream) {
    var buf = stream.readByte(),
        len = buf & 0x7F;
    if (len == buf)
        return len;
    // Refuse encoded lengths > 3 bytes and ensure encoded length is nonzero.
    if ( (len > 3) || (len === 0) ) {
        return -1;
    }
    buf = 0;
    for (var i = 0; i < len; ++i)
        buf = (buf << 8) | stream.readByte();
    return buf;
}

function hasContent(stream, tag, len) {
    if (tag & 0x20)
        return true; // constructed
    if ((tag < tagVal.BIT_STRING) || (tag > tagVal.OCTET_STRING))
        return false;
    var s = new AbvStream(stream);
    if (tag == tagVal.BIT_STRING)
        s.skip(1); // BitString unused bits, must be in [0, 7]
    var subTag = s.readByte();
    if ((subTag >> 6) & 0x01)
        return false; // not (universal or context)
    var subLength = decodeLength(s);
    var isContent = ((s.getPosition() - stream.getPosition()) + subLength == len);
    return isContent;
}

var asn1ParseRecursionDepth = 0,
    asn1ParseMaxRecursionDepth = 8;

function asn1Parse(rootToken, start, len) {
    var abv = rootToken.backingStore,
        stream = new AbvStream(abv, start),
        tokenEndIdx = start + len,
        token = rootToken,
        tagByte,
        tokenTag,
        tokenLength,
        tokenStartIdx,
        subIdx,
        subLength,
        curIdx;
    
    if (asn1ParseRecursionDepth++ > asn1ParseMaxRecursionDepth) {
        DEBUG && debugLog("asn1Parse max recursion depth exceeded");
        return undefined;
    }
    
    DEBUG && debugLog("==================== asn1Parse ENTER ====================");
    DEBUG && debugLog(stream.show() + ", len = " + len);
    
    while (stream.getPosition() < tokenEndIdx) {
        
        DEBUG && debugAssert(!stream.isEndOfStream());
        
        DEBUG && debugLog("---- token ----");
        DEBUG && debugLog(stream.show());
        
        tokenStartIdx = stream.getPosition();

        // The first byte of the token is the tagByte.
        tagByte = decodeTagByte(stream);
        tokenTag = tagByte & 0x1F;
        if (tokenTag < 0 || tokenTag > 30) {
            DEBUG && debugLog("Invalid tag found at position " + (stream.getPosition() - 1));
            return undefined;
        }
        
        // The next few bytes are the data length (vle).
        tokenLength = decodeLength(stream);
        if ( (tokenLength < 0) || (tokenLength > stream.getRemaining()) ) {
            DEBUG && debugLog("Invalid length found at position " + (stream.getPosition() - 1));
            return undefined;
        }
        
        // The remaining bytes are the payload. We have enough info now to fill
        // in the token object.
        token.constructed = tagByte & 0x20;
        token.tagClass = (tagByte & 0xC0) >> 6;
        token.tag = tokenTag;
        token.dataLen = tokenLength;
        token.dataIdx = stream.getPosition();
        DEBUG && debugLog(tagText[token.tag] + " (" + token.dataIdx + "," + token.dataLen + ")");
        
        // If the current token has content, its data is another ASN.1 object.
        if (hasContent(stream, tagByte, tokenLength)) {
            
            DEBUG && debugLog("(has content)");
            
            // Move the token data pointer back and adjust the token length to,
            // include the entire item, since we've already advanced into it.
            //token.dataIdx = tokenStartIdx;
            //token.dataLen = tokenLength + (stream['getPosition']() - tokenStartIdx);
            
            // Prepare to parse the first subtoken.
            subIdx = stream.getPosition();
            subLength = tokenLength;
            
            // Special case for bit string: The first byte of a bit string is
            // the number of unused (padding) bits at the end. For X.509 this is
            // always zero, so just ignore it. To do this, we need to adjust
            // index and length of the current token, and since we are about to
            // recurse into it, the first subtoken to be parsed as well.
            if (token.tag == tagVal.BIT_STRING) {
                token.dataIdx++;
                token.dataLen--;
                subIdx++;
                subLength--;
            }
            
            // Append a new child to the current token and recurse.
            token.child = new Asn1Token(abv, token);
            asn1Parse(token.child, subIdx, subLength);
        }
        
        // Special handling for INTEGER token.
        if (token.tag == tagVal.INTEGER) {
            // In DER integer encoding, if the high-order bit of the actual
            // content is set, a leading 0x00 is added to the content to
            // indicate that the number is not negative. X.509 does not use
            // negative numbers, so we just need to exclude this byte from the
            // current token's data.
            curIdx = stream.getPosition();
            if (stream.peekByte(curIdx) == 0 && stream.peekByte(curIdx + 1) >> 7) {
                token.dataIdx++;
                token.dataLen--;
            }
        }

        // Move forward to the start of the next token.
        stream.skip(tokenLength);

        DEBUG && debugLog("tokenLength = " + (stream.getPosition() - tokenStartIdx));

        if (stream.getPosition() < tokenEndIdx) {
            token.next = new Asn1Token(abv, token.parent);
            token = token.next;
        }
    }
    
    asn1ParseRecursionDepth--;
    DEBUG && debugLog("==================== asn1Parse EXIT  ====================");
    return rootToken;
}

var rsaEncryptionOid = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);

function oidIsRsaEncryption(abv, idx, len) {
    if (len != 9)
        return false;
    var i = idx;
    for (var j = 0; j < 9; ++j) {
        if (abv[i++] != rsaEncryptionOid[j]) {
            return false;
        }
    }
    return true;
}

function asn1Show(rootToken, rootDepth) {
    if (!DEBUG) {
      return;
    }

    var i;
    var token = rootToken;
    var abv = rootToken.backingStore;
    var output = "";
    var depth = rootDepth || 0;

    while (token) {
        for (i = 0; i < depth; i++) {
            output += "  ";
        }

        switch (token.tagClass) {
        case tagClass.UNIVERSAL:
            output += tagText[token.tag];
            break;
        case tagClass.APPLICATION:
            output +=  "application";
            break;
        case tagClass.CONTEXT_SPECIFIC:
            output += "context";
            break;
        case tagClass.PRIVATE:
            output += "private";
            break;
        }

        output += " (" + token.dataIdx + ":" + token.dataLen + ") ";
        
        if (token.tagClass == tagClass.UNIVERSAL) {
            switch (token.tag) {
                case tagVal.BIT_STRING:
                case tagVal.OCTET_STRING:
                    break;
                case tagVal.INTEGER:
                    output += "(" + token.dataLen * 8 + " bit) ";
                    /* falls through */
                case tagVal.UTF8_STRING:
                    output += hexDump(abv, token.dataIdx, token.dataLen);
                    /* falls through */
                case tagVal.OBJECT_IDENTIFIER:
                    if (oidIsRsaEncryption(abv, token.dataIdx, token.dataLen)) {
                        output += " (rsaEncryption)";
                    }
                    break;
                case tagVal.NUMERIC_STRING:
                case tagVal.PRINTABLE_STRING:
                case tagVal.TELETEX_STRING:
                case tagVal.VIDEOTEX_STRING:
                case tagVal.IA5_STRING:
                case tagVal.UTC_TIME:
                case tagVal.GENERALIZED_TIME:
                case tagVal.GRAPHIC_STRING:
                case tagVal.VISIBLE_STRING:
                case tagVal.GENERAL_STRING:
                case tagVal.UNIVERSAL_STRING:
                case tagVal.CHARACTER_STRING:
                case tagVal.BMP_STRING:
                    /* falls through */
                default:
                    break;
            }
        }
        
        output += " payloadLen = " + token.length;

        output += "\n";

        if (token.child) {
            output += asn1Show(token.child, depth + 1);
        }

        token = token.next;
    }
    
    return output;
}

function isRsaSpki(asn1token) {
    if (!asn1token ||
        !asn1token.child ||
        !asn1token.child.next ||
        !asn1token.child.child ||
        !asn1token.child.next.child) {
        return false;
        }
    var oid = asn1token.child.child;
    if (!oidIsRsaEncryption(oid.backingStore, oid.dataIdx, oid.dataLen)) {
        return false;
    }
    if (asn1token.nChildren != 2 ||
        asn1token.child.nChildren != 2 ||
        asn1token.child.next.child.nChildren != 2) {
        return false;
    }
    return true;
}

function isRsaPkcs8(asn1token) {
    if (!asn1token ||
        !asn1token.child ||
        !asn1token.child.next ||
        !asn1token.child.next.child ||
        !asn1token.child.next.next ||
        !asn1token.child.next.next.child) {
        return false;
    }
    var oid = asn1token.child.next.child;
    if (!oidIsRsaEncryption(oid.backingStore, oid.dataIdx, oid.dataLen)) {
        return false;
    }
    if (asn1token.nChildren != 3 ||
        asn1token.child.next.nChildren != 2 ||
        asn1token.child.next.next.child.nChildren != 9) {
        return false;
    }
    return true;
}

/**
 * RsaPublicKey
 * @param {Object} n
 * @param {Object} e
 * @param {Object} ext
 * @param {Object} keyOps
 * @constructor
 */
var RsaPublicKey = function(n, e, ext, keyOps) {
    this.n = n;
    this.e = e;
    this.ext = ext;
    this.keyOps = keyOps;
};

/**
 * RsaPrivateKey
 * @param {Object} n
 * @param {Object} e
 * @param {Object} d
 * @param {Object} p
 * @param {Object} q
 * @param {Object} dp
 * @param {Object} dq
 * @param {Object} qi
 * @param {Object=} alg
 * @param {Object=} ext
 * @param {Object=} keyOps
 * @constructor
 */
var RsaPrivateKey = function(n, e, d, p, q, dp, dq, qi, alg, keyOps, ext) {
    this.n = n;
    this.e = e;
    this.d = d;
    this.p = p;
    this.q = q;
    this.dp = dp;
    this.dq = dq;
    this.qi = qi;
    this.alg = alg;
    this.keyOps = keyOps;
    this.ext = ext;
};

function buildRsaSpki(rsaPublicKey) {
    var rootNode = NodeFactory.createSequenceNode();
    var builder = new Builder(rootNode);
      builder.addChild(NodeFactory.createSequenceNode());
        builder.addChild(NodeFactory.createOidNode(rsaEncryptionOid));
        builder.addSibling(NodeFactory.createNullNode());
      builder.addToParent(rootNode, NodeFactory.createBitStringNode(null));
        builder.addChild(NodeFactory.createSequenceNode());
          builder.addChild(NodeFactory.createIntegerNode(rsaPublicKey.n));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPublicKey.e));
    return rootNode;
}

function parseRsaSpki(spkiDer) {
    var spkiAsn = parse(spkiDer);
    if (!isRsaSpki) {
        return undefined;
    }
    return extractRsaSpkiParams(spkiAsn);
}

function extractRsaSpkiParams(spkiAsn) {
    var parm = spkiAsn.child.next.child.child;
    var n = parm.data;
    parm = parm.next;
    var e = parm.data;
    return new RsaPublicKey(n, e, null, null);
}

function buildRsaPkcs8(rsaPrivateKey) {
    var rootNode = NodeFactory.createSequenceNode();
    var builder = new Builder(rootNode);
      builder.addChild(NodeFactory.createIntegerNode(new Uint8Array([0])));
      builder.addSibling(NodeFactory.createSequenceNode());
        builder.addChild(NodeFactory.createOidNode(rsaEncryptionOid));
        builder.addSibling(NodeFactory.createNullNode());
      builder.addToParent(rootNode, NodeFactory.createOctetStringNode(null));
        builder.addChild(NodeFactory.createSequenceNode());
          builder.addChild(NodeFactory.createIntegerNode(new Uint8Array([0])));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.n));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.e));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.d));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.p));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.q));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.dp));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.dq));
          builder.addSibling(NodeFactory.createIntegerNode(rsaPrivateKey.qi));
    return rootNode;
}

function parseRsaPkcs8(pkcs8Der) {
    var pkcs8Asn1 = parse(pkcs8Der);
    if (!isRsaPkcs8(pkcs8Asn1)) {
        return undefined;
    }
    return extractRsaPkcs8Params(pkcs8Asn1);
}

function extractRsaPkcs8Params(pkcs8Asn1) {
    var parmData = [];
    var parm = pkcs8Asn1.child.next.next.child.child.next;
    for (var i = 0; i < 8; i++) {
        parmData.push(parm.data);
        parm = parm.next;
    }
    return new RsaPrivateKey(
        parmData[0],
        parmData[1],
        parmData[2],
        parmData[3],
        parmData[4],
        parmData[5],
        parmData[6],
        parmData[7]
    );
}

var jwkKeyOps = ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'];

function buildRsaJwk(rsaKey, alg, keyOps, ext) {
    if (!(rsaKey instanceof RsaPublicKey) && !(rsaKey instanceof RsaPrivateKey) ) {
        return undefined;
    }
    if (keyOps) {
        for (var i = 0; i < keyOps.length; ++i) {
            if (jwkKeyOps.indexOf(keyOps[i]) == -1) {
                return undefined;
            }
        }
    }
    var jwk = {
        'kty': 'RSA',
        'alg': alg,
        'key_ops' : keyOps || [],
        'ext': ext == undefined ? false : ext,
        'n': Base64.encode(rsaKey.n, true),
        'e': Base64.encode(rsaKey.e, true)
    };
    if (rsaKey instanceof RsaPrivateKey) {
        jwk['d']  = Base64.encode(rsaKey.d, true);
        jwk['p']  = Base64.encode(rsaKey.p, true);
        jwk['q']  = Base64.encode(rsaKey.q, true);
        jwk['dp'] = Base64.encode(rsaKey.dp, true);
        jwk['dq'] = Base64.encode(rsaKey.dq, true);
        jwk['qi'] = Base64.encode(rsaKey.qi, true);
    }
    return jwk;
}

function parseRsaJwk(jwk) {
    if (!jwk['kty'] || jwk['kty'] != 'RSA' || !jwk['n'] || !jwk['e']) {
        return undefined;
    }
    var allowedAlg = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RS256', 'RS384', 'RS512'];
    if (jwk['alg']) {
        if (allowedAlg.indexOf(jwk['alg']) == -1) {
            return undefined;
        }
    }
    var keyOps = [];
    if (jwk['use']) {
        if (jwk['use'] == 'enc') {
            keyOps = ['encrypt', 'decrypt', 'wrap', 'unwrap'];
        } else if (jwk['use'] == 'sig') {
            keyOps = ['sign', 'verify'];
        }
    } else {
        keyOps = jwk['key_ops'];
    }
    var ext = jwk['ext'];
    var n = Base64.decode(jwk['n'], true);
    var e = Base64.decode(jwk['e'], true);
    if (!jwk['d']) {
        return new RsaPublicKey(n, e, ext, keyOps);
    } else {
        var d = Base64.decode(jwk['d'], true);
        var p = Base64.decode(jwk['p'], true);
        var q = Base64.decode(jwk['q'], true);
        var dp = Base64.decode(jwk['dp'], true);
        var dq = Base64.decode(jwk['dq'], true);
        var qi = Base64.decode(jwk['qi'], true);
        return new RsaPrivateKey(n, e, d, p, q, dp, dq, qi, jwk['alg'], keyOps, ext);
    }
}

function rsaDerToJwk(der, alg, keyOps, extractable) {
    var asn = parse(der);
    if (!asn) {
        return undefined;
    }
    var rsaKey;
    if (isRsaSpki(asn)) {
        rsaKey = extractRsaSpkiParams(asn);
    } else if (isRsaPkcs8(asn)) {
        rsaKey = extractRsaPkcs8Params(asn);
    } else {
        return undefined;
    }
    return buildRsaJwk(rsaKey, alg, keyOps, extractable);
}

/**
 * RsaDer
 * @param {Object} der
 * @param {string} type
 * @param {Object=} keyOps
 * @param {Object=} extractable
 * @constructor
 */
function RsaDer(der, type, keyOps, extractable) {
    this.der = der;
    this.type = type;
    this.keyOps = keyOps;
    this.extractable = extractable;
}
RsaDer.prototype['getDer'] = function() {
  return this.der;
};
RsaDer.prototype['getType'] = function() {
  return this.type;
};
RsaDer.prototype['getKeyOps'] = function() {
  return this.keyOps;
};
RsaDer.prototype['getExtractable'] = function() {
  return this.extractable;
};

function jwkToRsaDer(jwk) {
    var rsaKey = parseRsaJwk(jwk);
    if (!rsaKey) {
        return undefined;
    }
    var type;
    var der;
    if (rsaKey instanceof RsaPublicKey) {
        type = KeyFormat.SPKI;
        der = buildRsaSpki(rsaKey).der;
    } else if (rsaKey instanceof RsaPrivateKey) {
        type = KeyFormat.PKCS8;
        der = buildRsaPkcs8(rsaKey).der;
    } else {
        return undefined;
    }
    return new RsaDer(der, type, rsaKey.keyOps, rsaKey.ext);
}

function webCryptoUsageToJwkKeyOps(webCryptoUsage) {
    var keyOps = webCryptoUsage.map(function(x) {
        if (x == 'wrapKey')
            return 'wrap';
        if (x == 'unwrapKey')
            return 'unwrap';
        return x;
    });
    return keyOps;
}

function webCryptoAlgorithmToJwkAlg(webCryptoAlgorithm) {
    if (webCryptoAlgorithm.name == 'RSAES-PKCS1-v1_5') {
        return 'RSA1_5';
    }
    else if (webCryptoAlgorithm.name == 'RSASSA-PKCS1-v1_5') {
        if (webCryptoAlgorithm.hash.name == 'SHA-256') {
            return 'RS256';
        }
        else if (webCryptoAlgorithm.hash.name == 'SHA-384') {
            return 'RS384';
        }
        else if (webCryptoAlgorithm.hash.name == 'SHA-512') {
            return 'RS512';
        }
        else {
            return undefined;
        }
    }
    else {
        return undefined;
    }
}

function parse(abv) {
    asn1ParseRecursionDepth = 0;
    return asn1Parse(new Asn1Token(abv), 0, abv.length);
}

// external interface

// Debug builds include these named symbols plus the Release symbols below. The
// symbols here get renamed in Release builds.
module.exports.parse = parse;
module.exports.show = asn1Show;
module.exports.isRsaSpki = isRsaSpki;
module.exports.isRsaPkcs8 = isRsaPkcs8;
module.exports.NodeFactory = NodeFactory;
module.exports.Builder = Builder;
module.exports.tagVal = tagVal;
module.exports.RsaPublicKey = RsaPublicKey;
module.exports.RsaPrivateKey = RsaPrivateKey;
module.exports.buildRsaSpki = buildRsaSpki;
module.exports.parseRsaSpki = parseRsaSpki;
module.exports.buildRsaPkcs8 = buildRsaPkcs8;
module.exports.parseRsaPkcs8 = parseRsaPkcs8;
module.exports.buildRsaJwk = buildRsaJwk;
module.exports.parseRsaJwk = parseRsaJwk;
module.exports.RsaDer = RsaDer;

// Release builds export only these named symbols.
module.exports['rsaDerToJwk'] = rsaDerToJwk;
module.exports['jwkToRsaDer'] = jwkToRsaDer;
module.exports['webCryptoAlgorithmToJwkAlg'] = webCryptoAlgorithmToJwkAlg;
module.exports['webCryptoUsageToJwkKeyOps'] = webCryptoUsageToJwkKeyOps;

})(require, (typeof module !== 'undefined') ? module : mkmodule('asnjwk'));

/*! rsapem-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
//
// rsa-pem.js - adding function for reading/writing PKCS#1 PEM private key
//              to RSAKey class.
//
// version: 1.1 (2012-May-10)
//
// Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://kjur.github.com/jsrsasign/license/
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
// 
//
// Depends on:
//
//
//
// _RSApem_pemToBase64(sPEM)
//
//   removing PEM header, PEM footer and space characters including
//   new lines from PEM formatted RSA private key string.
//

function _rsapem_privatePEMToBase64(sPEMPrivateKey) {
  var s = sPEMPrivateKey;
  s = s.replace("-----BEGIN RSA PRIVATE KEY-----", "");
  s = s.replace("-----END RSA PRIVATE KEY-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _rsapem_publicPEMToBase64(sPEMPublicKey) {
  var s = sPEMPublicKey;
  s = s.replace("-----BEGIN PUBLIC KEY-----", "");
  s = s.replace("-----END PUBLIC KEY-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _rsapem_getPosArrayOfChildrenFromPrivateHex(hPrivateKey) {
  var a = new Array();
  var v1 = ASN1HEX.getStartPosOfV_AtObj(hPrivateKey, 0);
  var n1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, v1);
  var e1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, n1);
  var d1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, e1);
  var p1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, d1);
  var q1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, p1);
  var dp1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, q1);
  var dq1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, dp1);
  var co1 = ASN1HEX.getPosOfNextSibling_AtObj(hPrivateKey, dq1);
  a.push(v1, n1, e1, d1, p1, q1, dp1, dq1, co1);
  return a;
}

function _rsapem_getHexValueArrayOfChildrenFromPrivateHex(hPrivateKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromPrivateHex(hPrivateKey);
  var v =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[0]);
  var n =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[1]);
  var e =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[2]);
  var d =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[3]);
  var p =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[4]);
  var q =  ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[5]);
  var dp = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[6]);
  var dq = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[7]);
  var co = ASN1HEX.getHexOfV_AtObj(hPrivateKey, posArray[8]);
  var a = new Array();
  a.push(v, n, e, d, p, q, dp, dq, co);
  return a;
}

function _rsapem_getPosArrayOfChildrenFromPublicHex(hPublicKey) {
  var a = new Array();
  var n1 = ASN1HEX.getStartPosOfV_AtObj(hPublicKey, 0);
  var e1 = ASN1HEX.getPosOfNextSibling_AtObj(hPublicKey, n1);
  a.push(n1, e1);
  return a;
}

function _rsapem_getHexValueArrayOfChildrenFromPublicHex(hPublicKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromPublicHex(hPublicKey);
  var n = ASN1HEX.getHexOfV_AtObj(hPublicKey, posArray[0]);
  var e = ASN1HEX.getHexOfV_AtObj(hPublicKey, posArray[1]);
  var a = new Array();
  a.push(n, e);
  return a;
}

/**
 * read PKCS#1 private key from a string
 * @name readPrivateKeyFromPEMString
 * @memberOf RSAKey#
 * @function
 * @param {String|Uint8Array} key PEM string or DER encoding of PKCS#1 private key.
 */
function _rsapem_readPrivateKeyFromPEMString(key) {
  if (typeof key !== 'string')
	  key = base64$encode(key);
  var keyB64 = _rsapem_privatePEMToBase64(key);
  var keyHex = b64tohex(keyB64); // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromPrivateHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
  this.setPEMString(keyB64);
}

/**
 * read public key from a string
 * @name readPublicKeyFromPEMString
 * @memberOf RSAKey#
 * @function
 * @param {String|Uint8Array} key PEM string or DER encoding of public key.
 */
function _rsapem_readPublicKeyFromPEMString(key) {
	  if (typeof key !== 'string')
		  key = base64$encode(key);
	var keyB64 = _rsapem_publicPEMToBase64(key);
	var keyHex = b64tohex(keyB64);
	var a = _rsapem_getHexValueArrayOfChildrenFromPublicHex(keyHex);
	this.setPublic(a[0], a[1]);
	this.setPEMString(keyB64);
}

RSAKey.prototype.readPrivateKeyFromPEMString = _rsapem_readPrivateKeyFromPEMString;
RSAKey.prototype.readPublicKeyFromPEMString = _rsapem_readPublicKeyFromPEMString;
//RSAKey.prototype.privateKeyToPEMString = _rsapem_privateKeyToPEMString;
//RSAKey.prototype.publicKeyToPEMString = _rsapem_publicKeyToPEMString;
// Licensed to the Software Freedom Conservancy (SFC) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The SFC licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

'use strict'

class VirtualAuthenticatorOptions {

  static Protocol = {
    "CTAP2": 'ctap2',
    "U2F": 'ctap1/u2f',
  }
  
  static Transport = {
    "BLE": 'ble',
    "USB": 'usb',
    "NFC": 'nfc',
    "INTERNAL": 'internal',
  } 

  constructor() {
    this._protocol = VirtualAuthenticatorOptions.Protocol["CTAP2"]
    this._transport = VirtualAuthenticatorOptions.Transport["USB"]
    this._hasResidentKey = false
    this._hasUserVerification = false
    this._isUserConsenting = true
    this._isUserVerified = false
  }

  getProtocol() {
    return this._protocol
  }

  setProtocol(protocol) {
    this._protocol = protocol
  }

  getTransport() {
    return this._transport
  }

  setTransport(transport) {
    this._transport = transport
  }

  getHasResidentKey() {
    return this._hasResidentKey
  }

  setHasResidentKey(value) {
    this._hasResidentKey = value
  }

  getHasUserVerification() {
    return this._hasUserVerification
  }

  setHasUserVerification(value) {
    this._hasUserVerification = value
  }

  getIsUserConsenting() {
    return this._isUserConsenting
  }

  setIsUserConsenting(value) {
    this._isUserConsenting = value
  }

  getIsUserVerified() {
    return this._isUserVerified
  }

  setIsUserVerified(value) {
    this._isUserVerified = value
  }

  toDict() {
    return {
      "protocol": this.getProtocol(),
      "transport": this.getTransport(),
      "hasResidentKey": this.getHasResidentKey(),
      "hasUserVerification": this.getHasUserVerification(),
      "isUserConsenting": this.getIsUserConsenting(),
      "isUserVerified": this.getIsUserVerified(),

    }
  }
}

class Credential {
  constructor(
    credentialId,
    isResidentCredential,
    rpId,
    userHandle,
    privateKey,
    signCount
  ) {
    this._id = credentialId
    this._isResidentCredential = isResidentCredential
    this._rpId = rpId
    this._userHandle = userHandle
    this._privateKey = privateKey
    this._signCount = signCount
  }

  id() {
    return Buffer.from(this._id).toString('base64url')
  }

  isResidentCredential() {
    return this._isResidentCredential
  }

  rpId() {
    return this._rpId
  }

  //   userHandle() {
  //     return this._userHandle
  //   }

  userHandle() {
    if (this._userHandle) {
      return Buffer.from(this._userHandle).toString('base64url')
    }
    return null
  }

  //   privateKey() {
  //     return this._privateKey
  //   }

  privateKey() {
    return Buffer.from(this._privateKey, 'binary').toString('base64url')
  }

  signCount() {
    return this._signCount
  }

  // Class method
  createResidentCredential(id, rpId, userHandle, privateKey, signCount) {
    return new Credential(id, true, rpId, userHandle, privateKey, signCount)
  }

  // Class method
  createNonResidentCredential(id, rpId, privateKey, signCount) {
    return new Credential(id, false, rpId, null, privateKey, signCount)
  }

  toDict() {
    let credentialData = {
      'credentialId': this.id(),
      'isResidentCredential': this.isResidentCredential(),
      'rpId': this.rpId(),
      'privateKey': this.privateKey(),
      'signCount': this.signCount(),
    }

    if (this.userHandle() != null) {
      credentialData['userHandle'] = this.userHandle()
    }

    return credentialData
  }

  fromDict(data) {
    let _id = Buffer.from(data['privateKey'], 'base64url').toString()
    let isResidentCredential = data['isResidentCredential']
    let rpId = data['rpId']
    let privateKey = Buffer.from(data['privateKey'], 'base64url').toString()
    let signCount = data['signCount']
    let userHandle

    if ('userHandle' in data) {
      userHandle = Buffer.from(data[('userHandle', 'base64url')]).toString()
    } else {
      userHandle = null
    }
    return new Credential(
      _id,
      isResidentCredential,
      rpId,
      userHandle,
      privateKey,
      signCount
    )
  }
}

module.exports = {
  Credential,
  VirtualAuthenticatorOptions,
}

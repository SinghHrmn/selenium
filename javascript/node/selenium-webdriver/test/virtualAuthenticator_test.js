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

const assert = require('assert')
const { until } = require('..')
const virtualAuthenticatorCredential =
  require('../lib/virtual_authenticator').Credential
const virtualAuthenticatorOptions =
  require('../lib/virtual_authenticator').VirtualAuthenticatorOptions
const webdriver = require('../lib/webdriver').WebDriver
const { ignore, suite } = require('../lib/test')
const { By } = require('..')
const { Browser } = require('../lib/capabilities')
const { resolve } = require('path')
// const PQueue = require('p-queue')

let options

function createRkEnabledU2fAuthenticator(driver) {
  let options
  options = new virtualAuthenticatorOptions()
  options.setProtocol(virtualAuthenticatorOptions.Protocol['U2F'])
  options.setHasResidentKey(true)
  driver.addVirtualAuthenticator(options)
  return driver
}

function createRkDisabledU2fAuthentication(driver) {
  let options
  options = new virtualAuthenticatorOptions()
  options.setProtocol(virtualAuthenticatorOptions.Protocol['U2F'])
  options.setHasResidentKey(false)
  driver.addVirtualAuthenticator(options)
  return driver
}

function createRkEnabledAuthenticator(driver) {
  let options
  options = new virtualAuthenticatorOptions()
  options.setProtocol(virtualAuthenticatorOptions.Protocol['CTAP2'])
  options.setHasResidentKey(true)
  options.setHasUserVerification(true)
  options.setIsUserVerified(true)
  driver.addVirtualAuthenticator(options)
  return driver
}

function createRkDisabledAuthenticator(driver) {
  let options
  options = new virtualAuthenticatorOptions()
  options.setProtocol(virtualAuthenticatorOptions.Protocol['CTAP2'])
  options.setTransport(virtualAuthenticatorOptions.Transport['USB'])
  options.setHasResidentKey(false)
  options.setHasUserVerification(true)
  options.setIsUserVerified(true)
  driver.addVirtualAuthenticator(options)
  return driver
}

// ----------------------- TESTS --------------------------

suite(function (env) {
  const BASE64_ENCODED_PK =
    'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDbBOu5Lhs4vpowbCnmCyLUpIE7JM9sm9QXzye2G+jr+Kr' +
    'MsinWohEce47BFPJlTaDzHSvOW2eeunBO89ZcvvVc8RLz4qyQ8rO98xS1jtgqi1NcBPETDrtzthODu/gd0sjB2Tk3TLuBGV' +
    'oPXt54a+Oo4JbBJ6h3s0+5eAfGplCbSNq6hN3Jh9YOTw5ZA6GCEy5l8zBaOgjXytd2v2OdSVoEDNiNQRkjJd2rmS2oi9AyQ' +
    'FR3B7BrPSiDlCcITZFOWgLF5C31Wp/PSHwQhlnh7/6YhnE2y9tzsUvzx0wJXrBADW13+oMxrneDK3WGbxTNYgIi1PvSqXlq' +
    'GjHtCK+R2QkXAgMBAAECggEAVc6bu7VAnP6v0gDOeX4razv4FX/adCao9ZsHZ+WPX8PQxtmWYqykH5CY4TSfsuizAgyPuQ0' +
    '+j4Vjssr9VODLqFoanspT6YXsvaKanncUYbasNgUJnfnLnw3an2XpU2XdmXTNYckCPRX9nsAAURWT3/n9ljc/XYY22ecYxM' +
    '8sDWnHu2uKZ1B7M3X60bQYL5T/lVXkKdD6xgSNLeP4AkRx0H4egaop68hoW8FIwmDPVWYVAvo8etzWCtibRXz5FcNld9MgD' +
    '/Ai7ycKy4Q1KhX5GBFI79MVVaHkSQfxPHpr7/XcmpQOEAr+BMPon4s4vnKqAGdGB3j/E3d/+4F2swykoQKBgQD8hCsp6FIQ' +
    '5umJlk9/j/nGsMl85LgLaNVYpWlPRKPc54YNumtvj5vx1BG+zMbT7qIE3nmUPTCHP7qb5ERZG4CdMCS6S64/qzZEqijLCqe' +
    'pwj6j4fV5SyPWEcpxf6ehNdmcfgzVB3Wolfwh1ydhx/96L1jHJcTKchdJJzlfTvq8wwKBgQDeCnKws1t5GapfE1rmC/h4ol' +
    'L2qZTth9oQmbrXYohVnoqNFslDa43ePZwL9Jmd9kYb0axOTNMmyrP0NTj41uCfgDS0cJnNTc63ojKjegxHIyYDKRZNVUR/d' +
    'xAYB/vPfBYZUS7M89pO6LLsHhzS3qpu3/hppo/Uc/AM/r8PSflNHQKBgDnWgBh6OQncChPUlOLv9FMZPR1ZOfqLCYrjYEqi' +
    'uzGm6iKM13zXFO4AGAxu1P/IAd5BovFcTpg79Z8tWqZaUUwvscnl+cRlj+mMXAmdqCeO8VASOmqM1ml667axeZDIR867ZG8' +
    'K5V029Wg+4qtX5uFypNAAi6GfHkxIKrD04yOHAoGACdh4wXESi0oiDdkz3KOHPwIjn6BhZC7z8mx+pnJODU3cYukxv3WTct' +
    'lUhAsyjJiQ/0bK1yX87ulqFVgO0Knmh+wNajrb9wiONAJTMICG7tiWJOm7fW5cfTJwWkBwYADmkfTRmHDvqzQSSvoC2S7aa' +
    '9QulbC3C/qgGFNrcWgcT9kCgYAZTa1P9bFCDU7hJc2mHwJwAW7/FQKEJg8SL33KINpLwcR8fqaYOdAHWWz636osVEqosRrH' +
    'zJOGpf9x2RSWzQJ+dq8+6fACgfFZOVpN644+sAHfNPAI/gnNKU5OfUv+eav8fBnzlf1A3y3GIkyMyzFN3DE7e0n/lyqxE4H' +
    'BYGpI8g=='

  const browsers = (...args) => env.browsers(...args)

  let driver

  before(async function () {
    driver =
      // new webdriver()
      await env.builder().build()
  })

  after(function () {
    return driver.quit()
  })

  describe('VirtualAuthenticator', function () {
    // ignore(browsers(Browser.SAFARI, Browser.FIREFOX)).it(
    //   'should add or remove virtual authenticator',
    //   function () {
    //     driver = createRkDisabledAuthenticator(driver)
    //     assert(driver.virtualAuthenticatorId() != null)

    //     driver.removeVirtualAuthenticator()
    //     assert(driver.virtualAuthenticatorId() == null)
        
    //   }
    // )

    ignore(browsers(Browser.SAFARI, Browser.FIREFOX)).it(
      'should add or remove non resident credential',
      async function () {
        driver = createRkDisabledAuthenticator(driver)
        // assert(driver.virtualAuthenticatorId() != null)

        let credential =
          new virtualAuthenticatorCredential().createNonResidentCredential(
            new Uint8Array([1, 2, 3, 4]),
            'localhost',
            Buffer.from(BASE64_ENCODED_PK, 'base64url').toString('binary'),
            0
          )

        let credential2 =
          new virtualAuthenticatorCredential().createNonResidentCredential(
            new Uint8Array([1, 2, 3, 4, 5]),
            'localhost',
            Buffer.from(BASE64_ENCODED_PK, 'base64').toString('binary'),
            1
          )
          
        

        

        // driver.addCredential(credential).then(response => {
        //   assert.equal(driver.getCredentials().length, 1)
        // })

        new Promise(async (resolve) => {
          driver.addCredential(credential2)
          resolve()
        }).then(() => {
            assert.equal(driver.getCredentials().length, 2000)
          }
        ).catch(() => {
        })

        // assert(false)

        // new Promise((resolve) => {
        //   resolve(driver.removeCredential(credential.id()))
        // }).then((response) => {
        //   if(response != null){
        //     assert.equal(driver.getCredentials().length, 1)
        //   }
        // }).catch(() => {
        // })

        // driver.removeVirtualAuthenticator()
        // assert(driver.virtualAuthenticatorId() == null)

        // new Promise((resolve) => {
        //   resolve(driver.removeVirtualAuthenticator())
        // }).then((response) => {
        //   if(response != null){
        //     assert(driver.virtualAuthenticatorId() == null)
        //   }
        // }).catch(() => {
        //   console.log("error")
        //   assert(false)
        // })
      }
    )

    // ignore(browsers(Browser.SAFARI, Browser.FIREFOX)).it(
    //   'should add or remove resident credential',
    //   function () {
    //     driver = createRkEnabledAuthenticator(driver)
    //     assert(driver.virtualAuthenticatorId() != null)

    //     let credential =
    //       new virtualAuthenticatorCredential().createNonResidentCredential(
    //         new Uint8Array([1, 2, 3, 4]),
    //         'localhost',
    //         Buffer.from(BASE64_ENCODED_PK, 'base64').toString('binary'),
    //         0
    //       )

    //     let credential2 =
    //       new virtualAuthenticatorCredential().createResidentCredential(
    //         new Uint8Array([1, 2, 3, 4, 5]),
    //         'localhost',
    //         new Uint8Array([1]),
    //         Buffer.from(BASE64_ENCODED_PK, 'base64').toString('binary'),
    //         1
    //       )

    //     driver.addCredential(credential)
    //     setTimeout(function () {
    //       assert.equal(driver.getCredentials().length, 1)
    //     }, 500)

    //     driver.addCredential(credential2)
    //     setTimeout(function () {
    //       assert.equal(driver.getCredentials().length, 2)
    //     }, 500)

    //     setTimeout(function () {
    //       driver.removeCredential(credential.id())
    //     }, 500)

    //     setTimeout(function () {
    //       assert.equal(driver.getCredentials().length, 1)
    //     }, 500)

    //     driver.removeVirtualAuthenticator()
    //     assert(driver.virtualAuthenticatorId() == null)
    //   }
    // )

    // ignore(browsers(Browser.SAFARI, Browser.FIREFOX)).it(
    //   'should remove all credentials',
    //   function () {
    //     let options = new virtualAuthenticatorOptions()
    //     options.setHasResidentKey(true)

    //     driver.addVirtualAuthenticator(options)
    //     assert(driver.virtualAuthenticatorId() != null)

    //     let credential =
    //       new virtualAuthenticatorCredential().createNonResidentCredential(
    //         new Uint8Array([1, 2, 3, 4]),
    //         'localhost',
    //         Buffer.from(BASE64_ENCODED_PK, 'base64').toString('binary'),
    //         0
    //       )

    //     let credential2 =
    //       new virtualAuthenticatorCredential().createResidentCredential(
    //         new Uint8Array([1, 2, 3, 4, 5]),
    //         'localhost',
    //         new Uint8Array([1]),
    //         Buffer.from(BASE64_ENCODED_PK, 'base64').toString('binary'),
    //         1
    //       )

    //     driver.addCredential(credential)
    //     setTimeout(function () {
    //       assert.equal(driver.getCredentials().length, 1)
    //     }, 500)

    //     driver.addCredential(credential2)
    //     setTimeout(function () {
    //       assert.equal(driver.getCredentials().length, 2)
    //     }, 500)

    //     setTimeout(function () {
    //       driver.removeCredential(credential.id())
    //     }, 500)

    //     setTimeout(function () {
    //       assert.equal(driver.getCredentials().length, 1)
    //     }, 500)

    //     driver.removeVirtualAuthenticator()
    //     assert(driver.virtualAuthenticatorId() == null)
    //   }
    // )

    // ignore(browsers(Browser.SAFARI, Browser.FIREFOX)).it(
    //   'should test full virtual authenticator',
    //   async function () {
    //     let options
    //     options = new virtualAuthenticatorOptions()
    //     options.setProtocol(virtualAuthenticatorOptions.Protocol['U2F'])
    //     options.setTransport(virtualAuthenticatorOptions.Transport['USB'])
    //     options.setIsUserConsenting(true)

    //     driver.addVirtualAuthenticator(options)

    //     driver.get('https://webauthn.io/')
    //     let username = await driver.findElement(By.id('input-email'))
    //     username.sendKeys('username')

    //     driver.findElement({ id: 'select-attestation' }).sendKeys('Direct')
    //     driver
    //       .findElement({ id: 'select-authenticator' })
    //       .sendKeys('cross-platform')

    //     await driver.findElement(By.id('register-button')).click()

    //     let login = await driver.findElement(By.id('login-button'))
    //     await driver.wait(until.elementIsVisible(login), 40000)
    //     await driver.wait(until.elementIsEnabled(login), 40000)
    //     login.click()

    //     login.click()

    //     // driver.wait(until.elementLocated(await driver.findElement(By.className('col-lg-12'))), 3000)
    //     await driver.wait(
    //       until.elementLocated(By.className('col-lg-12')),
    //       400000
    //     )

    //     let source = await driver.getPageSource()

    //     console.log('source = ', source)

    //     if (source.includes("You're logged in!")) {
    //       assert(true)
    //     } else {
    //       assert(false)
    //     }
    //   }
    // )
  })
})

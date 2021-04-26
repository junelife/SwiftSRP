//
//  SwiftSRPTests.swift
//  SwiftSRPTests
//
//  Created by Joseph Ross on 1/26/17.
//  Copyright © 2017 Joseph Ross. All rights reserved.
//

import XCTest
@testable import SwiftSRP
import openssl
import SRP
import CryptoKit

class SwiftSRPTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSRP() {
        guard
            let verifier = SRPVerifier(password:"12345678"),
            let user = SRPUser(password: "12345678"),
            let A = user.startAuthentication(),
            let (B, salt) = verifier.startVerification(A: A),
            let M1 = user.processChallenge(B: B, salt: salt)
            else {
                XCTFail("Secret calculation failed")
                return
        }
        
        XCTAssertEqual(verifier.secret, user.secret)
        
        guard
            let M2 = verifier.verifySession(M1: M1),
            user.verifySession(M2: M2)
            else {
                XCTFail("Verification failed")
                return
        }
    }
    
    func testInteropJuneSrpVerifier() {
        guard
            let verifier = JuneSrpVerifier(password:"12345678"),
            let user = SRPUser(password: "12345678"),
            let A = user.startAuthentication(),
            let (B, salt) = verifier.startVerification(A: A),
            let M1 = user.processChallenge(B: B, salt: salt)
            else {
                XCTFail("Secret calculation failed")
                return
        }
        
        XCTAssertEqual(verifier.secret, user.secret)
        
        guard
            let M2 = verifier.verifySession(M1: M1),
            user.verifySession(M2: M2)
            else {
                XCTFail("Verification failed")
                return
        }
    }
    
    
    func testFowler() {
        let username = "user"
        let password = "12345678"
        
        let configuration = SRPConfiguration<Insecure.SHA1>(.N8192)
        
        let client = SRPClient(configuration: configuration)
        let (salt, verifier) = client.generateSaltAndVerifier(username: username, password: password)
        
        let clientKeys = client.generateKeys()
        let clientPublicKey = clientKeys.public
        
        let server = SRPServer(configuration: configuration)
        let serverKeys = server.generateKeys(verifier: verifier)
        let serverPublicKey = serverKeys.public
        
        let clientSharedSecret = try! client.calculateSharedSecret(
            username: username,
            password: password,
            salt: salt,
            clientKeys: clientKeys,
            serverPublicKey: serverPublicKey
        )
        let clientProof = client.calculateClientProof(
            username: username,
            salt: salt,
            clientPublicKey: clientKeys.public,
            serverPublicKey: serverPublicKey,
            sharedSecret: clientSharedSecret
        )
        
        let serverSharedSecret = try! server.calculateSharedSecret(
            clientPublicKey: clientPublicKey,
            serverKeys: serverKeys,
            verifier: verifier
        )
        let serverProof = try! server.verifyClientProof(
            proof: clientProof,
            username: username,
            salt: salt,
            clientPublicKey: clientPublicKey,
            serverPublicKey: serverKeys.public,
            sharedSecret: serverSharedSecret
        )
        
        try! client.verifyServerProof(
            serverProof: serverProof,
            clientProof: clientProof,
            clientKeys: clientKeys,
            sharedSecret: clientSharedSecret
        )
    }
    
    func testSpecificCase() {
        let A_b64 = "jAN+nVpeNcoLDMXHsKwyqrlsk13oBzxbF2zpzr6AS99aVpTZvidi+SJuyw/zS0py87ZtL4YgIFICDSGxrrbx20pOOrSVRVAWHbXR9mW5bLns2dODB2ZIvrNYSQ2fAuN7oBinE98WT5+qIVDbupG0jv4m09LjNaSSJcgLwa3saLVtgNfiKSHFAStN8pJSzacIv1m3qCzp/hEYw59b5TWPvXW7fpOsm3wrHSLIbosy0EreIXR52bm8/c9auCxA0bmE+JZ4uBUPj+Vny2swxWiVS5MalolstllDS2lWDYskkFEL5oOfwEdmpk1HfCNJfRnB1H3MHVopM48tA5L7cU4soqScxCeofSbmJNqhwYtG/S9ak/qUk1asGm5y5u3T6I29ft6The2+6vBODJzG/O19jJd/269BFoYfmBwX8eVZosWwstjdBpRQyppT8DlhNoq0+OE/X4Xnn8I/uMSoSthtH5v7u+l8Ott98P5Zn/ptpLYrcS0nJtbl/KtVCEO6LGzJ4PakfZqTfVpNgEzMhOvQy4XztKdj3VTB4g7XM13tr0TtXBIJup9o2qHz+NpgI0MmiUvK0SHq86DTkz19wU0xuOd68TeUVl2JDG9DSI0bDxfInAWit71P/s3zJkGdN9NzMTc5RHuWYPiASusKD+ajE7FmYfqNL7r147PlddM8GQT+shQd25+ugk07/vK4yk648mXkinNlWkDs9pXKL9hi4kfn1z+AfLRYUM2I44fCDiVARWYUlxRjrBbc19d7P7p80z9csdENtflqaQiubMJM1AAvmFOYvd9iHHjtFSdN/AKGpaJ1rENkP/xQ5+AlLldlIW759966JrJOARrU8oHTTFfQ5Sa3WerDjBCQNhoM+z1YbZ0pesv6LMk/a5tu9Qflj3f2xlmjG5LB1pRVsGVZ+x69UdUkcyZHsO/0IpfF2hghXYVUtDn7zW6+zMpJH7AF1nswUTSq+0UhZ3eB337XFVkNQIplLxmsh1Hn7bpOWFSu8Y+OQplgDKYz47vSrGVfQOEPS+OA6x8PZyl3v6t6c18KqMezw7J0CfC4rlCYkj2xdomsSHYbdezfnmqMi7Z/2sKTTngyIG+eqDUt61AbzR9/ZxENpXT14erz/gIcVshgqifCds1fQATfdIPYwb6Hyc6MlHMmVBnlZv/M8OUBKePOa4szOb6STs9xwglRDvr9zISbybQ6nG8CeaEYC5vuSg3/hFwJW7qewONqmn4p7Vri2/C/s8+JsgjXxsh2hsIYoNE5szq0Sn6bfOVUrtn5xJMQqPJ5gNwj3Cr+S5N8lEUJlWufjWAUBHAjWX6wcjyuUeJXeg7GQQbg0mcOVhNXAe5vrCmDlDZw5Ta66A6mrg=="
        let B_b64 = "k69tb52/eixotMF/t90oEsMy/JSnXK9SRKkKcH+hxPGj9uhV6Rg9YM08FjpzqwVOrgp5CbndU8AzWIA0VdjGb4pX5YtgMqGbsG3JuPeTpuaHkvZDfPG1nyPlsEUkUCwzSPGk+UXMKw/V7zPtywJxL7KQ3U52o0/TfTMD+sodsZMlll4P+OHj5nWzhEQpNUWKUnEGd5K98r5UZlZgyBN8r2IpvLlLochd4yzue1/D/3mxhj3/LN1kBTY7RipMB+W9vqKyRJwOrgnCC4LvhkqhpkviNj6pe+vtBGNb9uReCuDUfThPLlJAtw3GBkoIZnaFJNlE27L3rcR5WqyOmXWMz7Ss1UhVzrF4/cpC91v/qsnt4htE0ft4iBnV7mpMjRL5H4c/ERmhouzahH3dxp2ohrVK+HX+ski2YyBtrmVw8zKlxXccGhYL20ALuCigcKuGeGAZTpfxeEr73jN+cqfgTQn0xiWCf5SUIBglvOAndgBVRmhs5hPciFqbFt/ozZCBZhSW4tZKQxOrMXPjy9ysOSOV/3vmweSviIuaBZUNnQ0Yz2jagu6ltFVCKVYhbhwePbQJBPLJGgf17M+lsmU+t6hsc3Z+fcOdQWkIHDBaME8Kkz6EY2Vv1G3tJpQ/pN55Zg8VcDaLVKUBAtAUbAPNocGg7A34rfAzs44k3CZl0lF+2t8P7aKvvLIAmJJSdBpgJVZMiHz5PymdEFbHQjYhKcPi9fHlvr1ltspz+z+iAiyXEmW/Klu4YQIJcVOzbMpzAJ+oJHpXZHtoGpxPJ7/cLBqUAL0W6axElndnuCYUj+ESqhu4rKZKW29NiFax3xifz3HKxA+vy2NFnwZJeEian52W5D6mWdjsUOowR5HsTifaVJNkyPP0P13ao3Hr4CyGncTuYOi+z7VZryLjJKvHX+4i5V8X6ZSXWmQYqy4H+IwBe9rjAZ5jZ+e+DfFvGRfnLOIO5DTvM4A5eTqyC2/uMiBetslyndGIXpVBcuG6jPVt939saXCKP+p+BYP+ex9l2Wpws1UBv3a9SnI8lTLJ/a0aCorbqfVS5Rcahef2K/kAQr/askOARyPw8S3pSNHDowrlYEvFdMMW2oY+tds2E9B41MdGWgWKRpzhOZEN9ldb2zyUUD8v1DlHxSTf8H4aaW6rjljDf8fdvxAOdFEb2XPboMgk4gSh3rDBNmZQapYLhYnq0A9Wkaz47KbiSOyJ2t+LfAYXw0Hx7Fi5GDMntTi+O4sZ8U+J99kKCi8l+L8IuwCUrG/CRIXvyGSmQRSgqYwzM0VHCmKR8GeM/0Q114ZnA26MQu4rMkTHApecwKrZtPIzqGWOatbAOfpTBjiqEvqMqQ2fxBFbcYe5BJ9BxA=="
        let S_b64 = "zXOGbrhG/JF/mWww6ZiQRuRv9WsnBy5TvT8ELTCTmksxOTlfjfQ5EatVACzOtw45x1Qc6qbSk4Q1fMH3qxdAdi0r4BWWauj/AHVTaEsekiNiE//C3UN2DNQifgOh+axfctX4sapozk7f6vwdhiUIgNWEWgdQJQvIHeWWMHNM/xeSqfTVtBmrDuzZEqiGuNMdVcCGMhD0VEGLS0LG/e1WPMgZoEWOc+aWAcduu2bXc7ssSC6EWHp24tS78fI+0ioqLXeZFDXIXp2pTG/ybccJwU3FgZYF2Q9hCnpeRAfHh9x1NpHX8LZXa0O1EJBVCF8wxH6/8U0qc+L48sY1FryMs7RaNdrG876FUHs6KlNFOkXwCkgwikMx8bLnr4/n+PNc+zsRz4o0H9LumgMIVU273NWdEy5Y+mFT1q2iMDdZxjitOpJ+fZtxxZrNExGg7ffSpbMS9AzfNkjcp15sSscrnjB3FNLVQMMx4h03fm1VDxfhBIDibcD/uWmo9+H9fyeMvL1KMEF902maWyPWN9ssqSZfZd8OlmLr7hiX7rMIm8y8P7+FM5sSukyDfuRcICmk9qn02UbmqKP1OiucefiKjFypU8mvvj8YDuF8OLKx2ekClkWhyRCn6byLHrFkcZUg52rKa/n4Se8cd/i1U50HHxRoNrehyPTzU2zx9uFBWkRiBOV6sQe/pLaqryzH2Bs3sT9sPBKzLlE+g77UwcKFs/3u11jXl6EdS5jBOIpq24u3L2M+SVzhH7L5Oa0e41Vd91BqASyQ3oG6QBRvMY1fFKXBXgqchEEq8pQO+bRAwuMOzW72w13/Re8xQ5IJS7QZTr1iGGP3ELoZZQ+jEOQB01YX5PPDiyfR6EJymTEOEEZVB6D8EDTaBuHzQ9QzDj71/KkP4jxkhx6cmY8xJZsoAu86Bl259wjuvcEFRdrrYYsitODec+vigBqwL0DkfiFdCpb7XPAV6DxTeBQzB97njZrMe6AZgst2JGuvm7CKGRZtpw1OdSeYVmGU/vGS1VFId1miuT/1aSmBaJN2pBjoBh5dCVUfhBAhlHT4wLwPrHPqPtyMEU/9BDBYiRV4Aq/dGrueumah145u6eJoLJBjanqc1bk7jpXyBKE5jG0K1TJvFDP+qNlNGK6FdvQsCZey2sb0cz4ZKV5EPAg8BNn8cH+AUDfP4do0vWhpK67pfgLork7jPRPU+jsJ7Alc+W+W+71WP5iWRI5MdoIa2ko/WrvPSQX7q99xCJLSrZbT3qaTGskbwNHgQwlatvNgeM4aAjjWzqiNUFGFt1X7XBk+6jtpixxa0LdVpTpkstAtvRyrFNV8GCIJxgko2vbXr7Ew7Xw6OuIi+pmUg2hKKrtiJQ=="
        let AData = Data(base64Encoded: A_b64)!
        let BData = Data(base64Encoded: B_b64)!
        let SData = Data(base64Encoded: S_b64)!
        let A = AData.withUnsafeBytes({ (ptr:UnsafePointer<UInt8>) in return BN_bin2bn(ptr, Int32(AData.count), nil)})!
        let B = BData.withUnsafeBytes({ (ptr:UnsafePointer<UInt8>) in return BN_bin2bn(ptr, Int32(BData.count), nil)})!
        let S = SData.withUnsafeBytes({ (ptr:UnsafePointer<UInt8>) in return BN_bin2bn(ptr, Int32(SData.count), nil)})!
        
        let APadded = BN_bn2binpad(A, minLength:1024)
        let BPadded = BN_bn2binpad(B, minLength:1024)
        let SPadded = BN_bn2binpad(S, minLength:1024)
        let ABS = APadded + BPadded + SPadded
        var M1Data = Data(count:Int(CC_SHA1_DIGEST_LENGTH))
        let _ = ABS.withUnsafeBytes() { absPtr in
            M1Data.withUnsafeMutableBytes() { m1Ptr in
                CC_SHA1(absPtr, UInt32(ABS.count), m1Ptr)
            }
        }
        
        XCTAssertEqual(M1Data.base64EncodedString(), "ADHKzgxGvOe4kFMQFA+MzQTabXQ=")
    }
}

//
//  SwiftSRPTests.swift
//  SwiftSRPTests
//
//  Created by Joseph Ross on 1/26/17.
//  Copyright © 2017 Joseph Ross. All rights reserved.
//

import XCTest
@testable import SwiftSRP

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
            let a = user.startAuthentication(),
            let (b, salt) = verifier.startVerification(a: a),
            let m = user.processChallenge(b: b, salt: salt),
            let hamk = verifier.verifySession(m: m),
            user.verifySession(hamk: hamk)
            else {
                XCTFail("Verification failed")
                return
        }
        XCTAssertEqual(verifier.sessionKey, user.sessionKey)
    }
}

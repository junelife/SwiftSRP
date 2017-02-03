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
            let A = user.startAuthentication(),
            let (B, salt) = verifier.startVerification(A: A),
            let M1 = user.processChallenge(B: B, salt: salt),
            let M2 = verifier.verifySession(M1: M1),
            user.verifySession(M2: M2)
            else {
                XCTFail("Verification failed")
                return
        }
        XCTAssertEqual(verifier.K, user.K)
    }
}

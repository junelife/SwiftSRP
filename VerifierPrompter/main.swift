//
//  main.swift
//  VerifierPrompter
//
//  Created by Joseph Ross on 1/28/17.
//  Copyright © 2017 Joseph Ross. All rights reserved.
//

import Foundation

while true {
    let verifier = SRPVerifier(password:"password")!
    print("salt: \(verifier.salt)")
    print("A:")
    var A = readLine()!.trimmingCharacters(in: .whitespacesAndNewlines)
    print("more A(optional):")
    A.append(readLine()!.trimmingCharacters(in: .whitespacesAndNewlines))
    let (B, _) = verifier.startVerification(A: A)!
    print("B: \(B)")
    //print("S: \(verifier.secret!.base64EncodedString())")
    print("M1:")
    var M1 = readLine()!
    M1 = M1.trimmingCharacters(in: .whitespacesAndNewlines)
    let M2 = verifier.verifySession(M1: M1)!
    print("M2: \(M2)")
    print("K: \(verifier.K!.base64EncodedString())")
}

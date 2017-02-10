//
//  main.swift
//  VerifierPrompter
//
//  Created by Joseph Ross on 1/28/17.
//  Copyright © 2017 Joseph Ross. All rights reserved.
//
import Foundation

setbuf(__stdoutp, nil);

var password = "password"
if CommandLine.arguments.count > 1 {
    password = CommandLine.arguments[1]
}
printError("VerifierPrompter \(password)")
let verifier = SRPVerifier(password:password)!
// print("A:")
let A = readLine()!.trimmingCharacters(in: .whitespacesAndNewlines)
// print("more A(optional):")
// A.append(readLine()!.trimmingCharacters(in: .whitespacesAndNewlines))
printError("A: \(A)")
let (B, _) = verifier.startVerification(A: A) ?? ("","")
print("\(B)")
print("\(verifier.salt)")
printError("S: \(verifier.secret!)")
// print("M1:")
let M1 = readLine()!.trimmingCharacters(in: .whitespacesAndNewlines)
printError("M1: \(M1)")
let M2 = verifier.verifySession(M1: M1)
print("\(M2 ?? "")")
guard M2 != nil else {
    exit(1)
}
printError("K: \(verifier.K!.base64EncodedString())")

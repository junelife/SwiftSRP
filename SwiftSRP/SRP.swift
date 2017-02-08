//
//  SRP.swift
//  SwiftSRP
//
//  Created by Joseph Ross on 1/26/17.
//  Copyright © 2017 Joseph Ross. All rights reserved.
//

import Foundation
import CommonCrypto
import openssl

public class SRPVerifier {
    
    private let s:UnsafeMutablePointer<BIGNUM>
    private let v:UnsafeMutablePointer<BIGNUM>
    private let gN:UnsafeMutablePointer<SRP_gN>
    private var S:UnsafeMutablePointer<BIGNUM>?
    public private(set) var K:Data? = nil
    private var M1:Data? = nil
    private var M2:Data? = nil
    
    public init?(password:String) {
        var saltBN:UnsafeMutablePointer<BIGNUM>?
        var verificationBN:UnsafeMutablePointer<BIGNUM>?
        guard let gN = SRP_get_default_gN("8192") else {
            return nil
        }
        self.gN = gN
        
        let N = gN.pointee.N
        let g = gN.pointee.g
        SRP_create_verifier_BN("user", password, &saltBN, &verificationBN, N, g)
        
        guard let v = verificationBN, let s = saltBN else {
            return nil
        }
        self.s = s
        self.v = v
        
    }
    
    public var salt:String {
        var saltData = Data(count: BN_num_bytes(s))
        let _ = saltData.withUnsafeMutableBytes() { ptr in
            BN_bn2bin(s, ptr)
        }
        return saltData.base64EncodedString()
    }
    
    public var secret:String? {
        guard let S = S else { return nil }
        var secretData = Data(count: BN_num_bytes(S))
        let _ = secretData.withUnsafeMutableBytes() { ptr in
            BN_bn2bin(S, ptr)
        }
        return secretData.base64EncodedString()
    }
    
    deinit {
        BN_free(s)
        BN_free(v)
        if let S = self.S {
            BN_free(S)
        }
    }
    
    public func startVerification(A A64:String) -> (B:String, s:String)? {
        guard let aDecoded = Data(base64Encoded: A64) else {
            return nil
        }
        
        
        guard let A = aDecoded.withUnsafeBytes({ ptr in
            return BN_bin2bn(ptr, Int32(aDecoded.count), nil)
        }) else {
            return nil
        }
        defer {
            BN_free(A)
        }
        
        //        let AString = String(cString: BN_bn2dec(A))
        //        print("A: \(AString)")
        
        guard let b = BN_new() else {
            return nil
        }
        defer {
            BN_free(b)
        }
        BN_rand(b, 256, -1, 0)
        
        guard SRP_Verify_A_mod_N(A, gN.pointee.N) != 0 else {
            print("A mod N was zero, invalid A")
            return nil
        }
        
        guard let B = SRP_Calc_B(b, gN.pointee.N, gN.pointee.g, v) else {
            return nil
        }
        defer {
            BN_free(B)
        }
        //        let BString = String(cString: BN_bn2dec(B))
        //        print("B: \(BString)")
        
        guard let u = SRP_Calc_u(A, B, gN.pointee.N) else {
            return nil
        }
        defer {
            BN_free(u)
        }
        guard let S = SRP_Calc_server_key(A, v, u, b, gN.pointee.N) else {
            return nil
        }
        self.S = S
        //        let SString = String(cString: BN_bn2dec(S))
        //        print("S: \(SString)")
        
        let padLength = BN_num_bytes(gN.pointee.N)
        
        let AData = BN_bn2binpad(A, minLength: padLength)
        let BData = BN_bn2binpad(B, minLength: padLength)
        let SData = BN_bn2binpad(S, minLength: padLength)
        
        // Calculate M1
        let ABSData = AData + BData + SData
        var M1 = Data(count:Int(CC_SHA1_DIGEST_LENGTH))
        let _ = ABSData.withUnsafeBytes() { absPtr in
            M1.withUnsafeMutableBytes() { m1Ptr in
                CC_SHA1(absPtr, UInt32(ABSData.count), m1Ptr)
            }
        }
        self.M1 = M1
        
        // Calculate M2
        let m1PadSize = padLength - M1.count
        let padding = Data(count:m1PadSize)
        let AM1SData = AData + padding + M1 + SData
        var M2 = Data(count:Int(CC_SHA1_DIGEST_LENGTH))
        let _ = AM1SData.withUnsafeBytes() { am1sPtr in
            M2.withUnsafeMutableBytes() { m2Ptr in
                CC_SHA1(am1sPtr, UInt32(AM1SData.count), m2Ptr)
            }
        }
        self.M2 = M2
        
        // Calculate K
        var K = Data(count:Int(CC_SHA1_DIGEST_LENGTH))
        let _ = SData.withUnsafeBytes() { sPtr in
            K.withUnsafeMutableBytes() { kPtr in
                CC_SHA1(sPtr, UInt32(SData.count), kPtr)
            }
        }
        self.K = K
        
        return (B: BData.base64EncodedString(), s: self.salt)
        
    }
    
    public func verifySession(M1 M164:String) -> String? {
        guard let M1Data = Data(base64Encoded: M164) else {
            printError("Couldn't decode M1: \(M164)")
            return nil
        }
        guard M1Data == M1, let M2 = self.M2 else {
            printError("M1 doesn't match.  \(M164) != \(M1?.base64EncodedString())")
            // M1 doesn't match, or M2 is not available.
            return nil
        }
        return M2.base64EncodedString()
    }
}

public class SRPUser {
    private let g:UnsafeMutablePointer<BIGNUM>
    private let N:UnsafeMutablePointer<BIGNUM>
    private var A:UnsafeMutablePointer<BIGNUM>?
    private var a:UnsafeMutablePointer<BIGNUM>?
    private var S:UnsafeMutablePointer<BIGNUM>?
    public private(set) var K:Data? = nil
    private var M1:Data? = nil
    private var M2:Data? = nil
    private let password:String
    
    public init?(password:String) {
        self.password = password
        guard let gN = SRP_get_default_gN("8192"), let N = gN.pointee.N, let g = gN.pointee.g else {
            return nil
        }
        self.N = N
        self.g = g
    }
    
    deinit {
        if let a = self.a {
            BN_free(a)
        }
        if let S = self.S {
            BN_free(S)
        }
    }
    
    public func startAuthentication() -> String? {
        guard let a = BN_new() else {
            return nil
        }
        BN_rand(a, 256, -1, 0)
        self.a = a
        guard let A = SRP_Calc_A(a, N, g) else {
            return nil
        }
        self.A = A
        var AData = Data(count:BN_num_bytes(A))
        let _ = AData.withUnsafeMutableBytes() { ptr in
            BN_bn2bin(A, ptr)
        }

        return AData.base64EncodedString()
    }

    public func processChallenge(B:String, salt:String) -> String? {
        guard let saltData = Data(base64Encoded: salt), let BDecoded = Data(base64Encoded:B) else {
            return nil
        }
        
        guard let s = saltData.withUnsafeBytes({ ptr in
            return BN_bin2bn(ptr, Int32(saltData.count), nil)
        }) else {
            return nil
        }
        defer {
            BN_free(s)
        }
        
        guard let B = BDecoded.withUnsafeBytes({ ptr in
            return BN_bin2bn(ptr, Int32(BDecoded.count), nil)
        }) else {
            return nil
        }
        defer {
            BN_free(B)
        }
        guard SRP_Verify_B_mod_N(B, N) != 0 else {
            print("B mod N was zero, invalid B")
            return nil
        }
        
        guard let x = SRP_Calc_x(s, "user", password) else {
            return nil
        }
        defer {
            BN_free(x)
        }
        
        guard let u = SRP_Calc_u(A, B, N) else {
            return nil
        }
        defer {
            BN_free(u)
        }
        
        guard let a = a, let S = SRP_Calc_client_key(N, B, g, x, a, u) else {
            return nil
        }
        defer {
            BN_free(S)
        }
        //        let SString = String(cString: BN_bn2dec(S))
        //        print("S: \(SString)")
        
        let padLength = BN_num_bytes(N)
        
        guard let A = A else {
            return nil
        }
        let APadded = BN_bn2binpad(A, minLength: padLength)
        let BPadded = BN_bn2binpad(B, minLength: padLength)
        let SPadded = BN_bn2binpad(S, minLength: padLength)
        
        // Calculate M1
        let ABSData = APadded + BPadded + SPadded
        var M1 = Data(count:Int(CC_SHA1_DIGEST_LENGTH))
        let _ = ABSData.withUnsafeBytes() { absPtr in
            M1.withUnsafeMutableBytes() { m1Ptr in
                CC_SHA1(absPtr, UInt32(ABSData.count), m1Ptr)
            }
        }
        self.M1 = M1
        
        // Calculate M2
        let m1PadSize = padLength - M1.count
        let padding = Data(count:m1PadSize)
        let AM1SData = APadded + padding + M1 + SPadded
        var M2 = Data(count:Int(CC_SHA1_DIGEST_LENGTH))
        let _ = AM1SData.withUnsafeBytes() { am1sPtr in
            M2.withUnsafeMutableBytes() { m2Ptr in
                CC_SHA1(am1sPtr, UInt32(AM1SData.count), m2Ptr)
            }
        }
        self.M2 = M2
        
        // Calculate K
        var K = Data(count:Int(CC_SHA1_DIGEST_LENGTH))
        let _ = SPadded.withUnsafeBytes() { sPtr in
            K.withUnsafeMutableBytes() { kPtr in
                CC_SHA1(sPtr, UInt32(SPadded.count), kPtr)
            }
        }
        self.K = K
        
        return M1.base64EncodedString()
    }
    
    public func verifySession(M2:String) -> Bool {
        guard let M2Decoded = Data(base64Encoded:M2) else {
            return false
        }
        return M2Decoded == self.M2
    }
}



func BN_bn2binpad(_ bn: UnsafeMutablePointer<BIGNUM>, minLength:Int) -> Data {
    let bnLength = BN_num_bytes(bn)
    var bnData = Data(count: bnLength)
    let _ = bnData.withUnsafeMutableBytes() { ptr in
        BN_bn2bin(bn, ptr)
    }
    if bnLength < minLength {
        let padding = Data(count:minLength - bnLength)
        return padding + bnData
    } else {
        return bnData
    }
}

func BN_num_bytes(_ bn: UnsafeMutablePointer<BIGNUM>) -> Int {
    return (Int(BN_num_bits(bn)) + 7) / 8
}

var standardError = FileHandle.standardError

extension FileHandle : TextOutputStream {
    public func write(_ string: String) {
        guard let data = string.data(using: .utf8) else { return }
        self.write(data)
    }
}

func printError(_ msg:String) {
    print(msg, to:&standardError)
}

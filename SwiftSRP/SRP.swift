//
//  SRP.swift
//  SwiftSRP
//
//  Created by Joseph Ross on 1/26/17.
//  Copyright © 2017 Joseph Ross. All rights reserved.
//

import Foundation

public class SRPVerifier {
    
    private let salt:Data
    private let verificationKey:Data
    private var ver:OpaquePointer?
    
    public init?(password:String) {
        var saltPtr:UnsafePointer<UInt8>? = nil
        var saltLength:Int32 = 0
        var verificationKeyPtr:UnsafePointer<UInt8>? = nil
        var verificationKeyLength:Int32 = 0
        srp_create_salted_verification_key(SRP_SHA256, SRP_NG_8192, "user", password, Int32(password.characters.count), &saltPtr, &saltLength, &verificationKeyPtr, &verificationKeyLength, nil, nil)
        
        guard let vPtr = verificationKeyPtr, let sPtr = saltPtr else {
            return nil
        }
        verificationKey = Data(bytes:vPtr, count:Int(verificationKeyLength))
        salt = Data(bytes:sPtr, count:Int(saltLength))
        
        print("salt: \(salt.base64EncodedString()), verificationKey: \(verificationKey.base64EncodedString())")
    }
    
    deinit {
        srp_verifier_delete(ver)
    }
    
    public func startVerification(a:String) -> (b:String, salt:String)? {
        guard let aData = Data(base64Encoded: a) else {
            return nil
        }
        return aData.withUnsafeBytes { (aPtr:UnsafePointer<UInt8>) -> (b:String, salt:String)? in
            return salt.withUnsafeBytes { (saltPtr:UnsafePointer<UInt8>) -> (b:String, salt:String)? in
                return verificationKey.withUnsafeBytes { (verificationKeyPtr:UnsafePointer<UInt8>) -> (b:String, salt:String)? in
                    
                    var bPtr:UnsafePointer<UInt8>? = nil
                    var bLength:Int32 = 0
                    
                    guard let ver = srp_verifier_new( SRP_SHA256, SRP_NG_8192, "user", saltPtr, Int32(salt.count), verificationKeyPtr, Int32(verificationKey.count),
                                                      aPtr, Int32(aData.count), &bPtr, &bLength, nil, nil ),
                    let solidBPtr = bPtr, bLength > 0 else {
                                                        return nil
                    }
                    self.ver = ver
                    return (b:Data(bytes:solidBPtr, count:Int(bLength)).base64EncodedString(), salt:salt.base64EncodedString())
                }
            }
        }
    }
    
    public func verifySession(m:String) -> String? {
        guard let ver = self.ver else {
            //Verification was not started correctly
            return nil
        }
        guard let mData = Data(base64Encoded: m) else {
            // Couldn't decode M
            return nil
        }
        return mData.withUnsafeBytes { (mPtr:UnsafePointer<UInt8>) -> String? in
            var hamkPtr:UnsafePointer<UInt8>? = nil
            srp_verifier_verify_session(ver, mPtr, &hamkPtr)
            guard let solidHamkPtr = hamkPtr else {
                return nil
            }
            return Data(bytes:solidHamkPtr, count:mData.count).base64EncodedString()
        }
    }
    
    public var sessionKey:Data? {
        guard let ver = ver else {
            //Verification was not started correctly
            return nil
        }
        
        var keyLength:Int32 = 0
        guard let keyPtr = srp_verifier_get_session_key(ver, &keyLength), keyLength > 0 else {
            //Couldn't fetch session key
            return nil
        }
        return Data(bytes: keyPtr, count:Int(keyLength))
    }
}

public class SRPUser {
    private let usr:OpaquePointer
    public init?(password:String) {
        guard let usr =  srp_user_new( SRP_SHA256, SRP_NG_8192, "user", password,
                                       Int32(password.characters.count), nil, nil ) else {
                                        return nil
        }
        
        self.usr = usr
    }
    
    deinit {
        srp_user_delete(usr)
    }
    
    public func startAuthentication() -> String? {
        var aPtr:UnsafePointer<UInt8>? = nil
        var aLength:Int32 = 0
        var authUsernamePtr:UnsafePointer<Int8>? = nil
        srp_user_start_authentication(usr, &authUsernamePtr, &aPtr, &aLength)
        guard let solidAPtr = aPtr, aLength > 0 else {
            return nil
        }
        return Data(bytes:solidAPtr, count:Int(aLength)).base64EncodedString()
    }
    
    public func processChallenge(b:String, salt:String) -> String? {
        var mPtr:UnsafePointer<UInt8>? = nil
        var mLength:Int32 = 0
        
        guard let bData = Data(base64Encoded: b), let saltData = Data(base64Encoded:salt) else {
            // Couldn't decode b and salt
            return nil
        }
        return bData.withUnsafeBytes { (bPtr:UnsafePointer<UInt8>) -> String? in
            saltData.withUnsafeBytes { (saltPtr:UnsafePointer<UInt8>) -> String? in
                srp_user_process_challenge(self.usr, saltPtr, Int32(saltData.count), bPtr, Int32(bData.count), &mPtr, &mLength)
                guard let solidMPtr = mPtr, mLength > 0 else {
                    return nil
                }
                return Data(bytes:solidMPtr, count:Int(mLength)).base64EncodedString()
            }
        }
    }
    
    public func verifySession(hamk:String) -> Bool {
        guard let hamkData = Data(base64Encoded: hamk) else {
            // Couldn't decode HAMK
            return false
        }
        hamkData.withUnsafeBytes { (hamkPtr:UnsafePointer<UInt8>) -> Void in
            srp_user_verify_session(usr, hamkPtr)
        }
        return srp_user_is_authenticated(usr) != 0
    }
    
    public var sessionKey:Data? {
        var keyLength:Int32 = 0
        guard let keyPtr = srp_user_get_session_key(usr, &keyLength), keyLength > 0 else {
            //Couldn't fetch session key
            return nil
        }
        return Data(bytes: keyPtr, count:Int(keyLength))
    }
}

//
//  JuneSRP.swift
//  SwiftSRP
//
//  Created by Joseph Ross on 4/25/21.
//  Copyright © 2021 Joseph Ross. All rights reserved.
//

import Foundation
import SRP
import CryptoKit

public class JuneSrpVerifier {
    private let configuration = SRPConfiguration<Insecure.SHA1>(.N8192)
    private let server: SRPServer<Insecure.SHA1>
    private let serverKeys: SRPKeyPair
    
    private let salt:Data
    private let verifier: SRPKey
    
    public private(set) var secret:Data? = nil
    private var AData:Data? = nil
    private var BData:Data? = nil
    private var M1:Data? = nil
    private var M2:Data? = nil
    
    public init?(password:String) {
        server = SRPServer(configuration: configuration)
        
        let (salt, verifier) = SRPClient(configuration: configuration).generateSaltAndVerifier(username: "user", password: password)
        self.salt = Data(salt)
        self.verifier = verifier
        serverKeys = server.generateKeys(verifier: verifier)
    }
    
    public func startVerification(A A64:String) -> (B:String, s:String)? {
        guard let AData = Data(base64Encoded: A64) else {
            return nil
        }
        self.AData = AData
        
        let clientPublicKey = SRPKey([UInt8](AData))
        
        do  {
            let serverSharedSecret = try server.calculateSharedSecret(
                clientPublicKey: clientPublicKey,
                serverKeys: serverKeys,
                verifier: verifier
            )
            secret = Data(serverSharedSecret.bytes)
        } catch {
            assertionFailure("Failed to calculate shared secret: \(error)")
            return nil
        }
        
        let BData = Data(serverKeys.public.bytes)
        self.BData = BData
        
        return (B: BData.base64EncodedString(), s: self.salt.base64EncodedString())
        
    }
    
    public func verifySession(M1 M164:String) -> String? {
        guard let AData = AData, let BData = BData, let SData = secret else {
            assertionFailure("Not ready to verify session")
            return nil
        }
        
        guard let M1Data = Data(base64Encoded: M164) else {
            assertionFailure("Couldn't decode M1: \(M164)")
            return nil
        }
        
        let paddedLength = server.configuration.N.data.count
        
        // Calculate M1
        let ABSData = AData + BData + SData
        let M1Digest = Insecure.SHA1.hash(data: ABSData)
        let M1 = Data(M1Digest)
        self.M1 = M1
        
        
        // Calculate M2
        let padding = Data(count:paddedLength - M1.count)
        let AM1SData = AData + padding + M1 + SData
        let M2Digest = Insecure.SHA1.hash(data: AM1SData)
        let M2 = Data(M2Digest)
        self.M2 = M2
        
        guard M1Data == M1, let M2 = self.M2 else {
            assertionFailure("M1 doesn't match.  \(M164) != \(M1.base64EncodedString())")
            // M1 doesn't match, or M2 is not available.
            return nil
        }
        return M2.base64EncodedString()
        
    }
}

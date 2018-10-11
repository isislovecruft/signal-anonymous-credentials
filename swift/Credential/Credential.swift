//
//  Credential.swift
//  Credential
//
//  Created by isis on 10/9/18, with the utmost apologies to my future readers
//  as this was my first time writing Swift.
//
//  Copyright © 2018 Signal. All rights reserved.
//

import Foundation

class SystemParameters {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_SYSTEM_PARAMETERS))
    
    func create(seed: [UInt8]) -> Self? {
        guard seed.count == 32 else { return nil }
        
        let buffer = system_parameters_create(H)
        
        self.data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
        return self
    }
}

class AlgebraicMACKeypair {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_ISSUER_KEYPAIR))
    
    init?(withBytes bytes: [UInt8]) {
        guard bytes.count == LENGTH_ISSUER_KEYPAIR else { return }
        
        self.data = bytes
    }
}

class ElGamalKeypair {
    var data = [UInt8](repeating: 0, count: Int(64))
    
    init?(withBytes bytes: [UInt8]) {
        guard bytes.count == 64 else { return }
        
        self.data = bytes
    }
}

class IssuerParameters {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_ISSUER_PARAMETERS))

    init?(withBytes bytes: [UInt8]) {
        guard bytes.count == LENGTH_ISSUER_KEYPAIR else { return }
        
        self.data = bytes
    }
}

class CredentialRequest {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_CREDENTIAL_REQUEST))
    
    init?(withBytes bytes: [UInt8]) {
        guard bytes.count == LENGTH_CREDENTIAL_REQUEST else { return }
        
        self.data = bytes
    }
}

class CredentialIssuance {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_CREDENTIAL_ISSUANCE))
    
    init?(withBytes bytes: [UInt8]) {
        guard bytes.count == LENGTH_CREDENTIAL_ISSUANCE else { return }
        
        self.data = bytes
    }
}

class CredentialPresentation {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_CREDENTIAL_PRESENTATION))
    
    init?(withBytes bytes: [UInt8]) {
        guard bytes.count == LENGTH_CREDENTIAL_PRESENTATION else { return }
        
        self.data = bytes
    }
}

class VerifiedCredential {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_VERIFIED_CREDENTIAL))
    
    init?(withBytes bytes: [UInt8]) {
        guard bytes.count == LENGTH_VERIFIED_CREDENTIAL else { return }
        
        self.data = bytes
    }
}

class SignalIssuer {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_ISSUER))
    
    init?(withSeed seed: [UInt8], system_parameters: SystemParameters) {
        guard seed.count == 32 else { return nil }
        
        let buffer = issuer_create(&system_parameters.data, UInt64(system_parameters.data.count), seed)
        self.data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
    }

    init(withKeypair keypair: AlgebraicMACKeypair, system_parameters: SystemParameters) {
        let buffer = issuer_new(&system_parameters.data, UInt64(system_parameters.data.count),
                                &keypair.data, UInt64(keypair.data.count))
        self.data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
    }
    
    // XXX cache this
    func get_keypair() -> AlgebraicMACKeypair? {
        let buffer = issuer_get_keypair(&self.data, UInt64(self.data.count))
        let data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
        let keypair = AlgebraicMACKeypair(withBytes: data)
        
        return keypair
    }
    
    // XXX cache this
    func get_parameters() -> IssuerParameters? {
        let buffer = issuer_get_issuer_parameters(&self.data, UInt64(self.data.count))
        let data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
        let issuer_parameters = IssuerParameters(withBytes: data)
        
        return issuer_parameters
    }

    func issue(request: CredentialRequest,
               phone_number: [UInt8],
               seed: [UInt8]) -> CredentialIssuance? {
        guard seed.count == 32 else { return nil }
        
        let buffer = issuer_issue(&self.data, UInt64(self.data.count), seed,
                                  &request.data, UInt64(request.data.count),
                                  phone_number, UInt64(phone_number.count))
        let data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
        let issuance = CredentialIssuance(withBytes: data)
        
        return issuance
    }

    func verify(presentation: CredentialPresentation) -> VerifiedCredential? {
        let buffer = issuer_verify(&self.data, UInt64(self.data.count),
                                   &presentation.data, UInt64(presentation.data.count))
         let data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
        let verified = VerifiedCredential(withBytes: data)
        
        return verified
    }
}


class User {
    var data = [UInt8](repeating: 0, count: Int(LENGTH_USER))
    
    init?(withSeed seed: [UInt8],
          system_parameters: SystemParameters,
          keypair: ElGamalKeypair?,
          phone_number: [UInt8],
          issuer_parameters: IssuerParameters) {
        // XXX export these lengths from C
        guard seed.count == 32 else { return nil }
        guard keypair?.data.count == 64 else { return nil }
 
        let buffer = user_new(&system_parameters.data, UInt64(system_parameters.data.count),
                              keypair?.data ?? nil, UInt64(keypair?.data.count ?? 0),
                              phone_number, UInt64(phone_number.count),
                              &issuer_parameters.data, UInt64(issuer_parameters.data.count),
                              seed)
        
        self.data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
    }
    
    func obtain() -> CredentialRequest? {
        let buffer = user_obtain(&self.data, UInt64(self.data.count))
        
        let data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
        let request = CredentialRequest(withBytes: data)
        
        return request
    }
    
    func obtain_finish(issuance: CredentialIssuance) {
        let buffer = user_obtain_finish(&self.data, UInt64(self.data.count),
                                        &issuance.data, UInt64(issuance.data.count))
        
        self.data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
    }

    func show(seed: [UInt8]) -> CredentialPresentation? {
        guard seed.count == 32 else { return nil }
        
        let buffer = user_show(&self.data, UInt64(self.data.count), seed)
        let data = buffer.ptr.withMemoryRebound(to: UInt8.self, capacity: Int(buffer.len)) {
            Array(UnsafeBufferPointer(start: $0, count: Int(buffer.len)))
        }
        let presentation = CredentialPresentation(withBytes: data)
        
        return presentation
    }
}

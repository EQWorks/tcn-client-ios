//
//  Created by Zsombor Szabo on 03/04/2020.
//  

import Foundation
#if canImport(CryptoKit)
import CryptoKit
//#else
//import CommonCrypto
#endif

import CommonCrypto

@available(iOS 13.0, *)
extension SHA256.Digest: DataRepresentable {}

extension UInt8: DataRepresentable {}
extension UInt16: DataRepresentable {}
extension MemoType: DataRepresentable {}

public let H_TCK_DOMAIN_SEPARATOR = "H_TCK".data(using: .utf8)!
public let H_TCN_DOMAIN_SEPARATOR = "H_TCN".data(using: .utf8)!


public protocol PublicPrivateKeyPair {

    var privateKey: Data { get }
    var publicKey: Data { get }

    func signature<D>(for data: D) throws -> Data where D : DataProtocol
}

@available(iOS 13.0, *)
struct CryptoKitEllipticCurveKeyPair: PublicPrivateKeyPair {

    private let curve25519PrivateKey = Curve25519.Signing.PrivateKey()

    var privateKey: Data { return curve25519PrivateKey.rawRepresentation }
    var publicKey: Data { return curve25519PrivateKey.publicKey.rawRepresentation }

    func signature<D>(for data: D) throws -> Data where D : DataProtocol {
        return try curve25519PrivateKey.signature(for: data)
    }
}

extension UUID {

    func asData() -> Data {
        return withUnsafePointer(to: self.uuid) { Data(bytes: $0, count: MemoryLayout.size(ofValue: self.uuid)) }
    }
}

// TODO: mark as iOS12 only and deprecated on iOS 13
struct SecKeyEllipticCurveKeyPair: PublicPrivateKeyPair {

    // TODO: TMP impl
    private let curvePrivateKey = UUID().asData()
    private let curvePublicKey = UUID().asData() + UUID().asData()

    var privateKey: Data { return curvePrivateKey }
    var publicKey: Data { return curvePublicKey }

    func signature<D>(for data: D) throws -> Data where D : DataProtocol {
        // TODO: tmp impl
        return data as! Data
    }


}

public enum CryptoProvider {

    public static func generateKeyPair() -> PublicPrivateKeyPair {
        if #available(iOS 13.0, *) {
            return CryptoKitEllipticCurveKeyPair()
        } else {
            return SecKeyEllipticCurveKeyPair()
        }
    }

    public static func sha256(data : Data) -> Data {
        if #available(iOS 13.0, *) {
            return SHA256.hash(data: data).dataRepresentation
        } else {
            var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
            data.withUnsafeBytes {
                _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
            }
            return Data(hash)
        }
    }

    static func isValidSignature<S, D, K>(key: K, _ signature: S, for data: D) throws -> Bool where S : DataProtocol, D : DataProtocol, K : ContiguousBytes {
        if #available(iOS 13.0, *) {
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: key)
            return publicKey.isValidSignature(signature, for: data)
        } else {
            // TODO: tmp impl
            return true
        }
    }

}

/// Authorizes publication of a report of potential exposure.
public struct ReportAuthorizationKey: Equatable {

    /// Initialize a new report authorization key from a random number generator.
    internal let keyPair: PublicPrivateKeyPair

    /// Compute the initial temporary contact key derived from this report authorization key.
    ///
    /// Note: this returns `tck_1`, the first temporary contact key that can be used to generate tcks.
    public var initialTemporaryContactKey: TemporaryContactKey {
        return self.tck_0.ratchet()! // It's safe to unwrap.
    }
    
    /// This is internal because tck_0 shouldn't be used to generate a TCN.
    var tck_0: TemporaryContactKey {
        return TemporaryContactKey(
            index: 0,
            reportVerificationPublicKeyBytes: keyPair.publicKey,
            bytes: CryptoProvider.sha256(data: H_TCK_DOMAIN_SEPARATOR + keyPair.privateKey)
        )
    }
    
    public init(keyPair: PublicPrivateKeyPair = CryptoProvider.generateKeyPair()) {
        self.keyPair = keyPair
    }
    
    public static func == (
        lhs: ReportAuthorizationKey,
        rhs: ReportAuthorizationKey
    ) -> Bool {
        return lhs.keyPair.privateKey == rhs.keyPair.privateKey
    }
    
}

/// A pseudorandom 128-bit value broadcast to nearby devices over Bluetooth.
public struct TemporaryContactNumber: Equatable {
    
    /// The 16 bytes of the temporary contact number.
    public var bytes: Data
    
    public init(bytes: Data) {
        self.bytes = bytes
    }
    
}

/// A ratcheting key used to derive temporary contact numbers.
public struct TemporaryContactKey: Equatable {
    
    /// The current ratchet index.
    public var index: UInt16
    
    /// The 32 bytes of the ed25519 public key used for report verification.
    public var reportVerificationPublicKeyBytes: Data
    
    /// The 32 bytes of the temporary contact key.
    public var bytes: Data
    
    /// Compute the temporary contact number derived from this key.
    public var temporaryContactNumber: TemporaryContactNumber {
        return TemporaryContactNumber(
            bytes: CryptoProvider.sha256(
                data: H_TCN_DOMAIN_SEPARATOR + index.dataRepresentation + bytes
            )[0..<16]
        )
    }
    
    public init(
        index: UInt16, reportVerificationPublicKeyBytes: Data,
        bytes: Data
    ) {
        self.index = index
        self.reportVerificationPublicKeyBytes = reportVerificationPublicKeyBytes
        self.bytes = bytes
    }
    
    /// Ratchet the key forward, producing a new key for a new temporary contact number.
    /// - Returns: A new temporary contact key if `index` is less than `UInt16.max`, nil
    ///     otherwise, signaling that the report authorization key should be rotated.
    public func ratchet() -> TemporaryContactKey? {
        guard index < .max else {
            return nil
        }
        
        let nextBytes = CryptoProvider.sha256(
            data: H_TCK_DOMAIN_SEPARATOR + reportVerificationPublicKeyBytes + bytes
        )
        
        return TemporaryContactKey(
            index: index + 1,
            reportVerificationPublicKeyBytes: reportVerificationPublicKeyBytes,
            bytes: nextBytes
        )
    }
    
}

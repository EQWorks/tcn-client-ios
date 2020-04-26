//
//  Created by Eugene Kolpakov on 2020-04-25.
//

import Foundation
import CommonCrypto

#if canImport(CryptoKit)
import CryptoKit
#endif

@available(iOS 13.0, *)
extension SHA256.Digest: DataRepresentable {}

public class CryptoLib {

    public static func generateKeyPair() -> AsymmetricKeyPair {
        if #available(iOS 13.0, *) {
            return CryptoKitEllipticCurveKeyPair()
        } else {
            return SecKeyEllipticCurveKeyPair()
        }
    }

    public static func restoreKeyPair(serializedData: Data) throws -> AsymmetricKeyPair {
        if #available(iOS 13.0, *) {
            return try CryptoKitEllipticCurveKeyPair(rawRepresentation: serializedData)
        } else {
            return try SecKeyEllipticCurveKeyPair(rawRepresentation: serializedData)
        }
    }

    public static func sha256(data : Data) -> Data {
        if #available(iOS 13.0, *) {
            return SHA256.hash(data: data).dataRepresentation
        } else {
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
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

public protocol AsymmetricKeyPair {

    var privateKey: Data { get }
    var publicKey: Data { get }

    func signature<D>(for data: D) throws -> Data where D : DataProtocol
}

@available(iOS 13.0, *)
struct CryptoKitEllipticCurveKeyPair: AsymmetricKeyPair {

    private let curve25519PrivateKey: Curve25519.Signing.PrivateKey

    var privateKey: Data { return curve25519PrivateKey.rawRepresentation }
    var publicKey: Data { return curve25519PrivateKey.publicKey.rawRepresentation }

    init() {
        curve25519PrivateKey = Curve25519.Signing.PrivateKey()
    }

    init(rawRepresentation: Data) throws {
        curve25519PrivateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rawRepresentation)
    }

    func signature<D>(for data: D) throws -> Data where D : DataProtocol {
        return try curve25519PrivateKey.signature(for: data)
    }
}

extension UUID {

    func asData() -> Data {
        return withUnsafePointer(to: self.uuid) { Data(bytes: $0, count: MemoryLayout.size(ofValue: self.uuid)) }
    }
}

@available(iOS, introduced: 12.0, deprecated: 13.0, message: "Use CryptoKitEllipticCurveKeyPair on iOS 13")
struct SecKeyEllipticCurveKeyPair: AsymmetricKeyPair {

    private let curvePrivateKey: Data
    private let curvePublicKey: Data

    var privateKey: Data { return curvePrivateKey }
    var publicKey: Data { return curvePublicKey }

    init() {
        // TODO: TMP impl
        curvePrivateKey = UUID().asData()
        curvePublicKey = UUID().asData() + UUID().asData()
    }

    init(rawRepresentation: Data) throws {
        // TODO: TMP impl
        curvePrivateKey = rawRepresentation
        curvePublicKey = rawRepresentation + rawRepresentation
    }

    func signature<D>(for data: D) throws -> Data where D : DataProtocol {
        // TODO: tmp impl
        return data as! Data
    }
}


import Foundation
import Security
import UIKit

class Rsa {

    let tag = UIDevice.current.identifierForVendor!.uuidString //.data(using: .utf8)
    var privateKey: SecKey?

// MARK: - Initialization
    init() {
        guard let privateKey = getPrivateKeyFromKeychain() else {
            generatePrivateKey()
            return
        }
        self.privateKey = privateKey
    }

// MARK: - Private methods
    private func generatePrivateKey() {
        let attributes = getPrivateKeyAttributes()
        var error: Unmanaged<CFError>?
        guard let privateKey: SecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("Error generating private key: \(error.debugDescription)")
        }
        self.privateKey = privateKey
   }

    private func generatePublicKey(privateKey: SecKey) -> SecKey? {
        let publicKey: SecKey? = SecKeyCopyPublicKey(privateKey)
        return publicKey
    }

    private func getPublicKeyToExport(publicKey: SecKey) -> String {
        guard 
            SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionPKCS1),
            let keyData: CFData = SecKeyCopyExternalRepresentation(publicKey, nil)
        else { return "" }
        let keyBase64: String = (keyData as Data).base64EncodedString()
        return keyBase64
    }

    private func decodePublicKeyFromBase64(keyBase64: String) -> SecKey? {
        guard
            let keyData: Data = Data(base64Encoded: keyBase64),
            let key: SecKey = SecKeyCreateWithData(keyData as CFData, [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic
            ] as CFDictionary, nil)
        else { return nil }
        return key
    }

    private func getPrivateKeyFromKeychain() -> SecKey? {
        let query: CFDictionary = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ] as CFDictionary
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return item as! SecKey?
    }


    private func getPrivateKeyAttributes() -> CFDictionary {
        let attributes: CFDictionary = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!
            ]
        ] as CFDictionary
        return attributes
    }

// MARK: - Encreption/Decryption
    func encrypt(data: Data?, keyBase64: String) -> Data? {
        guard 
            let publicKey: SecKey = decodePublicKeyFromBase64(keyBase64: keyBase64),
            SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionPKCS1),
            let data: Data = data
        else { return nil }
        var error: Unmanaged<CFError>?
        guard let encryptedData: Data = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, &error) as? Data else {
            fatalError("Error encrypting data: \(error.debugDescription)")
        }
        return encryptedData
    }

    func decrypt(data: Data?) -> Data? {
        guard
            let privateKey: SecKey = privateKey,
            SecKeyIsAlgorithmSupported(privateKey, .decrypt, .rsaEncryptionPKCS1),
            let data: Data = data
        else { return nil }
        var error: Unmanaged<CFError>?
        guard let decryptedData: Data = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, data as CFData, &error) as? Data else {
            fatalError("Error decrypting data: \(error.debugDescription)")
        }
        return decryptedData
    }

// MARK: - Public key update on server 
    func updatePubKeyOnServer() {
        guard
            let privateKey: SecKey,
            let publicKey: SecKey = generatePublicKey(privateKey: privateKey),
            let pubKey: String = getPublicKeyToExport(publicKey: publicKey)
        else { return }
        // TODO: update pub key on server
    }
}

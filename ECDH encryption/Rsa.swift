
// Rsa class which generates a public private key pair and encrypts and decrypts data using the public key and private key respectively.
class Rsa {

    let tag = UIdevice.current.identifierForVendor!.uuidString

    let publicKey: SecKey
    let privateKey: SecKey

    init() {
        guard let privateKey = getPrivateKeyFromKeychain() else {
            generateKeys()
            return
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            fatalError("Error generating public key")
        }
        self.privateKey = privateKey
        self.publicKey = publicKey
        updatePubKeyOnServer()
    }

   // func generates public private key
   func generateKeys() { 
    let attributes = getPrivateKeyAttributes()
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        fatalError("Error generating private key: \(error.debugDescription)")
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        fatalError("Error generating public key")
    }
    self.publicKey = publicKey
    self.privateKey = privateKey
   }

   // decode public key
    func getPublicKey() -> String {
        let keyData = SecKeyCopyExternalRepresentation(privateKey)! as Data
        let keyBase64 = keyData.base64EncodedString()
        return keyBase64
    } 

   // func get private key from keychain
    func getPrivateKeyFromKeychain() -> SecKey? {
        let query: CFDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag.data(using: .utf8)!,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecReturnRef: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return item as! SecKey?
    }

   // func encrypts data using public key
    func encrypt(data: Data) -> Data? {
    
    }

    // func decrypts data using private key
    func decrypt(data: Data) -> Data? {

    
    }

    // func gets attributes of private key
    func getPrivateKeyAttributes() -> CFdictionary {
        let attributes: CFdictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag.data(using: .utf8)!
            ]
        ]
        return attributes 
    }
    func updatePubKeyOnServer() {

    }
}
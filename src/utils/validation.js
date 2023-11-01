class ValidationService {
  /**
   * Check the validity of a local ECDH public key JSON Web Key (JWK).
   * 
   * @param {Object} localECDHPublicKeyJWK - the local ECDH public key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidLocalECDHPublicKeyJWK(localECDHPublicKeyJWK) {
    if (
      !localECDHPublicKeyJWK ||
      typeof localECDHPublicKeyJWK !== 'object' ||
      localECDHPublicKeyJWK.kty !== 'EC' ||
      localECDHPublicKeyJWK.crv !== "P-521" ||
      (localECDHPublicKeyJWK.x && localECDHPublicKeyJWK.x.length !== 88) ||
      (localECDHPublicKeyJWK.y && localECDHPublicKeyJWK.y.length !== 88) ||
      (localECDHPublicKeyJWK.keyOps && localECDHPublicKeyJWK.keyOps.length === 0)
    ) {
      throw new Error('Failed to generate a valid local ECDH public key JWK');
    }
  }

  /**
   * Check the validity of a local ECDH private key JSON Web Key (JWK).
   * 
   * @param {Object} localECDHPrivateKeyJWK - the local ECDH private key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidLocalECDHPrivateKeyJWK(localECDHPrivateKeyJWK) {
    if (
      !localECDHPrivateKeyJWK ||
      typeof localECDHPrivateKeyJWK !== 'object' ||
      localECDHPrivateKeyJWK.kty !== 'EC' ||
      localECDHPrivateKeyJWK.crv !== "P-521" ||
      (localECDHPrivateKeyJWK.x && localECDHPrivateKeyJWK.x.length !== 88) ||
      (localECDHPrivateKeyJWK.y && localECDHPrivateKeyJWK.y.length !== 88) ||
      (localECDHPrivateKeyJWK.d && localECDHPrivateKeyJWK.d.length !== 88) ||
      !(localECDHPrivateKeyJWK.key_ops && localECDHPrivateKeyJWK.key_ops.includes("deriveKey"))
    ) {
      throw new Error('Failed to generate a valid local ECDH private key JWK');
    }
  }

  /**
   * Check the validity of a local ECDH private key wrapping key JSON Web Key (JWK).
   * 
   * @param {Object} localECDHPrivateKeyWrappingKeyJWK - the local ECDH private key wrapping key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidLocalECDHPrivateKeyWrappingKeyJWK(localECDHPrivateKeyWrappingKeyJWK) {
    if (
      !localECDHPrivateKeyWrappingKeyJWK ||
      typeof localECDHPrivateKeyWrappingKeyJWK !== 'object' ||
      localECDHPrivateKeyWrappingKeyJWK.alg !== 'A256GCM' ||
      (localECDHPrivateKeyWrappingKeyJWK.k && localECDHPrivateKeyWrappingKeyJWK.k.length !== 43) ||
      localECDHPrivateKeyWrappingKeyJWK.kty !== 'oct' ||
      !localECDHPrivateKeyWrappingKeyJWK.key_ops?.includes("wrapKey") ||
      !localECDHPrivateKeyWrappingKeyJWK.key_ops?.includes("unwrapKey")
    ) {
      throw new Error('Failed to generate a valid local ECDH private key wrapping key JWK');
    }
  }

  /**
   * Check the validity of a master key wrapping key JSON Web Key (JWK).
   * 
   * @param {Object} masterKeyWrappingKeyJWK - the master key wrapping key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterKeyWrappingKeyJWK(masterKeyWrappingKeyJWK) {
    if (
      !masterKeyWrappingKeyJWK ||
      typeof masterKeyWrappingKeyJWK !== 'object' ||
      masterKeyWrappingKeyJWK.alg !== 'A256GCM' ||
      (masterKeyWrappingKeyJWK.k && masterKeyWrappingKeyJWK.k.length !== 43) ||
      masterKeyWrappingKeyJWK.kty !== 'oct' ||
      !(masterKeyWrappingKeyJWK.key_ops && masterKeyWrappingKeyJWK.key_ops.includes("wrapKey")) ||
      !(masterKeyWrappingKeyJWK.key_ops && masterKeyWrappingKeyJWK.key_ops.includes("unwrapKey"))
    ) {
      throw new Error('Failed to generate a valid master key wrapping key AES256GCM JWK');
    }
  }

  /**
   * Check the validity of a wrapped local ECDH private key JSON Web Key (JWK).
   * 
   * @param {ArrayBuffer} wrappedLocalECDHPrivateKeyJWK - the wrapped local ECDH private key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidWrappedLocalECDHPrivateKeyJWK(wrappedLocalECDHPrivateKeyJWK) {
    if (
      !wrappedLocalECDHPrivateKeyJWK ||
      !(wrappedLocalECDHPrivateKeyJWK instanceof ArrayBuffer) ||
      wrappedLocalECDHPrivateKeyJWK.byteLength !== 362
    ) {
      throw new Error('Failed to wrap the local ECDH private key JWK');
    }
  }

  /**
   * Check the validity of a wrapped master key.
   * 
   * @param {ArrayBuffer} wrappedMasterKeyJWK - the wrapped master key to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidWrappedMasterKey(wrappedMasterKeyJWK) {
    if (
      !wrappedMasterKeyJWK ||
      !(wrappedMasterKeyJWK instanceof ArrayBuffer) ||
      wrappedMasterKeyJWK.byteLength !== 138
    ) {
      throw new Error('Failed to wrap the master key');
    }
  }

  /**
   * Check the validity of a master ECDH public key JSON Web Key (JWK).
   * 
   * @param {Object} masterECDHPublicKeyJWK - the master ECDH public key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterECDHPublicKeyJWK(masterECDHPublicKeyJWK) {
    if (
      !masterECDHPublicKeyJWK ||
      typeof masterECDHPublicKeyJWK !== 'object' ||
      masterECDHPublicKeyJWK.kty !== 'EC' ||
      masterECDHPublicKeyJWK.crv !== "P-521" ||
      (masterECDHPublicKeyJWK.x && masterECDHPublicKeyJWK.x.length !== 88) ||
      (masterECDHPublicKeyJWK.y && masterECDHPublicKeyJWK.y.length !== 88) ||
      (masterECDHPublicKeyJWK.key_ops && masterECDHPublicKeyJWK.key_ops.length !== 0)
    ) {
      throw new Error('The master ECDH public key is not a valid EC P-521 JWK');
    }
  }

  /**
   * Check the validity of a master ECDH private key JSON Web Key (JWK).
   * 
   * @param {Object} masterECDHPrivateKeyJWK - the master ECDH private key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterECDHPrivateKeyJWK(masterECDHPrivateKeyJWK) {
    if (
      !masterECDHPrivateKeyJWK ||
      typeof masterECDHPrivateKeyJWK !== 'object' ||
      masterECDHPrivateKeyJWK.kty !== 'EC' ||
      masterECDHPrivateKeyJWK.crv !== "P-521" ||
      (masterECDHPrivateKeyJWK.x && masterECDHPrivateKeyJWK.x.length !== 88) ||
      (masterECDHPrivateKeyJWK.y && masterECDHPrivateKeyJWK.y.length !== 88) ||
      (masterECDHPrivateKeyJWK.d && masterECDHPrivateKeyJWK.d.length !== 88) ||
      !(masterECDHPrivateKeyJWK.key_ops && masterECDHPrivateKeyJWK.key_ops.includes("deriveKey"))
    ) {
      throw new Error('The master ECDH private key is not a valid EC P-521 JWK');
    }
  }

  /**
   * Check the validity of a master key JSON Web Key (JWK).
   * 
   * @param {Object} masterKeyJWK - the master key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterKeyJWK(masterKeyJWK) {
    if (
      !masterKeyJWK ||
      typeof masterKeyJWK !== 'object' ||
      masterKeyJWK.alg !== 'A256GCM' ||
      (masterKeyJWK.k && masterKeyJWK.k.length !== 43) ||
      masterKeyJWK.kty !== 'oct' ||
      !(masterKeyJWK.key_ops && masterKeyJWK.key_ops.includes("encrypt")) ||
      !(masterKeyJWK.key_ops && masterKeyJWK.key_ops.includes("decrypt"))
    ) {
      throw new Error('The master key is not a valid AES256GCM JWK');
    }
  }
}
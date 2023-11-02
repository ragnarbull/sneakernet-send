class ValidationService {
  /**
   * Check the validity of a local ECDH public key JSON Web Key (JWK).
   * 
   * @param {JsonWebKey} key - the local ECDH public key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidLocalECDHPublicKeyJWK(key) {
    if (
      !key ||
      typeof key !== 'object' ||
      key.kty !== 'EC' ||
      key.crv !== "P-521" ||
      (key.x && key.x.length !== 88) ||
      (key.y && key.y.length !== 88) ||
      (key.keyOps && key.keyOps.length === 0)
    ) {
      throw new Error('Failed to generate a valid local ECDH public key JWK');
    }
  }

  /**
   * Check the validity of a local ECDH private key JSON Web Key (JWK).
   * 
   * @param {JsonWebKey} key - the local ECDH private key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidLocalECDHPrivateKeyJWK(key) {
    if (
      !key ||
      typeof key !== 'object' ||
      key.kty !== 'EC' ||
      key.crv !== "P-521" ||
      (key.x && key.x.length !== 88) ||
      (key.y && key.y.length !== 88) ||
      (key.d && key.d.length !== 88) ||
      !(key.key_ops && key.key_ops.includes("deriveKey"))
    ) {
      throw new Error('Failed to generate a valid local ECDH private key JWK');
    }
  }

  /**
   * Check the validity of a local ECDH private key wrapping key JSON Web Key (JWK).
   * 
   * @param {JsonWebKey} key - the local ECDH private key wrapping key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidLocalECDHPrivateKeyWrappingKeyJWK(key) {
    if (
      !key ||
      typeof key !== 'object' ||
      key.alg !== 'A256GCM' ||
      (key.k && key.k.length !== 43) ||
      key.kty !== 'oct' ||
      !(key.key_ops && key.key_ops.includes("wrapKey")) ||
      !(key.key_ops && key.key_ops.includes("unwrapKey"))
    ) {
      throw new Error('Failed to generate a valid local ECDH private key wrapping key JWK');
    }
  }

  /**
   * Check the validity of a master key wrapping key JSON Web Key (JWK).
   * 
   * @param {JsonWebKey} key - the master key wrapping key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterKeyWrappingKeyJWK(key) {
    if (
      !key ||
      typeof key !== 'object' ||
      key.alg !== 'A256GCM' ||
      (key.k && key.k.length !== 43) ||
      key.kty !== 'oct' ||
      !(key.key_ops && key.key_ops.includes("wrapKey")) ||
      !(key.key_ops && key.key_ops.includes("unwrapKey"))
    ) {
      throw new Error('Failed to generate a valid master key wrapping key AES256GCM JWK');
    }
  }

  /**
   * Check the validity of a wrapped local ECDH private key JSON Web Key (JWK).
   * 
   * @param {ArrayBuffer} wrappedKey - the wrapped local ECDH private key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidWrappedLocalECDHPrivateKeyJWK(wrappedKey) {
    if (
      !wrappedKey ||
      !(wrappedKey instanceof ArrayBuffer) ||
      wrappedKey.byteLength !== 362
    ) {
      throw new Error('Failed to wrap the local ECDH private key JWK');
    }
  }

  /**
   * Check the validity of a wrapped master key.
   * 
   * @param {ArrayBuffer} wrappedKey - the wrapped master key to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidWrappedMasterKey(wrappedKey) {
    if (
      !wrappedKey ||
      !(wrappedKey instanceof ArrayBuffer) ||
      wrappedKey.byteLength !== 138
    ) {
      throw new Error('Failed to wrap the master key');
    }
  }

  /**
   * Check the validity of a master ECDH public key JSON Web Key (JWK).
   * 
   * @param {JsonWebKey} key - the master ECDH public key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterECDHPublicKeyJWK(key) {
    if (
      !key ||
      typeof key !== 'object' ||
      key.kty !== 'EC' ||
      key.crv !== "P-521" ||
      (key.x && key.x.length !== 88) ||
      (key.y && key.y.length !== 88) ||
      (key.key_ops && key.key_ops.length !== 0)
    ) {
      throw new Error('The master ECDH public key is not a valid EC P-521 JWK');
    }
  }

  /**
   * Check the validity of a master ECDH private key JSON Web Key (JWK).
   * 
   * @param {JsonWebKey} key - the master ECDH private key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterECDHPrivateKeyJWK(key) {
    if (
      !key ||
      typeof key !== 'object' ||
      key.kty !== 'EC' ||
      key.crv !== "P-521" ||
      (key.x && key.x.length !== 88) ||
      (key.y && key.y.length !== 88) ||
      (key.d && key.d.length !== 88) ||
      !(key.key_ops && key.key_ops.includes("deriveKey"))
    ) {
      throw new Error('The master ECDH private key is not a valid EC P-521 JWK');
    }
  }

  /**
   * Check the validity of a master key JSON Web Key (JWK).
   * 
   * @param {JsonWebKey} key - the master key JWK to validate
   * @throws {Error} - Throws an error if the key is not valid.
   */
  static isValidMasterKeyJWK(key) {
    if (
      !key ||
      typeof key !== 'object' ||
      key.alg !== 'A256GCM' ||
      (key.k && key.k.length !== 43) ||
      key.kty !== 'oct' ||
      !(key.key_ops && key.key_ops.includes("encrypt")) ||
      !(key.key_ops && key.key_ops.includes("decrypt"))
    ) {
      throw new Error('The master key is not a valid AES256GCM JWK');
    }
  }
}
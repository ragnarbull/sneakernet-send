const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8');

/**
 * Generate the local ECDH key pair
 *
 * @returns {Promise<{ localECDHPublicKeyJWK: JsonWebKey, localECDHPrivateKeyJWK: JsonWebKey }>}
 */
async function generateLocalECDHKeyPairJWKs() {
  try {
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-521' }, true, ['deriveKey']);
    const localECDHPublicKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const localECDHPrivateKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return { localECDHPublicKeyJWK, localECDHPrivateKeyJWK };
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Create a symmetric encryption key used to wrap the local ECDH private key from the PRF output
 *
 * @param {Uint8Array} prfOutput
 * @param {Uint8Array} hkdfSalt
 * @returns {Promise<JsonWebKey>}
 */
async function derivelocalECDHPrivateKeyWrappingKey({ prfOutput, hkdfSalt }) {
  try {
    if (!prfOutput || !hkdfSalt) throw new Error('Input objects for derivelocalECDHPrivateKeyWrappingKey are undefined or missing.');

    const keyDerivationKey = await crypto.subtle.importKey(
      'raw',
      prfOutput,
      'HKDF',
      false,
      ['deriveKey']
    );

    if (!keyDerivationKey) throw new Error('Failed to import the key derivation key for the local ECDH private key wrapping key.');

    const localECDHPrivateKeyWrappingKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', info: textEncoder.encode('localECDHPrivateKeyWrappingKey'), salt: hkdfSalt, hash: 'SHA-256' },
      keyDerivationKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    if (!localECDHPrivateKeyWrappingKey) throw new Error('The local ECDH private key wrapping key is undefined or missing.');

    const localECDHPrivateKeyWrappingKeyJWK = await crypto.subtle.exportKey('jwk', localECDHPrivateKeyWrappingKey);
    return localECDHPrivateKeyWrappingKeyJWK;
  } catch (err) {
    console.error(err.stack);
   }
}

/**
 * Wrap the local ECDH private key with a symmetric key
 * 
 * @param {JsonWebKey} localECDHPrivateKeyJWK - The local ECDH private key to be wrapped as a JsonWebKey
 * @param {Uint8Array} wrappedLocalECDHPrivateKeyIV - The initialization vector as a Uint8Array
 * @param {JsonWebKey} localECDHPrivateKeyWrappingKeyJWK  - The local ECDH private key wrapping key as a JsonWebKey
 * @returns {Promise<ArrayBuffer}>} - A promise that resolves to the wrapped local ECDH private key as an ArrayBuffer
 */
async function wraplocalECDHPrivateKey({ localECDHPrivateKeyJWK, wrappedLocalECDHPrivateKeyIV, localECDHPrivateKeyWrappingKeyJWK }) {
  try {
    if (!localECDHPrivateKeyJWK || !wrappedLocalECDHPrivateKeyIV || !localECDHPrivateKeyWrappingKeyJWK) throw new Error('Input elements for wraplocalECDHPrivateKey are undefined or missing.');

    const importedLocalECDHPrivateKey = await crypto.subtle.importKey(
      'jwk',
      localECDHPrivateKeyJWK,
      { name: 'ECDH', namedCurve: 'P-521' },
      true,
      ['deriveKey']
    );

    if (!importedLocalECDHPrivateKey) throw new Error("Failed to import the local ECDH private key.");

    const importedLocalECDHPrivateKeyWrappingKey = await crypto.subtle.importKey(
      'jwk',
      localECDHPrivateKeyWrappingKeyJWK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    if (!importedLocalECDHPrivateKeyWrappingKey) throw new Error("Failed to import the local ECDH private key wrapping key.");

    const wrappedLocalECDHPrivateKey = await crypto.subtle.wrapKey(
      'jwk',
      importedLocalECDHPrivateKey,
      importedLocalECDHPrivateKeyWrappingKey,
      { name: 'AES-GCM', iv: wrappedLocalECDHPrivateKeyIV }
    );

    if (!wrappedLocalECDHPrivateKey) throw new Error("Failed to create the wrapped local ECDH private key.");
    return wrappedLocalECDHPrivateKey;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Generate the master wrapping key
 *
 * @param {JsonWebKey} localECDHPublicKeyJWK - The local ECDH public key as a JsonWebKey
 * @param {JsonWebKey} masterECDHPrivateKeyJWK - The master ECDH private key as a JsonWebKey
 * @returns {Promise<JsonWebKey>} - A promise that resolves to the master wrapping key as a JsonWebKey
 */
async function generateMasterKeyWrappingKey({ localECDHPublicKeyJWK, masterECDHPrivateKeyJWK }) {
  try {
    if (!localECDHPublicKeyJWK || !masterECDHPrivateKeyJWK) throw new Error('Input objects for generateMasterKeyWrappingKey are undefined or missing.');
   
    const importedPublicKey = await crypto.subtle.importKey(
      'jwk',
      localECDHPublicKeyJWK,
      { name: 'ECDH', namedCurve: 'P-521' },
      true,
      []
    );

    if (!importedPublicKey) throw new Error('Failed to import the local ECDH public key.');

    const importedBaseKey = await crypto.subtle.importKey(
      'jwk',
      masterECDHPrivateKeyJWK,
      { name: 'ECDH', namedCurve: 'P-521' },
      true,
      ['deriveKey']
    );

    if (!importedBaseKey) throw new Error('Failed to import the remote master private key.');

    const masterKeyWrappingKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedPublicKey },
      importedBaseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    if (!masterKeyWrappingKey) throw new Error('Failed to create the master key wrapping key.');
    
    const masterKeyWrappingKeyJWK = await crypto.subtle.exportKey('jwk', masterKeyWrappingKey);

    return masterKeyWrappingKeyJWK;
  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Wrap the master key with a symmetric key
 * 
 * @param {JsonWebKey} masterKeyJWK - The master key as JsonWebKey
 * @param {Uint8Array} wrappedMasterKeyIV - The initialization vector as a Uint8Array
 * @param {JsonWebKey} masterKeyWrappingKeyJWK  - The master wrapping key as a JsonWebKey
 * @returns {Promise<ArrayBuffer>} - A promise that resolves to the wrapped master key as an ArrayBuffer.
 */
async function wrapMasterKey({ masterKeyJWK, wrappedMasterKeyIV, masterKeyWrappingKeyJWK }) {
  try {
    if (!masterKeyJWK || !wrappedMasterKeyIV || !masterKeyWrappingKeyJWK) throw new Error('Input objects for wrapMasterKey are undefined or missing.');
       
    const importedMasterKey = await crypto.subtle.importKey(
      'jwk',
      masterKeyJWK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    if (!importedMasterKey) throw new Error('Failed to import the master key');
    
    const importedMasterKeyWrappingKey = await crypto.subtle.importKey(
      'jwk',
      masterKeyWrappingKeyJWK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    if (!importedMasterKeyWrappingKey) throw new Error('Failed to import the master key wrapping key');
    
    const wrappedMasterKey = await crypto.subtle.wrapKey(
      'jwk',
      importedMasterKey,
      importedMasterKeyWrappingKey,
      { name: 'AES-GCM', iv: wrappedMasterKeyIV }
    );

    if (!wrappedMasterKey) throw new Error('Failed to create the wrapped master key');
    return wrappedMasterKey;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Unwrap the local ECDH private key
 *
 * @param {ArrayBuffer} wrappedLocalECDHPrivateKeyJWK - The wrapped local ECDH private key as an ArrayBuffer.
 * @param {ArrayBuffer} wrappedLocalECDHPrivateKeyIV - The wrapped local ECDH private key initialization vector as an ArrayBuffer.
 * @param {JsonWebKey} localECDHPrivateKeyWrappingKeyJWK - The local ECDH private key wrapping key (symmetric encryption key) as a JsonWebKey.
 * @returns {Promise<JsonWebKey>} - A promise that resolves to the local ECDH private key as a JsonWebKey.
 */
async function unwrapLocalECDHPrivateKey({ wrappedLocalECDHPrivateKeyJWK, wrappedLocalECDHPrivateKeyIV, localECDHPrivateKeyWrappingKeyJWK }) {
  try {
    if (!wrappedLocalECDHPrivateKeyJWK || !wrappedLocalECDHPrivateKeyIV || !localECDHPrivateKeyWrappingKeyJWK) throw new Error('Input objects for unwrapLocalECDHPrivateKey are undefined or missing.');

    const importedWrappingKey = await crypto.subtle.importKey(
      'jwk',
      localECDHPrivateKeyWrappingKeyJWK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    if (!importedWrappingKey) throw new Error('Failed to import the local ECDH private key wrapping key.');

    const localECDHPrivateKey = await crypto.subtle.unwrapKey(
      'jwk',
      wrappedLocalECDHPrivateKeyJWK,
      importedWrappingKey,
      { // unwrapAlgo
        name: 'AES-GCM',
        iv: wrappedLocalECDHPrivateKeyIV,
        tagLength: 128
      },
      { // unwrappedKeyAlgo
        name: 'ECDH',
        namedCurve: 'P-521'
      },
      true,
      ['deriveKey']
    );

    if (!localECDHPrivateKey) throw new Error('Failed to import the local ECDH private key.');
    const keyMaterial = await crypto.subtle.exportKey('jwk', localECDHPrivateKey);
    return keyMaterial;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Derive the master wrapping key
 *
 * @param {JsonWebKey} masterECDHPublicKeyJWK - The master remote ECDH public key as aJsonWebKey
 * @param {JsonWebKey} localECDHPrivateKeyJWK - The local ECDH private key as a JsonWebKey
 * @returns {Promise<JsonWebKey>} - A promise that resolves to the master key wrapping key as a JsonWebKey
 */
async function deriveMasterKeyWrappingKey({ masterECDHPublicKeyJWK, localECDHPrivateKeyJWK }) {
  try {
    if (!masterECDHPublicKeyJWK || !localECDHPrivateKeyJWK) throw new Error('Input objects for deriveMasterWrappingKey are undefined or missing.');
   
    const importedPublicKey = await crypto.subtle.importKey(
      'jwk',
      masterECDHPublicKeyJWK,
      { name: 'ECDH', namedCurve: 'P-521' },
      true,
      []
    );

    if (!importedPublicKey) throw new Error('Failed to create the imported public key.');

    const importedBaseKey = await crypto.subtle.importKey(
      'jwk',
      localECDHPrivateKeyJWK,
      { name: 'ECDH', namedCurve: 'P-521' },
      true,
      ['deriveKey']
    );

    if (!importedBaseKey) throw new Error('Failed to create the imported private key.');

    const masterKeyWrappingKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedPublicKey },
      importedBaseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    if (!masterKeyWrappingKey) throw new Error('Failed to create the master wrapping key.');
    const masterKeyWrappingKeyJWK = await crypto.subtle.exportKey('jwk', masterKeyWrappingKey);
    return masterKeyWrappingKeyJWK;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Unrap the master key (encrypted with ECDH)
 *
 * @param {ArrayBuffer} wrappedMasterKeyJWK - The wrapped master key as an ArrayBuffer.
 * @param {ArrayBuffer} wrappedMasterKeyIV - The wrapped master key initialization vector as an ArrayBuffer.
 * @param {JsonWebKey} masterKeyWrappingKeyJWK - The encryption key as a JsonWebKey.
 * @returns {Promise<JsonWebKey>} - A promise that resolves to the master key as a JsonWebKey.
 */
async function unwrapMasterKey({ wrappedMasterKeyJWK, wrappedMasterKeyIV, masterKeyWrappingKeyJWK }) {
  try {
    if (!wrappedMasterKeyJWK || !wrappedMasterKeyIV|| !masterKeyWrappingKeyJWK) throw new Error('Input objects for unwrapMasterKey are undefined or missing.');

    const importedWrappingKey = await crypto.subtle.importKey(
      'jwk',
      masterKeyWrappingKeyJWK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    if (!importedWrappingKey) throw new Error('Failed to import the master key wrapping key.');

    const masterKey = await crypto.subtle.unwrapKey(
      'jwk',
      wrappedMasterKeyJWK,
      importedWrappingKey,
      { // unwrapAlgo
        name: 'AES-GCM',
        iv: wrappedMasterKeyIV,
        tagLength: 128
      },
      { // unwrappedKeyAlgo
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );

    if (!masterKey) throw new Error('Failed to import the master key.');
    const masterKeyJWK = await crypto.subtle.exportKey('jwk', masterKey);
    return masterKeyJWK;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Encrypt a payload with a symmetric encryption key
 *
 * @param {string} cleartext - The data to be encrypted
 * @param {Uint8Array} iv - The initialization vector as a Uint8Array
 * @param {JsonWebKey} masterKeyJWK - The encryption key as a JsonWebKey
 * @returns {Promise<Uint8Array>} - A promise that resolves to the ciphertext as an ArrayBuffer
 */
async function encrypt({ cleartext, iv, masterKeyJWK }) {
  try {
    if (!cleartext || !iv || !masterKeyJWK) throw new Error('Input objects for encrypt are undefined or missing.');
    ValidationService.isValidMasterKeyJWK(masterKeyJWK);

    const importedMasterKey = await crypto.subtle.importKey(
      'jwk',
      masterKeyJWK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt']
    );

    if (!importedMasterKey) throw new Error('Failed to import the master key.');

    const ciphertextArrayBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      importedMasterKey,
      textEncoder.encode(cleartext),
    );

    if (!ciphertextArrayBuffer) throw new Error('Failed to encrypt the cleartext');
    const ciphertext = new Uint8Array(ciphertextArrayBuffer);
    return ciphertext;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Encrypt a payload with a symmetric encryption key
 *
 * @param {Uint8Array} ciphertext - The data to be decrypted as an Uint8Array
 * @param {Uint8Array} iv - The initialization vector as a Uint8Array
 * @param {JsonWebKey} masterKeyJWK - The encryption key as a JsonWebKey
 * @returns {Promise<string>} - A promise that resolves to the cleartext as a string
 */
async function decrypt({ ciphertext, iv, masterKeyJWK }) {
  try {
    if (!ciphertext|| !iv || !masterKeyJWK) throw new Error('Input objects for decrypt are undefined or missing.');
    ValidationService.isValidMasterKeyJWK(masterKeyJWK);

    const importedMasterKey = await crypto.subtle.importKey(
      'jwk',
      masterKeyJWK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    );

    if (!importedMasterKey) throw new Error('Failed to import the master key.');

    const cleartextBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      importedMasterKey,
      ciphertext,
    );

    if (!cleartextBuffer) throw new Error('Failed to decrypt the ciphertext.');
    const cleartext = textDecoder.decode(new Uint8Array(cleartextBuffer));
    return cleartext;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Derive the master key to encrypt/decrypt a payload
 *
 * @param {JsonWebKey} masterECDHPublicKeyJWK - The master ECDH public key
 * @param {any[]} prfHandles - array containing the saved PRF handles (one for each registered/authenticated authenticator)
 *  
 * @returns {Promise<JsonWebKey>} - A promise that resolves to the master key as a JsonWebKey
 */
async function deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles }) {
  try {
    if (!masterECDHPublicKeyJWK || !prfHandles || !prfHandles.length) throw new Error('Input elements for deriveMasterKey are undefined or missing');
    ValidationService.isValidMasterECDHPublicKeyJWK(masterECDHPublicKeyJWK);

    const { credentialID, prfOutput } = await getWebAuthnResults({ prfHandles });
    if (!credentialID || !prfOutput) throw new Error('Received missing or undefined results from the WebAuthn extension');

    const prfHandleIndex = encryptedEnvelope.prfHandles.findIndex(h => bufferToBase64URLString(h.credentialID) === bufferToBase64URLString(credentialID));
    if (prfHandleIndex === -1) throw new Error('Could not retrieve the associated PRF handle');
    const prfHandle = prfHandles[prfHandleIndex];

    const { 
      hkdfSalt,
      wrappedLocalECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV, 
      wrappedMasterKeyJWK,
      wrappedMasterKeyIV
    } = prfHandle;

    const localECDHPrivateKeyWrappingKeyJWK = await derivelocalECDHPrivateKeyWrappingKey({ 
      prfOutput, 
      hkdfSalt
    });
    ValidationService.isValidLocalECDHPrivateKeyWrappingKeyJWK(localECDHPrivateKeyWrappingKeyJWK);

    const localECDHPrivateKeyJWK = await unwrapLocalECDHPrivateKey({ 
      wrappedLocalECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,
      localECDHPrivateKeyWrappingKeyJWK,
    });
    ValidationService.isValidLocalECDHPrivateKeyJWK(localECDHPrivateKeyJWK)

    const masterKeyWrappingKeyJWK = await deriveMasterKeyWrappingKey({ 
      masterECDHPublicKeyJWK,
      localECDHPrivateKeyJWK
    });
    ValidationService.isValidMasterKeyWrappingKeyJWK(masterKeyWrappingKeyJWK);

    const masterKeyJWK = await unwrapMasterKey({ 
      wrappedMasterKeyJWK,
      wrappedMasterKeyIV,
      masterKeyWrappingKeyJWK 
    });
    ValidationService.isValidMasterKeyJWK(masterKeyJWK);

    return masterKeyJWK;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Create the master symmetric encryption key from random bytes
 *
 * @returns {Promise<JsonWebKey>} - a Promise that returns the master key as a JWK
 */
async function generateMasterKey() {
  try {
    const masterKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const masterKey = await crypto.subtle.importKey(
      'raw',
      masterKeyBytes,
      { name: 'AES-GCM' },
      true,
      ['encrypt', 'decrypt']
    );
    const masterKeyJWK = await crypto.subtle.exportKey('jwk', masterKey);
    ValidationService.isValidMasterKeyJWK(masterKeyJWK);

    return masterKeyJWK;
  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Generate the master ECDH key pair
 *
 * @returns {Promise<{ masterECDHPublicKeyJWK: JsonWebKey, masterECDHPrivateKeyJWK: JsonWebKey }>} - a Promise that returns an object containing the master ECDH key pair as JWKs
 */
async function generateMasterECDHKeyPairJWKs() {
  try {
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-521' }, true, ['deriveKey']);
    const masterECDHPublicKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const masterECDHPrivateKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    
    ValidationService.isValidMasterECDHPublicKeyJWK(masterECDHPublicKeyJWK);
    ValidationService.isValidMasterECDHPrivateKeyJWK(masterECDHPrivateKeyJWK);

    return { masterECDHPublicKeyJWK, masterECDHPrivateKeyJWK };
  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Fallback to the previous master keys (AES256GCM and EC P-521)
 * in case of an error during key rotation or adding a new authenticator

 * 
 * @param {Object} encryptedEnvelope - the encrypted envelope as an Object
 * @param {JsonWebKey} prevMasterECDHPublicKeyJWK - the previous master ECDH public key as a JsonWebKey
 * @param {JsonWebKey[]} prevWrappedMasterKeyJWKs - the previous wrapped master key for each PRF handle as an array of JsonWebKeys
 * @param {Uint8Array[]} currWrappedMasterKeyIVs -  the previous wrapped master key initialization vectors for each PRF handle as an array of Uint8Arrays
 * 
 * @returns {Promise<boolean>} - a Promise that returns a boolean reprsenting if the verification was successful [true] or unsuccessful [false]
 */
function fallbackToPreviousValues({ encryptedEnvelope, prevMasterECDHPublicKeyJWK, prevWrappedMasterKeyJWKs, prevWrappedMasterKeyIVs }) {
  try {
    Object.assign(encryptedEnvelope, { masterECDHPublicKeyJWK: prevMasterECDHPublicKeyJWK });

    for (let i = 0; i < encryptedEnvelope.prfHandles.length; i++) {
      encryptedEnvelope.prfHandles[i] = {
        credentialID: encryptedEnvelope.prfHandles[i].credentialID,
        prfSalt: encryptedEnvelope.prfHandles[i].prfSalt,
        hkdfSalt: encryptedEnvelope.prfHandles[i].hkdfSalt,
        localECDHPublicKeyJWK: encryptedEnvelope.prfHandles[i].localECDHPublicKeyJWK,
        wrappedLocalECDHPrivateKeyJWK: encryptedEnvelope.prfHandles[i].wrappedLocalECDHPrivateKeyJWK,
        wrappedLocalECDHPrivateKeyIV: encryptedEnvelope.prfHandles[i].wrappedLocalECDHPrivateKeyIV,
        wrappedMasterKeyJWK: prevWrappedMasterKeyJWKs[i],
        wrappedMasterKeyIV: prevWrappedMasterKeyIVs[i]
      };
    }
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Rotate the master keys (AES256GCM and EC P-521)
 * 
 * @param {Object} encryptedEnvelope - the encrypted envelope as an Object
 * @param {JsonWebKey} currMasterECDHPublicKeyJWK - the new master ECDH public key as a JsonWebKey
 * @param {JsonWebKey[]} currWrappedMasterKeyJWKs - the new wrapped master keys for each PRF handle as an array of JsonWebKeys
 * @param {Uint8Array[]} currWrappedMasterKeyIVs -  the new wrapped master key initialization vectors for each PRF handle as an array of Uint8Arrays
 * 
 * @returns {Promise<boolean>} - a Promise that returns a boolean reprsenting if the verification was successful [true] or unsuccessful [false]
 */
function rotateMasterKeys({ encryptedEnvelope, currMasterECDHPublicKeyJWK, currWrappedMasterKeyJWKs, currWrappedMasterKeyIVs }) {
  try {
    // save the rotated master key data
    Object.assign(encryptedEnvelope, { masterECDHPublicKeyJWK: currMasterECDHPublicKeyJWK });

    for (let i = 0; i < encryptedEnvelope.prfHandles.length; i++) {
      encryptedEnvelope.prfHandles[i] = {
        credentialID: encryptedEnvelope.prfHandles[i].credentialID,
        prfSalt: encryptedEnvelope.prfHandles[i].prfSalt,
        hkdfSalt: encryptedEnvelope.prfHandles[i].hkdfSalt,
        localECDHPublicKeyJWK: encryptedEnvelope.prfHandles[i].localECDHPublicKeyJWK,
        wrappedLocalECDHPrivateKeyJWK: encryptedEnvelope.prfHandles[i].wrappedLocalECDHPrivateKeyJWK,
        wrappedLocalECDHPrivateKeyIV: encryptedEnvelope.prfHandles[i].wrappedLocalECDHPrivateKeyIV,
        wrappedMasterKeyJWK: currWrappedMasterKeyJWKs[i],
        wrappedMasterKeyIV: currWrappedMasterKeyIVs[i]
      };
    }
    return true;
  } catch (err) {
    console.error(err.stack);
    return false;
  }
}

/**
 * Verify that the new master key can successfully encrypt & decypt
 * a randomly generated string (containing letters, numbers, symbols, emojis)
 * 
 * @param {JsonWebKey} masterKeyJWK - the new master key as a JsonWebKey
 * 
 * @returns {Promise<boolean>} - a Promise that returns a boolean reprsenting if the verification was successful [true] or unsuccessful [false]
 */
async function verifyEncryptionAndDecryption(masterKeyJWK) {
  try {
    if (!masterKeyJWK) throw new Error('Input elements for verifyEncryptionAndDecryption are undefined or missing');

    const cleartext = await generateRandomString(12);
    if (!cleartext) return false;

    console.log("Encrypting randomly generated text...");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await encrypt({ cleartext, iv, masterKeyJWK });
    if (!ciphertext) return false;

    console.log("Decrypting...")
    const decryptedText = await decrypt({ ciphertext, iv, masterKeyJWK });
    if (!decryptedText) return false;

    if (cleartext === decryptedText) {
      return true;
    } else return false
  } catch (err) {
    console.error(err.stack);
    return false;
  }
}

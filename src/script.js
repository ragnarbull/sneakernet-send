const elemMessage = document.getElementById('message');
const dialogFirstTime = document.getElementById('dialogFirstTime');

const userProperties = (function () {
  /**
   * Generate the user properties needed for the WebAuthn registration
   *
   */ 
  function createUserProperties() {
    try {
      console.log("Setting up user properties...");
      if (!encryptedEnvelope) throw new Error("The encrypted envelope has not been properly configured.");
      if (!encryptedEnvelope.userProperties) encryptedEnvelope.userProperties = {};
      
      if (Object.keys(encryptedEnvelope.userProperties).length === 0) {
        const userID = getRandomBytes();
        const userName = `britneyspears${Date.now()}`; // ensure uniqueness
        const updateData = { userName, userID };
        Object.assign(encryptedEnvelope.userProperties, updateData);
      } else throw new Error("The userProperties have not been properly configured.");
    } catch (err) {
      console.error(err.stack);
      writeToDebug(err.stack);
      writeToOutput(`Error: ${err}`);
    }
  }

  /**
   * Get the user properties from the encrypted envelope
   *
   * @returns {<{userID: Uint8Array, userName: string}>} - returns the userID as a Uint8Array and the userName as a string
   */
  function getUserProperties() {
    try {
      if (encryptedEnvelope && (Object.keys(encryptedEnvelope.userProperties).length !== 0)) {
        const userID = encryptedEnvelope.userProperties.userID;
        const userName = encryptedEnvelope.userProperties.userName;
        return { userID, userName };
      } else throw new Error("THe user properties have not been properly configured.");
    } catch (err) {
      console.error(err.stack);
      writeToDebug(err.stack);
      writeToOutput(`Error: ${err}`);
    }
  }

  return {
    createUserProperties,
    getUserProperties
  };
})();

const secureModule = (function () {
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

      if (
        !masterKeyJWK ||
        typeof masterKeyJWK !== 'object' ||
        masterKeyJWK.alg !== 'A256GCM' ||
        masterKeyJWK.k?.length !== 43 ||
        masterKeyJWK.kty !== 'oct'
      ) {
        throw new Error('The master key is not a valid JWK');
      }

      if (
        !masterKeyJWK.key_ops.includes("encrypt") ||
        !masterKeyJWK.key_ops.includes("decrypt")
      ) {
        throw new Error('The master key JWK does not have the correct key usages (encrypt and decrypt)');
      }
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
      const algorithm = { name: 'ECDH', namedCurve: 'P-256' };
      const keyPair = await crypto.subtle.generateKey(algorithm, true, ['deriveKey']);
      const masterECDHPublicKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const masterECDHPrivateKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      
      if (
        typeof masterECDHPublicKeyJWK !== 'object' ||
        typeof masterECDHPublicKeyJWK !== 'object' ||
        masterECDHPublicKeyJWK.kty !== 'EC' ||
        masterECDHPublicKeyJWK.crv !== "P-256" ||
        masterECDHPublicKeyJWK.x?.length !== 43 ||
        masterECDHPublicKeyJWK.y?.length !== 43 ||
        masterECDHPublicKeyJWK.key_ops?.length !== 0
      ) {
        throw new Error('The master ECDH public key is not a valid JWK');
      }

      if (
        !masterECDHPrivateKeyJWK ||
        typeof masterECDHPrivateKeyJWK !== 'object' ||
        masterECDHPrivateKeyJWK.kty !== 'EC' ||
        masterECDHPrivateKeyJWK.crv !== "P-256" ||
        masterECDHPrivateKeyJWK.x?.length !== 43 ||
        masterECDHPrivateKeyJWK.y?.length !== 43 ||
        masterECDHPrivateKeyJWK.d?.length !== 43 || 
        !masterECDHPrivateKeyJWK.key_ops?.includes("deriveKey")
      ) {
        throw new Error('The master ECDH private key is not a valid JWK');
      }

      return { masterECDHPublicKeyJWK, masterECDHPrivateKeyJWK };
    } catch (err) {
      console.error(err.stack);
      writeToDebug(err.stack);
      writeToOutput(`Error: ${err}`);
    }
  }

  return {
    generateMasterKey,
    generateMasterECDHKeyPairJWKs,
  };
})();

// on page load (ie. wipes the encryptedEnvelope);
const encryptedEnvelope = {};
userProperties.createUserProperties();
console.log("encryptedEnvelope:", encryptedEnvelope);

// Event handlers
elemMessage.addEventListener('input', handleMessageChange);
document.getElementById('btnRegisterKey').addEventListener('click', handleRegisterKey);
document.getElementById('btnAuthenticateKey').addEventListener('click', handleAuthenticateKey);
document.getElementById('btnRotateMasterKeys').addEventListener('click', handleRotateMasterKeys);
document.getElementById('btnProtect').addEventListener('click', handleEncrypt);
document.getElementById('btnRead').addEventListener('click', handleDecrypt);
document.getElementById('btnShowFirstTime').addEventListener('click', handleShowFirstTime);
document.getElementById('btnCloseFirstTime').addEventListener('click', handleCloseFirstTime);
document.addEventListener('keyup', handleDocumentKeyUp);

/**
 * Register a security key that can use the PRF extension to encrypt messages
 * and save the credential ID and the salt
 */
async function handleRegisterKey() {
  try {
    console.log("Registering the security key...");
    const { userID, userName } = userProperties.getUserProperties();

    const prfSalt = crypto.getRandomValues(new Uint8Array(new Array(32)));
    const credentialID = await registerWebAuthnAuthenticator({ userID, userName, prfSalt });
    if (!credentialID) throw new Error('The authenticator was not registered');

    const prfHandles = encryptedEnvelope.prfHandles;
    if (prfHandles && prfHandles.length) {
      prfHandles.push({ credentialID, prfSalt });
    } else {
      Object.assign(encryptedEnvelope, { prfHandles: [{ credentialID, prfSalt }] });
    }

    console.log("The security key was successfully registered! Press `Authenticate` to continue key setup.");
    const msg = "The security key was successfully registered! Press `Authenticate` to continue key setup.";
    writeToDebug(msg);
    alert(msg);
    handleCloseFirstTime();
  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 *  For each authenticator (that supports the PRF / MHAC-secret extension and has been enrolled)
 *
 */
async function handleAuthenticateKey() {
  try {
    console.log("Authenticating the security key...");

    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    const prfHandles = encryptedEnvelope.prfHandles;
    if (!prfHandles || !prfHandles.length) throw new Error('There are no saved PRF handles or they are empty');

    const { credentialID, prfOutput } = await getWebAuthnResults({ prfHandles });
    if (!credentialID || !prfOutput) throw new Error('Received missing or undefined results from the WebAuthn extension');

    // generate a local ECDH key pair
    const localECDHKeypair = await generateLocalECDHKeyPairJWKs();
    const localECDHPublicKeyJWK = localECDHKeypair.publicKey;
    const localECDHPrivateKeyJWK = localECDHKeypair.privateKey;

    if (
      !localECDHPublicKeyJWK ||
      typeof localECDHPublicKeyJWK !== 'object' ||
      localECDHPublicKeyJWK.kty !== 'EC' ||
      localECDHPublicKeyJWK.crv !== "P-256" ||
      localECDHPublicKeyJWK.x?.length !== 43 ||
      localECDHPublicKeyJWK.y?.length !== 43
    ) {
      throw new Error('Failed to generate a valid local ECDH public key JWK');
    }

    if (
      !localECDHPrivateKeyJWK ||
      typeof localECDHPrivateKeyJWK !== 'object' ||
      localECDHPrivateKeyJWK.kty !== 'EC' ||
      localECDHPrivateKeyJWK.crv !== "P-256" ||
      localECDHPrivateKeyJWK.x?.length !== 43 ||
      localECDHPrivateKeyJWK.y?.length !== 43 ||
      localECDHPrivateKeyJWK.d?.length !== 43
    ) {
      throw new Error('Failed to generate a valid local ECDH private key JWK');
    }

    if (
      !localECDHPrivateKeyJWK.key_ops.includes("deriveKey")
    ) {
      throw new Error('The local ECDH private key does not have the correct key usages (deriveKey)');
    }

    // derive the local ECDH private key wrapping key from the PRF output
    const hkdfSalt = crypto.getRandomValues(new Uint8Array(new Array(32)));
    const localECDHPrivateKeyWrappingKeyJWK = await derivelocalECDHPrivateKeyWrappingKey({ 
      prfOutput, 
      hkdfSalt 
    });

    if (
      !localECDHPrivateKeyWrappingKeyJWK ||
      typeof localECDHPrivateKeyWrappingKeyJWK !== 'object' ||
      localECDHPrivateKeyWrappingKeyJWK.alg !== 'A256GCM' ||
      localECDHPrivateKeyWrappingKeyJWK.k?.length !== 43 ||
      localECDHPrivateKeyWrappingKeyJWK.kty !== 'oct'
    ) {
      throw new Error('Failed to generate a valid local ECDH private key wrapping key JWK');
    }

    if (
      !localECDHPrivateKeyWrappingKeyJWK.key_ops?.includes("wrapKey") ||
      !localECDHPrivateKeyWrappingKeyJWK.key_ops?.includes("unwrapKey")
    ) {
      throw new Error('The local ECDH private key wrapping key does not have the correct key usages (wrapKey and unwrapKey)');
    }

    // wrap the local ECDH private key
    const wrappedLocalECDHPrivateKeyIV = crypto.getRandomValues(new Uint8Array(new Array(12)));
    const wrappedLocalECDHPrivateKeyJWK = await wraplocalECDHPrivateKey({ 
      localECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,  
      localECDHPrivateKeyWrappingKeyJWK
    });

    if (
      !wrappedLocalECDHPrivateKeyJWK ||
      !(wrappedLocalECDHPrivateKeyJWK instanceof ArrayBuffer) ||
      wrappedLocalECDHPrivateKeyJWK.byteLength !== 227
    ) {
      throw new Error('Failed to wrap the local ECDH private key JWK');
    }

    const prfHandle = prfHandles.find(h => bufferToBase64URLString(h.credentialID) === bufferToBase64URLString(credentialID));
    if (!prfHandle) throw new Error('Could not retrieve the associated PRF handle');

    const updateData = {
      hkdfSalt,
      localECDHPublicKeyJWK,
      wrappedLocalECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,
    };

    Object.assign(prfHandle, updateData);
    await handleRotateMasterKeys();

    console.log("The security key has been successfully authenticated. You can now encrypt & decrypt messages here.");
    const msg = 'Your security key can now be used to encrypt messages with this site.';
    writeToDebug(msg);
    alert(msg);

    handleCloseFirstTime();
  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Encrypt a message using a prepared security key
 * 
 */
async function handleEncrypt() {
  try {
    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    const { masterECDHPublicKeyJWK, prfHandles } = encryptedEnvelope;
    console.log("Deriving the master key...");
    const masterKeyJWK = await deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles });
    if (!masterKeyJWK) throw new Error('Failed to derive the master key');

    console.log("Encrypting message...");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await encrypt({ cleartext: elemMessage.value ?? '', iv, masterKeyJWK });
    if (!ciphertext) throw new Error('Failed to encrypt the message');

    const updateData = { iv, ciphertext };
    Object.assign(encryptedEnvelope, updateData);

    const b64urlEncrypted = bufferToBase64URLString(ciphertext);
    const b64urlNonce = bufferToBase64URLString(iv);
    const toReturn = `${b64urlEncrypted}:${b64urlNonce}`;

    console.log("Messaged encrypted...")
    writeToDebug(`Encrypted Message: ${toReturn}`);
    writeToOutput(toReturn.trim());

  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Decrypt a protected message using a prepared security key
 * 
 */
async function handleDecrypt() {
  try {
    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    const { iv, ciphertext, masterECDHPublicKeyJWK, prfHandles } = encryptedEnvelope;
    console.log("Deriving the master key...");
    const masterKeyJWK = await deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles });
    if (!masterKeyJWK) throw new Error('Failed to derive the master key');

    console.log("Encrypting message...")
    const cleartext = await decrypt({ ciphertext, iv, masterKeyJWK });
    if (!cleartext) throw new Error('Failed to decrypt the message');

    console.log("Messaged decrypted...")
    writeToDebug(`Original Message: ${cleartext}`);
    writeToOutput(cleartext);

  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Rotate the master AES256GCM key and the master EC-P256 keypair
 * and wrap the master key with a new master key wrapping key for each PRF handle
 * 
 */
async function handleRotateMasterKeys() {
  try {
    console.log("Rotating the master keys...")
    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    if (encryptedEnvelope.ciphertext && encryptedEnvelope.iv) {
      // decrypt the existing ciphertext
      console.log("Decrypting the vault...");
      await handleDecrypt();
    }

    // TODO: ensure the prior master key can be recovered and data recovered if anything fails...
    const masterKeyJWK = await secureModule.generateMasterKey();
    const { masterECDHPublicKeyJWK, masterECDHPrivateKeyJWK } = await secureModule.generateMasterECDHKeyPairJWKs();
    Object.assign(encryptedEnvelope, { masterECDHPublicKeyJWK });

    if (elemMessage.value) {
      // encrypt the cleartext with the new master key
      console.log("Re-encrypting the vault...");
      await handleEncrypt();
    }

    const prfHandles = encryptedEnvelope.prfHandles;
    if (!prfHandles || !prfHandles.length) throw new Error('There are no saved PRF handles');
    
    // for each PRF handle: derive a master wrapping key from the local ECDH public key and the master ECDH private key, then wrap the master key with it
    console.log("Going through each PRF handle and wrapping the new master key...");

    let count = 0;
    for (const h of prfHandles) {
      count++;
      console.log(`Updating PRF handle #${count}`);

      const masterKeyWrappingKeyJWK = await generateMasterKeyWrappingKey({ 
        localECDHPublicKeyJWK: h.localECDHPublicKeyJWK, 
        masterECDHPrivateKeyJWK 
      });

      if (
        !masterKeyWrappingKeyJWK ||
        typeof masterKeyWrappingKeyJWK !== 'object' ||
        masterKeyWrappingKeyJWK.alg !== 'A256GCM' ||
        masterKeyWrappingKeyJWK.k?.length !== 43 ||
        masterKeyWrappingKeyJWK.kty !== 'oct'
      ) {
        throw new Error('Failed to generate a valid master key wrapping key JWK');
      }

      if (
        !masterKeyWrappingKeyJWK.key_ops.includes("wrapKey") ||
        !masterKeyWrappingKeyJWK.key_ops.includes("unwrapKey")
      ) {
        throw new Error('The master key wrapping key does not have the correct key usages (wrapKey and unwrapKey)');
      }

      // wrap the master key
      const wrappedMasterKeyIV = crypto.getRandomValues(new Uint8Array(new Array(12)));
      const wrappedMasterKeyJWK = await wrapMasterKey({ 
        masterKeyJWK,
        wrappedMasterKeyIV,
        masterKeyWrappingKeyJWK
      });

      if (
        !wrappedMasterKeyJWK ||
        !(wrappedMasterKeyJWK instanceof ArrayBuffer) ||
        wrappedMasterKeyJWK.byteLength !== 138
      ) {
        throw new Error('Failed to wrap the master key');
      }

      const updateData = {
        wrappedMasterKeyJWK,
        wrappedMasterKeyIV
      };
      Object.assign(h, updateData);
      console.log(`PRF handle #${count} successfully updated`);
    }

    console.log("All PRF handles updated. Master key rotation successful.");
  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Handle global keypresses for shortcut configuration
 * @param {KeyboardEvent} e
 */
function handleDocumentKeyUp(e) {
  // Toggle debug console visibility
  if (e.ctrlKey && e.shiftKey && e.key === 'D') {
    toggleDebugConsoleVisibility()
  }
}
/**
 * Support use of typing the toolbox emoji to reveal the debug console (for mobile)
 * @param {Event} e
 */
function handleMessageChange(e) {
  // Toggle debug console visibility
  if (e.data === '🧰') {
    toggleDebugConsoleVisibility();
  }
}

/**
 * Show informational modal for setting up a key
 */
async function handleShowFirstTime() {
  dialogFirstTime.showModal();
}

/**
 * Close informational modal for setting up a key
 */
async function handleCloseFirstTime() {
  dialogFirstTime.close();
}

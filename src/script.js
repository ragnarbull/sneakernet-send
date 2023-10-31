const elemMessage = document.getElementById('message');
const dialogFirstTime = document.getElementById('dialogFirstTime');

const secureModule = (function () {
  let masterKeyJWK;
  let masterECDHKeypairJWKs;

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
   * @returns {Promise<{ publicKey: JsonWebKey, privateKey: JsonWebKey }>} - a Promise that returns an object containing the master ECDH key pair as JWKs
   */
  async function generateMasterECDHKeyPairJWKs() {
    try {
      const algorithm = { name: 'ECDH', namedCurve: 'P-256' };
      const keyPair = await crypto.subtle.generateKey(algorithm, true, ['deriveKey']);
      const publicKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const privateKeyJWK = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      return { publicKey: publicKeyJWK, privateKey: privateKeyJWK };
    } catch (err) {
      console.error(err.stack);
      writeToDebug(err.stack);
      writeToOutput(`Error: ${err}`);
    }
  }

  /**
   * Generate the master keys (master syymetric encryption key and master asymmetric keys)
   *
   * @returns {Promise<{masterKey: JsonWebKey, masterKey: JsonWebKey}>} - a Promise that returns the master key and master ECDH keypair as JWKs
   */
  async function generateMasterKeys() {
    try {

      masterKeyJWK = await generateMasterKey();
      masterECDHKeypairJWKs = await generateMasterECDHKeyPairJWKs();
      console.log("Generated new master keys...");

      if (encryptedEnvelope && Object.keys(encryptedEnvelope).length && encryptedEnvelope.prfHandles && encryptedEnvelope.prfHandles.length) {
        // exisitng PRF handles (don't wipe them)!!!
        const updateData = {
          masterECDHPublicKeyJWK: masterECDHKeypairJWKs.publicKey,
        };
        Object.assign(encryptedEnvelope, updateData);
      } else {
        // first authenticator so no PRF handles
        console.log("Ready to register the first authenticator...");
        const updateData = {
          masterECDHPublicKeyJWK: masterECDHKeypairJWKs.publicKey,
          prfHandles: []
        };
        Object.assign(encryptedEnvelope, updateData);
      }
    } catch (err) {
      console.error(err.stack);
      writeToDebug(err.stack);
      writeToOutput(`Error: ${err}`);
    }
  }

  /**
   * Function that returns the master key as a JWK
   *
   * @returns {JsonWebKey} - the master key as a JWK
   */
  function getMasterKey() {
    return masterKeyJWK;
  }

  /**
   * Function that returns the master ECDH private key as a JWK
   *
   * @returns {JsonWebKey} - the master ECDH private key as a JWK
   */
  function getMasterECDHPrivateKey() {
    const masterECDHPrivateKeyJWK = masterECDHKeypairJWKs.privateKey;
    return masterECDHPrivateKeyJWK;
  }

  return {
    generateMasterKeys,
    getMasterKey,
    getMasterECDHPrivateKey
  };
})();

const userProperties = (function () {
  /**
   * Generate a random userID and save it to local storage
   *
   */
  function createUserID() {
    localStorage.setItem('userId', btoa(String.fromCharCode.apply(null, getRandomBytes()))); // convert from Uint8Array to base64url string 
  }

  /**
   * Generate a username and save it to local storage
   *
   */
  function createUserName() {
    localStorage.setItem('userName', `britneyspears${Date.now()}`); // ensure uniqueness
  }

  /**
   * Get the userID from local storage random bytes
   *
   * @returns {Uint8Array | null} - returns the userID as a Uint8Array if it exists, otherwise null
   */
  function getUserID() {
    const base64UserID = localStorage.getItem('userId');
    if (base64UserID) {
      return Uint8Array.from(atob(base64UserID), c => c.charCodeAt(0)); // convert from base64url string to Uint8Array
    }
    return null;
  }

  /**
   * Return the username from local storage
   * 
   * @returns {string | null} - returns the userName as a string if it exists, otherwise null
   * 
   */
  function getUserName() {
    return localStorage.getItem('userName');
  }

  return {
    createUserID,
    createUserName,
    getUserID,
    getUserName
  };
})();

// on page load
const encryptedEnvelope = {};
secureModule.generateMasterKeys();
userProperties.createUserID();
userProperties.createUserName();

console.log("encryptedEnvelope:", encryptedEnvelope);

// Event handlers
elemMessage.addEventListener('input', handleMessageChange);
document.getElementById('btnRegisterKey').addEventListener('click', handleRegisterKey);
document.getElementById('btnAuthenticateKey').addEventListener('click', handleAuthenticateKey);
document.getElementById('btnRotateMasterKeys').addEventListener('click', handleRotateMasterKey);
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

    let userID = userProperties.getUserID();
    if (!userID) {
      userProperties.createUserID();
      userID = userProperties.getUserID();
    };

    let userName = userProperties.getUserName();
    if (!userName) {
      userProperties.createUserID();
      userName = userProperties.getUserName();
    };

    const prfSalt = crypto.getRandomValues(new Uint8Array(new Array(32)));
    const credentialID = await registerWebAuthnAuthenticator({ userID, userName, prfSalt });
    if (!credentialID) throw new Error('The authenticator was not registered');

    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    const prfHandles = encryptedEnvelope.prfHandles;
    if (!prfHandles) throw new Error('The PRF handle has not been setup');

    prfHandles.push({
      credentialID, // ArrayBuffer
      prfSalt // Uint8Array
    });

    console.log("Successfully registered the security key, please authenticate the key - needed to get the PRF output & derive the other keys")
    const msg = 'Successfully registered the security key. Please authenticte the key.';
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

    const prfHandle = prfHandles.find(h => bufferToBase64URLString(h.credentialID) === bufferToBase64URLString(credentialID));
    if (!prfHandle) throw new Error('Could not retrieve the associated PRF handle');

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
      !localECDHPrivateKeyWrappingKeyJWK.key_ops.includes("wrapKey") ||
      !localECDHPrivateKeyWrappingKeyJWK.key_ops.includes("unwrapKey")
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

    // derive a master wrapping key from the local ECDH public key and the master ECDH private key
    const masterECDHPrivateKeyJWK = secureModule.getMasterECDHPrivateKey();

    if (
      !masterECDHPrivateKeyJWK ||
      typeof masterECDHPrivateKeyJWK !== 'object' ||
      masterECDHPrivateKeyJWK.kty !== 'EC' ||
      masterECDHPrivateKeyJWK.crv !== "P-256" ||
      masterECDHPrivateKeyJWK.x?.length !== 43 ||
      masterECDHPrivateKeyJWK.y?.length !== 43 ||
      masterECDHPrivateKeyJWK.d?.length !== 43
    ) {
      throw new Error('The master ECDH private key is not a valid JWK');
    }

    if (!masterECDHPrivateKeyJWK.key_ops.includes("deriveKey")) throw new Error('The master ECDH private key does not have the correct key usage (deriveKey)');

    const masterKeyWrappingKeyJWK = await generateMasterKeyWrappingKey({ 
      localECDHPublicKeyJWK, 
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

    // securely retrieve the master key
    const masterKeyJWK = secureModule.getMasterKey();

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
      hkdfSalt,
      localECDHPublicKeyJWK,
      wrappedLocalECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,
      wrappedMasterKeyJWK,
      wrappedMasterKeyIV
    };
    Object.assign(prfHandle, updateData);

    console.log("Successfully authenticated the security key. You can now encrypt & decrypt messages here.");
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

    console.log("Deriving the master key...")
    const masterKeyJWK = await deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles });
    if (!masterKeyJWK) throw new Error('Failed to derive the master key');

    console.log("Encrypting message...")
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

    console.log("Deriving the master key...")
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
async function handleRotateMasterKey() {
  try {
    console.log("Rotating the master keys...")
    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    if (encryptedEnvelope.ciphertext && encryptedEnvelope.iv) {
      // decrypt the existing ciphertext
      console.log("Decrypting the existing ciphertext...");
      await handleDecrypt();
    }

    // rotate the master keys
    secureModule.generateMasterKeys();

    if (elemMessage.value) {
      // encrypt the cleartext with the new master key
      console.log("Re-encrypting the data...");
      await handleEncrypt();
    }

    // derive a master wrapping key from the local ECDH public key and the master ECDH private key

    // "securely" retrieve the master ECDH private key
    const masterECDHPrivateKeyJWK = secureModule.getMasterECDHPrivateKey();

    if (
      !masterECDHPrivateKeyJWK ||
      typeof masterECDHPrivateKeyJWK !== 'object' ||
      masterECDHPrivateKeyJWK.kty !== 'EC' ||
      masterECDHPrivateKeyJWK.crv !== "P-256" ||
      masterECDHPrivateKeyJWK.x?.length !== 43 ||
      masterECDHPrivateKeyJWK.y?.length !== 43 ||
      masterECDHPrivateKeyJWK.d?.length !== 43
    ) {
      throw new Error('The master ECDH private key is not a valid JWK');
    }

    if (!masterECDHPrivateKeyJWK.key_ops.includes("deriveKey")) throw new Error('The master ECDH private key does not have the correct key usage (deriveKey)');

    // "securely" retrieve the master key
    const masterKeyJWK = secureModule.getMasterKey();

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

    // need to ensure the master key can be recovered if anything fails...

    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    const prfHandles = encryptedEnvelope.prfHandles;
    if (!prfHandles || !prfHandles.length) throw new Error('There are no saved PRF handles');
    
    console.log("Going through each PRF handle and wrapping the master key...");
    // generate a new masterkey wrapping key and wrap the master key with it for each PRF handle
    for (const h of prfHandles) {
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

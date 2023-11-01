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

// on page load (ie. wipes the encryptedEnvelope);
const encryptedEnvelope = {};
userProperties.createUserProperties();
console.log("encryptedEnvelope:", encryptedEnvelope);

// Event handlers
elemMessage.addEventListener('input', handleMessageChange);
document.getElementById('btnRegisterKey').addEventListener('click', handleRegisterKey);
document.getElementById('btnShowFirstTime').addEventListener('click', handleShowFirstTime);
document.getElementById('btnCloseFirstTime').addEventListener('click', handleCloseFirstTime);
document.getElementById('btnRotateMasterKeys').addEventListener('click', handleRotateMasterKeys);
document.getElementById('btnEncrypt').addEventListener('click', handleEncrypt);
document.getElementById('btnDecrypt').addEventListener('click', handleDecrypt);
document.addEventListener('keyup', handleDocumentKeyUp);

/**
 * Register a security key that can use the PRF extension to encrypt messages
 * and save the credential ID and the salt
 */
async function handleRegisterKey() {
  try {
    console.log("Registering the security key...");

    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    const { userID, userName } = userProperties.getUserProperties();

    const prfSalt = crypto.getRandomValues(new Uint8Array(new Array(32)));
    const credentialID = await registerWebAuthnAuthenticator({ userID, userName, prfSalt });
    if (!credentialID) throw new Error('The authenticator was not registered');

    if (!encryptedEnvelope.prfHandles) {
      Object.assign(encryptedEnvelope, { prfHandles: [] });
    }
    encryptedEnvelope.prfHandles.push({ credentialID, prfSalt });

    const msg = "The security key was successfully registered! Press enter to continue setting up the encryption keys.";
    console.log(msg);
    writeToDebug(msg);
    alert(msg);
    handleCloseFirstTime();

    await handleAuthenticateKey();
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

    if (!encryptedEnvelope.prfHandles) {
      throw new Error('There are no saved PRF handles');
    } else if (Object.keys(encryptedEnvelope.prfHandles).length === 0) {
      throw new Error('The PRF handle(s) do(es) not contain any data');
    }

    const prfHandles = encryptedEnvelope.prfHandles;

    const { credentialID, prfOutput } = await getWebAuthnResults({ prfHandles });
    if (!credentialID || !prfOutput) throw new Error('Received missing or undefined results from the WebAuthn extension');

    // generate a local ECDH key pair
    const { localECDHPublicKeyJWK, localECDHPrivateKeyJWK } = await generateLocalECDHKeyPairJWKs();

    if (
      !localECDHPublicKeyJWK ||
      typeof localECDHPublicKeyJWK !== 'object' ||
      localECDHPublicKeyJWK.kty !== 'EC' ||
      localECDHPublicKeyJWK.crv !== "P-521" ||
      localECDHPublicKeyJWK.x?.length !== 88 ||
      localECDHPublicKeyJWK.y?.length !== 88 ||
      localECDHPublicKeyJWK.keyOps?.length === 0
    ) {
      throw new Error('Failed to generate a valid local ECDH public key JWK');
    }

    if (
      !localECDHPrivateKeyJWK ||
      typeof localECDHPrivateKeyJWK !== 'object' ||
      localECDHPrivateKeyJWK.kty !== 'EC' ||
      localECDHPrivateKeyJWK.crv !== "P-521" ||
      localECDHPrivateKeyJWK.x?.length !== 88 ||
      localECDHPrivateKeyJWK.y?.length !== 88 ||
      localECDHPrivateKeyJWK.d?.length !== 88 ||
      !localECDHPrivateKeyJWK.key_ops?.includes("deriveKey")
    ) {
      throw new Error('Failed to generate a valid local ECDH private key JWK');
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
      wrappedLocalECDHPrivateKeyJWK.byteLength !== 362
    ) {
      throw new Error('Failed to wrap the local ECDH private key JWK');
    }

    const prfHandleIndex = await findPrfHandleIndex({encryptedEnvelope, credentialID});
    const prfSalt = encryptedEnvelope.prfHandles[prfHandleIndex]?.prfSalt;

    if (!prfSalt) {
      throw new Error('Could not retrieve the PRF salt');
    }

    encryptedEnvelope.prfHandles[prfHandleIndex] = {
      credentialID,
      prfSalt,
      hkdfSalt,
      localECDHPublicKeyJWK,
      wrappedLocalECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,
    };

    const masterKeyJWK = await handleRotateMasterKeys();
    if (!masterKeyJWK) throw new Error('Failed to derive the master key');

    console.log("Verifying encryption and decryption functions work...");
    const verifyResult = await verifyEncryptionAndDecryption(masterKeyJWK);
    let msg;
    if (verifyResult) {
      msg = "Your security key can now be used to encrypt & decrypted messages with this site."
    } else {
      msg = "Failed to configure security key. Please try again."
    }
    console.log(msg)
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

    if (!encryptedEnvelope.prfHandles) {
      throw new Error('There are no saved PRF handles');
    } else if (Object.keys(encryptedEnvelope.prfHandles).length === 0) {
      throw new Error('The PRF handle(s) do(es) not contain any data');
    }

    if (!encryptedEnvelope.masterECDHPublicKeyJWK) {
      throw new Error('The master ECDH public key does not exist');
    } else if (Object.keys(encryptedEnvelope.masterECDHPublicKeyJWK).length === 0) {
      throw new Error('The master ECDH public key does not contain any data');
    }

    const { masterECDHPublicKeyJWK, prfHandles } = encryptedEnvelope;
    console.log("Deriving the master key...");
    const masterKeyJWK = await deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles });
    console.log("masterKeyJWK", masterKeyJWK);

    if (!masterKeyJWK) throw new Error('Failed to derive the master key');

    console.log("Encrypting message...");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await encrypt({ cleartext: elemMessage.value ?? '', iv, masterKeyJWK });
    if (!ciphertext) throw new Error('Failed to encrypt the message');

    const updateData = { iv, ciphertext };
    Object.assign(encryptedEnvelope, updateData);

    const b64urlEncrypted = bufferToBase64URLString(ciphertext);
    const b64urlNonce = bufferToBase64URLString(iv);
    const b64Ciphertext = `${b64urlEncrypted}:${b64urlNonce}`;

    console.log("Messaged encrypted...");
    console.log("Base64 ciphertext:", b64Ciphertext);

    writeToDebug(`Encrypted Message: ${b64Ciphertext}`);
    writeToOutput(b64Ciphertext.trim());

    return ciphertext;
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

    if (!encryptedEnvelope.prfHandles) {
      throw new Error('There are no saved PRF handles');
    } else if (Object.keys(encryptedEnvelope.prfHandles).length === 0) {
      throw new Error('The PRF handle(s) do(es) not contain any data');
    }

    if (!encryptedEnvelope.masterECDHPublicKeyJWK) {
      throw new Error('The master ECDH public key does not exist');
    } else if (Object.keys(encryptedEnvelope.masterECDHPublicKeyJWK).length === 0) {
      throw new Error('The master ECDH public key does not contain any data');
    }

    if (!encryptedEnvelope.ciphertext || !encryptedEnvelope.iv) {
      throw new Error('There is no encrypted data');
    } else if (Object.keys(encryptedEnvelope.ciphertext).length === 0 || Object.keys(encryptedEnvelope.iv).length === 0) {
      throw new Error('There is no encrypted data');
    }

    const { iv, ciphertext, masterECDHPublicKeyJWK, prfHandles } = encryptedEnvelope;
    console.log("Deriving the master key...");
    const masterKeyJWK = await deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles });
    if (!masterKeyJWK) throw new Error('Failed to derive the master key');

    console.log("Encrypting message...")
    const decryptedText = await decrypt({ ciphertext, iv, masterKeyJWK });
    if (!decryptedText) throw new Error('Failed to decrypt the message');

    console.log("Messaged decrypted...");
    console.log("Decrypted message:", decryptedText);

    writeToDebug(`Original Message: ${decryptedText}`);
    writeToOutput(decryptedText);

    return decryptedText;
  } catch (err) {
    console.error(err.stack);
    writeToDebug(err.stack);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Rotate the master AES256GCM key and the master EC-P521 keypair
 * and wrap the master key with a new master key wrapping key for each PRF handle
 * 
 */
async function handleRotateMasterKeys() {
  try {
    console.log("Rotating the master keys...");
    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    if (!encryptedEnvelope.prfHandles) {
      throw new Error('There are no saved PRF handles');
    } else if (Object.keys(encryptedEnvelope.prfHandles).length === 0) {
      throw new Error('The PRF handle(s) do(es) not contain any data');
    }

    let prevMasterECDHPublicKeyJWK;
    const prevWrappedMasterKeyJWKs = [];
    const prevWrappedMasterKeyIVs = [];

    let masterKeyJWK;
    let currMasterECDHPublicKeyJWK;
    const currWrappedMasterKeyJWKs = [];
    const currWrappedMasterKeyIVs = [];
    let count = 0;

    // retrieve the existing master ECDH public key (if it exists) to use for fallback if needed
    if (encryptedEnvelope.masterECDHPublicKeyJWK) { 
      if (Object.keys(encryptedEnvelope.masterECDHPublicKeyJWK).length) {
        prevMasterECDHPublicKeyJWK = encryptedEnvelope.masterECDHPublicKeyJWK;
      } else {
        throw new Error("The master ECDH public key is defined but has no data.")
      }
    }

    // generate new master keys
    masterKeyJWK = await generateMasterKey();
    const { masterECDHPublicKeyJWK, masterECDHPrivateKeyJWK } = await generateMasterECDHKeyPairJWKs();
    currMasterECDHPublicKeyJWK = masterECDHPublicKeyJWK;

    // for each PRF handle: derive a master wrapping key from the local ECDH public key and the master ECDH private key, then wrap the master key with it
    for (const h of encryptedEnvelope.prfHandles) {
      
      // retrieve the existing wrapped master key (if it exists) to use for fallback if needed
      if (h.wrappedMasterKeyJWK && h.wrappedMasterKeyIV) {
        prevWrappedMasterKeyJWKs.push(h.wrappedMasterKeyJWK);
        prevWrappedMasterKeyIVs.push(h.wrappedMasterKeyIV);
      }

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
        masterKeyWrappingKeyJWK.kty !== 'oct' ||
        !masterKeyWrappingKeyJWK.key_ops?.includes("wrapKey") ||
        !masterKeyWrappingKeyJWK.key_ops?.includes("unwrapKey")
      ) {
        throw new Error('Failed to generate a valid master key wrapping key AES256GCM JWK');
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

      currWrappedMasterKeyJWKs.push(wrappedMasterKeyJWK);
      currWrappedMasterKeyIVs.push(wrappedMasterKeyIV);

      console.log(`PRF handle #${count} successfully updated`);
    }

    if (encryptedEnvelope.ciphertext && encryptedEnvelope.iv) {
      if (Object.keys(encryptedEnvelope.ciphertext).length && Object.keys(encryptedEnvelope.iv).length) {
        console.log("Decrypting the vault...");
        // decrypt the vault with the current master keys
        const cleartext = await handleDecrypt();
        if (!cleartext) throw new Error("Vault decryption failed.");

        console.log("Vault decryption successful. Rotating master keys...");

        // rotate the master keys
        const result = rotateMasterKeys({ encryptedEnvelope, currMasterECDHPublicKeyJWK, currWrappedMasterKeyJWKs, currWrappedMasterKeyIVs });
        if (!result) {
          console.log("Master key rotation was not successful. Falling back to the previous values and re-encrypting the vault.");
          fallbackToPreviousValues({ encryptedEnvelope, prevMasterECDHPublicKeyJWK, prevWrappedMasterKeyJWKs, prevWrappedMasterKeyIVs });
          // re-encrypt the vault with the previous master keys
          const ciphertext = await handleEncrypt(); // can make this more user-friendly by using the PRF output from the decryption
          if (!ciphertext) throw new Error("Failed to re-encrypt the vault.");
        } else {
          console.log("Master keys rotated. Encrypting the vault with the new master key...");
          // re-encrypt the vault with the new master keys
          const ciphertext = await handleEncrypt(); // should also test decryption, then encrypt the vault
          if (!ciphertext) {
            console.log("Failed to re-encrypt the vault with the new master keys. Falling back to the previous master keys...");
            fallbackToPreviousValues({ encryptedEnvelope, prevMasterECDHPublicKeyJWK, prevWrappedMasterKeyJWKs, prevWrappedMasterKeyIVs });
            // re-encrypt the vault with the previous master keys
            const ciphertext = await handleEncrypt();
            if (!ciphertext) throw new Error("Failed to re-encrypt the vault.");
          } else {
            console.log("Master keys successfully rotated and vault encrypted with the new master keys...");
          }
        }
      } else {
        throw new Error("Ciphertext and IV are defined but have no data.");
      }
    } else {
      const result = rotateMasterKeys({ encryptedEnvelope, currMasterECDHPublicKeyJWK, currWrappedMasterKeyJWKs, currWrappedMasterKeyIVs });
      if (!result) {
        throw new Error("Master key rotation failed")
      } else {
        console.log("Master keys successfully rotated.")
      }
    }

    return masterKeyJWK;
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

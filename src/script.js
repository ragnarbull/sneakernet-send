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
    if (!encryptedEnvelope || Object.keys(encryptedEnvelope).length === 0) {
      throw new Error('The encrypted envelope has not been properly configured');
    }

    const { userID, userName } = userProperties.getUserProperties();
    const prfSalt = crypto.getRandomValues(new Uint8Array(new Array(32)));
    const credentialID = await registerWebAuthnAuthenticator({ userID, userName, prfSalt });
    if (!credentialID) throw new Error('The authenticator was not registered');

    if (!encryptedEnvelope.prfHandles) Object.assign(encryptedEnvelope, { prfHandles: [] });
    encryptedEnvelope.prfHandles.push({ credentialID, prfSalt });

    const msg = "The security key was successfully registered! Press enter to continue setting up the encryption keys.";
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
    ValidationService.isValidLocalECDHPublicKeyJWK(localECDHPublicKeyJWK);
    ValidationService.isValidLocalECDHPrivateKeyJWK(localECDHPrivateKeyJWK);

      // derive the local ECDH private key wrapping key from the PRF output
    const hkdfSalt = crypto.getRandomValues(new Uint8Array(new Array(32)));
    const localECDHPrivateKeyWrappingKeyJWK = await derivelocalECDHPrivateKeyWrappingKey({ 
      prfOutput, 
      hkdfSalt 
    });
    ValidationService.isValidLocalECDHPrivateKeyWrappingKeyJWK(localECDHPrivateKeyWrappingKeyJWK);

    // wrap the local ECDH private key
    const wrappedLocalECDHPrivateKeyIV = crypto.getRandomValues(new Uint8Array(new Array(12)));
    const wrappedLocalECDHPrivateKeyJWK = await wraplocalECDHPrivateKey({ 
      localECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,  
      localECDHPrivateKeyWrappingKeyJWK
    });
    ValidationService.isValidWrappedLocalECDHPrivateKeyJWK(wrappedLocalECDHPrivateKeyJWK);

    const prfHandleIndex = await findPrfHandleIndex({encryptedEnvelope, credentialID});
    const prfSalt = encryptedEnvelope.prfHandles[prfHandleIndex]?.prfSalt;
    if (!prfSalt) throw new Error('Could not retrieve the PRF salt');

    encryptedEnvelope.prfHandles[prfHandleIndex] = {
      credentialID,
      prfSalt,
      hkdfSalt,
      localECDHPublicKeyJWK,
      wrappedLocalECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,
    };

    const newMasterKeyJWK = await handleRotateMasterKeys();
    ValidationService.isValidMasterKeyJWK({ masterKeyJWK: newMasterKeyJWK });

    const verifyResult = await verifyEncryptionAndDecryption(newMasterKeyJWK);
    const msg = verifyResult
      ? "Your security key can now be used to encrypt & decrypt messages with this site."
      : "Failed to configure the security key. Please try again.";

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
    const masterKeyJWK = await deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles });
    ValidationService.isValidMasterKeyJWK({ masterKeyJWK });

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await encrypt({ cleartext: elemMessage.value ?? '', iv, masterKeyJWK });
    if (!ciphertext) throw new Error('Failed to encrypt the message');
    Object.assign(encryptedEnvelope, { iv, ciphertext });

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
    const masterKeyJWK = await deriveMasterKey({ masterECDHPublicKeyJWK, prfHandles });
    ValidationService.isValidMasterKeyJWK({ masterKeyJWK });

    const decryptedText = await decrypt({ ciphertext, iv, masterKeyJWK });
    if (!decryptedText) throw new Error('Failed to decrypt the message');

    console.log("Messaged decrypted...");
    console.log("Decrypted message:", decryptedText);

    writeToDebug(`Original Message: ${decryptedText}`);
    writeToOutput(decryptedText);

    return { decryptedText, masterKeyJWK };
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

    const currWrappedMasterKeyJWKs = [];
    const currWrappedMasterKeyIVs = [];

    // retrieve the existing master ECDH public key (if it exists) to use for fallback if needed
    if (encryptedEnvelope.masterECDHPublicKeyJWK) { 
      if (Object.keys(encryptedEnvelope.masterECDHPublicKeyJWK).length) {
        prevMasterECDHPublicKeyJWK = encryptedEnvelope.masterECDHPublicKeyJWK;
      } else throw new Error("The master ECDH public key is defined but has no data.")
    }

    // generate new master keys
    const newMasterKeyJWK = await generateMasterKey();
    const { masterECDHPublicKeyJWK, masterECDHPrivateKeyJWK } = await generateMasterECDHKeyPairJWKs();

    // for each PRF handle: derive a master wrapping key from the local ECDH public key and the master ECDH private key, then wrap the master key with it
    for (const h of encryptedEnvelope.prfHandles) {
      // retrieve the existing wrapped master key (if it exists) to use for fallback if needed
      if (h.wrappedMasterKeyJWK && h.wrappedMasterKeyIV) {
        prevWrappedMasterKeyJWKs.push(h.wrappedMasterKeyJWK);
        prevWrappedMasterKeyIVs.push(h.wrappedMasterKeyIV);
      }

      const masterKeyWrappingKeyJWK = await generateMasterKeyWrappingKey({ 
        localECDHPublicKeyJWK: h.localECDHPublicKeyJWK, 
        masterECDHPrivateKeyJWK 
      });
      ValidationService.isValidMasterKeyWrappingKeyJWK(masterKeyWrappingKeyJWK);

      // wrap the master key
      const wrappedMasterKeyIV = crypto.getRandomValues(new Uint8Array(new Array(12)));
      const wrappedMasterKeyJWK = await wrapMasterKey({ 
        masterKeyJWK: newMasterKeyJWK,
        wrappedMasterKeyIV,
        masterKeyWrappingKeyJWK
      });
      ValidationService.isValidWrappedMasterKey(wrappedMasterKeyJWK);

      currWrappedMasterKeyJWKs.push(wrappedMasterKeyJWK);
      currWrappedMasterKeyIVs.push(wrappedMasterKeyIV);
    }

    if (encryptedEnvelope.ciphertext && encryptedEnvelope.iv) {
      if (Object.keys(encryptedEnvelope.ciphertext).length && Object.keys(encryptedEnvelope.iv).length) {
        console.log("Decrypting the vault...");
        // decrypt the vault with the current master keys (Need to use a previously configured authenticator)
        let msg = encryptedEnvelope.prfHandles.length
          ? "We need to decrypt your vault. Please present a previously configured security key"
          : "We need to decrypt your vault using your saved security key";
        alert(msg);

        const { decryptedText, masterKeyJWK } = await handleDecrypt();
        if (!decryptedText) throw new Error("Vault decryption failed.");
        const prevMasterKeyJWK = masterKeyJWK;
        ValidationService.isValidMasterKeyJWK({ masterKeyJWK: prevMasterKeyJWK });

        // rotate the master keys
        console.log("Vault decryption successful. Rotating master keys...");
        const result = rotateMasterKeys({ encryptedEnvelope, currMasterECDHPublicKeyJWK: masterECDHPublicKeyJWK, currWrappedMasterKeyJWKs, currWrappedMasterKeyIVs });
        if (!result) {
          console.log("Master key rotation was not successful. Falling back to the previous values and re-encrypting the vault.");
          fallbackToPreviousValues({ encryptedEnvelope, prevMasterECDHPublicKeyJWK, prevWrappedMasterKeyJWKs, prevWrappedMasterKeyIVs });
          // re-encrypt the vault with the previous master keys
          const ciphertext = await encrypt({ cleartext: decryptedText, iv: encryptedEnvelope.iv, masterKeyJWK: prevMasterKeyJWK });
          if (!ciphertext) throw new Error("Failed to re-encrypt the vault.");
        } else {
          console.log("Master keys rotated. Encrypting the vault with the new master key...");
          // re-encrypt the vault with the new master keys
          const newIV = crypto.getRandomValues(new Uint8Array(12));
          const ciphertextSuccess = await encrypt({ cleartext: decryptedText, iv: newIV, masterKeyJWK: newMasterKeyJWK });

          if (!ciphertextSuccess) {
            console.log("Failed to re-encrypt the vault with the new master keys. Falling back to the previous master keys...");
            fallbackToPreviousValues({ encryptedEnvelope, prevMasterECDHPublicKeyJWK, prevWrappedMasterKeyJWKs, prevWrappedMasterKeyIVs });
            // re-encrypt the vault with the previous master keys
            const ciphertextFallback = await encrypt({ cleartext: decryptedText, iv: encryptedEnvelope.iv, masterKeyJWK: prevMasterKeyJWK });
            if (!ciphertextFallback) throw new Error("Failed to re-encrypt the vault. Yeah oops we can't encrypt your data :(");
          } else {
            Object.assign(encryptedEnvelope, { iv: newIV, ciphertext: ciphertextSuccess });
            console.log("Master keys successfully rotated and vault encrypted with the new master keys.");
          }
        }
      } else throw new Error("Ciphertext and IV are defined but have no data.");
    } else {
      const result = rotateMasterKeys({ encryptedEnvelope, currMasterECDHPublicKeyJWK: masterECDHPublicKeyJWK, currWrappedMasterKeyJWKs, currWrappedMasterKeyIVs });
      if (!result) throw new Error("Master key rotation failed");
      else console.log("Master keys successfully rotated.");
    }

    return newMasterKeyJWK;
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

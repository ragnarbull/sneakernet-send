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
const encryptedEnvelope = {}; // this object will be saved to the server
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
    if (!encryptedEnvelope) {
      throw new Error("Then encrypted envelope does not exist.");
    } else if (Object.keys(encryptedEnvelope).length === 0) {
      throw new Error("The encrypted envelope has not been properly configured.");
    }

    const { userID, userName } = userProperties.getUserProperties();
    const prfSalt = crypto.getRandomValues(new Uint8Array(new Array(32))); // use the same PRF salt for the authentication
    const credentialID = await registerWebAuthnAuthenticator({ userID, userName, prfSalt });
    if (!credentialID) throw new Error('The authenticator was not registered');

    if (!encryptedEnvelope.prfHandles) {
      Object.assign(encryptedEnvelope, { prfHandles: [] })
    }
    encryptedEnvelope.prfHandles.push({ credentialID, prfSalt });

    if (Object.keys(encryptedEnvelope.prfHandles).length === 0) {
      throw new Error("Security key registration failed. The WebAuthn device data was not saved correctly.");
    }

    // security key registration is successful (and checked that the PRF extension is available)
    // now need to get the PRF extension output to derive a series of keys to securely wrap a master AES256GCM key
    // TODO: separate these when a login system is built

    const { prfOutput } = await getWebAuthnResults({ prfHandles: encryptedEnvelope.prfHandles });
    if (!prfOutput) throw new Error("Failed to register the security key. The PRF extension output is invalid.");

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
    encryptedEnvelope.prfHandles[prfHandleIndex] = {
      credentialID,
      prfSalt,
      hkdfSalt,
      localECDHPublicKeyJWK,
      wrappedLocalECDHPrivateKeyJWK,
      wrappedLocalECDHPrivateKeyIV,
    };

    // only filled if there is one or more fully-configured existing authenticators
    let prevMasterECDHPublicKeyJWK;
    const prevWrappedMasterKeyIVs = [];
    const prevWrappedMasterKeyJWKs = [];

    const newWrappedMasterKeyIVs = [];
    const newWrappedMasterKeyJWKs = [];

    // retrieve the existing master ECDH public key (if it exists) to use for fallback if needed
    if (encryptedEnvelope.masterECDHPublicKeyJWK) { 
      if (Object.keys(encryptedEnvelope.masterECDHPublicKeyJWK).length) {
        prevMasterECDHPublicKeyJWK = encryptedEnvelope.masterECDHPublicKeyJWK;
      } else throw new Error("Failed to authenticate the security key. The master ECDH public key is defined but has no data.")
    } 
    
    // generate new master keys
    const newMasterKeyJWK = await generateMasterKey();
    ValidationService.isValidMasterKeyJWK(newMasterKeyJWK);
    const verifyResult = await verifyEncryptionAndDecryption(newMasterKeyJWK);
    if (!verifyResult) throw new Error("Failed to authenticate the security key. The new master key was not correcly generated.");

    let newMasterECDHPublicKeyJWK;
    let newMasterECDHPrivateKeyJWK;
    const { masterECDHPublicKeyJWK, masterECDHPrivateKeyJWK } = await generateMasterECDHKeyPairJWKs();
    newMasterECDHPublicKeyJWK = masterECDHPublicKeyJWK;
    newMasterECDHPrivateKeyJWK = masterECDHPrivateKeyJWK;
    ValidationService.isValidMasterECDHPublicKeyJWK(newMasterECDHPublicKeyJWK);
    ValidationService.isValidMasterECDHPrivateKeyJWK(newMasterECDHPrivateKeyJWK);

    // for each PRF handle: derive a master wrapping key from the local ECDH public key and the master ECDH private key, then wrap the master key with it
    for (const h of encryptedEnvelope.prfHandles) {
      // retrieve the existing wrapped master key (if it exists) to use for fallback if needed
      if (h.wrappedMasterKeyJWK && h.wrappedMasterKeyIV) {
        prevWrappedMasterKeyJWKs.push(h.wrappedMasterKeyJWK);
        prevWrappedMasterKeyIVs.push(h.wrappedMasterKeyIV);
      }

      const newMasterKeyWrappingKeyJWK = await generateMasterKeyWrappingKey({ 
        localECDHPublicKeyJWK: h.localECDHPublicKeyJWK, 
        masterECDHPrivateKeyJWK: newMasterECDHPrivateKeyJWK
      });
      ValidationService.isValidMasterKeyWrappingKeyJWK(newMasterKeyWrappingKeyJWK);

      // wrap the master key
      const newWrappedMasterKeyIV = crypto.getRandomValues(new Uint8Array(new Array(12)));
      const newWrappedMasterKeyJWK = await wrapMasterKey({ 
        masterKeyJWK: newMasterKeyJWK,
        wrappedMasterKeyIV: newWrappedMasterKeyIV,
        masterKeyWrappingKeyJWK: newMasterKeyWrappingKeyJWK
      });
      ValidationService.isValidWrappedMasterKey(newWrappedMasterKeyJWK);

      newWrappedMasterKeyIVs.push(newWrappedMasterKeyIV);
      newWrappedMasterKeyJWKs.push(newWrappedMasterKeyJWK);
    }

    if (encryptedEnvelope.ciphertext && encryptedEnvelope.iv) {
      if (Object.keys(encryptedEnvelope.ciphertext).length && Object.keys(encryptedEnvelope.iv).length) {
        // existing encrypted data so we need to decrypt it with an existing master key first
        console.log("Decrypting the vault...");
        // decrypt the vault with the previous master keys
        if (encryptedEnvelope.prfHandles.length) {
          alert("We need to decrypt your vault. Please present a PREVIOUSLY configured security key.")
        }

        const { decryptedCiphertextBuffer, masterKeyJWK: prevMasterKeyJWK } = await handleDecrypt();
        if (!decryptedCiphertextBuffer || !prevMasterKeyJWK) {
          throw new Error("Failed to authenticate the security key. Vault decryption failed.")
        };

        // rotate the master keys
        const result = rotateMasterKeys({ 
          encryptedEnvelope, 
          newMasterECDHPublicKeyJWK, 
          newWrappedMasterKeyJWKs, 
          newWrappedMasterKeyIVs 
        });
        if (!result) {
          console.log("Master key rotation was not successful. Falling back to the previous values and re-encrypting the vault.");
          fallbackToPreviousValues({ 
            encryptedEnvelope, 
            prevMasterECDHPublicKeyJWK, 
            prevWrappedMasterKeyJWKs, 
            prevWrappedMasterKeyIVs 
          });
          // re-encrypt the vault with the previous master keys
          const ciphertext = await encrypt({ 
            encodedCleartextBuffer: decryptedCiphertextBuffer, 
            iv: encryptedEnvelope.iv, 
            masterKeyJWK: prevMasterKeyJWK
          });
          if (!ciphertext) throw new Error("Failed to authenticate the security key. Failed to re-encrypt the vault.");
        } else {
          console.log("Master keys rotated. Encrypting the vault with the new master key...");
          // re-encrypt the vault with the new master keys
          const newIV = crypto.getRandomValues(new Uint8Array(12));
          const ciphertextSuccess = await encrypt({ 
            encodedCleartextBuffer: decryptedCiphertextBuffer, 
            iv: newIV,
            masterKeyJWK: newMasterKeyJWK
          });

          if (!ciphertextSuccess) {
            console.log("Failed to re-encrypt the vault with the new master keys. Falling back to the previous master keys...");
            fallbackToPreviousValues({ 
              encryptedEnvelope, 
              prevMasterECDHPublicKeyJWK, 
              prevWrappedMasterKeyJWKs, 
              prevWrappedMasterKeyIVs 
            });
            // re-encrypt the vault with the previous master keys
            const ciphertextFallback = await encrypt({ 
              encodedCleartextBuffer: decryptedCiphertextBuffer, 
              iv: encryptedEnvelope.iv, 
              masterKeyJWK: prevMasterKeyJWK 
            });

            if (!ciphertextFallback) {
              throw new Error("Failed to authenticate the security key. Attempted to fallback to the previous master keys but failed to re-encrypt the vault.");
            }
            throw new Error("Failed to authenticate the security key. Failed to re-encrypt the vault with the new master keys. Your vault is locked with the previous master keys.");
          } else {
            Object.assign(encryptedEnvelope, { iv: newIV, ciphertext: ciphertextSuccess });
          }
        }
      }
    } else {
      const result = rotateMasterKeys({ 
        encryptedEnvelope, 
        newMasterECDHPublicKeyJWK, 
        newWrappedMasterKeyJWKs, 
        newWrappedMasterKeyIVs 
      });
      if (!result) throw new Error("Failed to register the security key.");
    }

    const successMsg = "You can now use the security key to encrypt & decrypt messages on this site."
    writeToDebug(successMsg);
    alert(successMsg);
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
    ValidationService.isValidMasterKeyJWK(masterKeyJWK);

    const cleartext = elemMessage.value ?? '';
    if (!cleartext) {
      alert("Please provide a message to encrypt");
      return;
    }
    const encodedCleartextBuffer = new TextEncoder().encode(cleartext);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await encrypt({ encodedCleartextBuffer, iv, masterKeyJWK });

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
 * Decrypt an encrypted message using a prepared security key
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
    ValidationService.isValidMasterKeyJWK(masterKeyJWK);

    const decryptedCiphertextBuffer = await decrypt({ ciphertext, iv, masterKeyJWK });
    if (!decryptedCiphertextBuffer) throw new Error('Failed to decrypt the message');

    const decryptedCiphertext = new TextDecoder('utf-8').decode(decryptedCiphertextBuffer);
    if (!decryptedCiphertext) throw new Error('Failed to decrypt the message');

    console.log("Messaged decrypted...");
    console.log("Decrypted message:", decryptedCiphertext);

    writeToDebug(`Original Message: ${decryptedCiphertext}`);
    writeToOutput(decryptedCiphertext);

    return { decryptedCiphertextBuffer, masterKeyJWK };
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

    const newWrappedMasterKeyIVs = [];
    const newWrappedMasterKeyJWKs = [];

    // retrieve the existing master ECDH public key (if it exists) to use for fallback if needed
    if (encryptedEnvelope.masterECDHPublicKeyJWK) { 
      if (Object.keys(encryptedEnvelope.masterECDHPublicKeyJWK).length) {
        prevMasterECDHPublicKeyJWK = encryptedEnvelope.masterECDHPublicKeyJWK;
      } else throw new Error("The master ECDH public key is defined but has no data.")
    } 
    
    // generate new master keys
    const newMasterKeyJWK = await generateMasterKey();
    ValidationService.isValidMasterKeyJWK(newMasterKeyJWK);
    const verifyResult = await verifyEncryptionAndDecryption(newMasterKeyJWK);
    if (!verifyResult) throw new Error("Failed to authenticate the security key. The new master key was not correcly generated.")

    let newMasterECDHPublicKeyJWK;
    let newMasterECDHPrivateKeyJWK;
    const { masterECDHPublicKeyJWK, masterECDHPrivateKeyJWK } = await generateMasterECDHKeyPairJWKs();
    newMasterECDHPublicKeyJWK = masterECDHPublicKeyJWK;
    newMasterECDHPrivateKeyJWK = masterECDHPrivateKeyJWK;
    ValidationService.isValidMasterECDHPublicKeyJWK(newMasterECDHPublicKeyJWK);
    ValidationService.isValidMasterECDHPrivateKeyJWK(newMasterECDHPrivateKeyJWK);

    // for each PRF handle: derive a master wrapping key from the local ECDH public key and the master ECDH private key, then wrap the master key with it
    for (const h of encryptedEnvelope.prfHandles) {
      // retrieve the existing wrapped master key (if it exists) to use for fallback if needed
      if (h.wrappedMasterKeyJWK && h.wrappedMasterKeyIV) {
        prevWrappedMasterKeyJWKs.push(h.wrappedMasterKeyJWK);
        prevWrappedMasterKeyIVs.push(h.wrappedMasterKeyIV);
      }

      const newMasterKeyWrappingKeyJWK = await generateMasterKeyWrappingKey({ 
        localECDHPublicKeyJWK: h.localECDHPublicKeyJWK, 
        masterECDHPrivateKeyJWK: newMasterECDHPrivateKeyJWK
      });
      ValidationService.isValidMasterKeyWrappingKeyJWK(newMasterKeyWrappingKeyJWK);

      // wrap the master key
      const newWrappedMasterKeyIV = crypto.getRandomValues(new Uint8Array(new Array(12)));
      const newWrappedMasterKeyJWK = await wrapMasterKey({ 
        masterKeyJWK: newMasterKeyJWK,
        wrappedMasterKeyIV: newWrappedMasterKeyIV,
        masterKeyWrappingKeyJWK: newMasterKeyWrappingKeyJWK
      });
      ValidationService.isValidWrappedMasterKey(newWrappedMasterKeyJWK);

      newWrappedMasterKeyIVs.push(newWrappedMasterKeyIV);
      newWrappedMasterKeyJWKs.push(newWrappedMasterKeyJWK);
    }

    if (encryptedEnvelope.ciphertext && encryptedEnvelope.iv) {
      if (Object.keys(encryptedEnvelope.ciphertext).length && Object.keys(encryptedEnvelope.iv).length) {
        console.log("Decrypting the vault...");
        // decrypt the vault with the previous master keys
        if (encryptedEnvelope.prfHandles.length) {
          alert("We need to decrypt your vault. Please present one of your registered security keys.")
        }

        const { decryptedCiphertextBuffer, masterKeyJWK: prevMasterKeyJWK } = await handleDecrypt();
        if (!decryptedCiphertextBuffer || !prevMasterKeyJWK) {
          throw new Error("Failed to authenticate the security key. Vault decryption failed.")
        };

        // rotate the master keys
        const result = rotateMasterKeys({ 
          encryptedEnvelope, 
          newMasterECDHPublicKeyJWK, 
          newWrappedMasterKeyJWKs, 
          newWrappedMasterKeyIVs 
        });
        if (!result) {
          console.log("Master key rotation was not successful. Falling back to the previous values and re-encrypting the vault.");
          fallbackToPreviousValues({ 
            encryptedEnvelope, 
            prevMasterECDHPublicKeyJWK, 
            prevWrappedMasterKeyJWKs, 
            prevWrappedMasterKeyIVs 
          });
          // re-encrypt the vault with the previous master keys
          const ciphertext = await encrypt({ 
            encodedCleartextBuffer: decryptedCiphertextBuffer, 
            iv: encryptedEnvelope.iv, 
            masterKeyJWK: prevMasterKeyJWK
          });
          if (!ciphertext) throw new Error("Failed to authenticate the security key. Failed to re-encrypt the vault.");
        } else {
          console.log("Master keys rotated. Encrypting the vault with the new master key...");
          // re-encrypt the vault with the new master keys
          const newIV = crypto.getRandomValues(new Uint8Array(12));
          const ciphertextSuccess = await encrypt({ 
            encodedCleartextBuffer: decryptedCiphertextBuffer, 
            iv: newIV,
            masterKeyJWK: newMasterKeyJWK
          });
          if (!ciphertextSuccess) {
            console.log("Failed to re-encrypt the vault with the new master keys. Falling back to the previous master keys...");
            fallbackToPreviousValues({ 
              encryptedEnvelope, 
              prevMasterECDHPublicKeyJWK, 
              prevWrappedMasterKeyJWKs, 
              prevWrappedMasterKeyIVs 
            });
            // re-encrypt the vault with the previous master keys
            const ciphertextFallback = await encrypt({ 
            encodedCleartextBuffer: decryptedCiphertextBuffer, 
              iv: encryptedEnvelope.iv, 
              masterKeyJWK: prevMasterKeyJWK 
            });
            if (!ciphertextFallback) {
              throw new Error("Failed to authenticate the security key. Attempted to fallback to the previous master keys but failed to re-encrypt the vault.");
            }
            throw new Error("Failed to authenticate the security key. Failed to re-encrypt the vault with the new master keys. Your vault is locked with the previous master keys.");
          } else {
            Object.assign(encryptedEnvelope, { iv: newIV, ciphertext: ciphertextSuccess });
          }
        }
      }
    } else {
      const result = rotateMasterKeys({ 
        encryptedEnvelope, 
        newMasterECDHPublicKeyJWK, 
        newWrappedMasterKeyJWKs, 
        newWrappedMasterKeyIVs 
      });
      if (!result) throw new Error("Failed to authenticate the security key.");
    }

    const msg = "You can now use the security key to encrypt & decrypt messages on this site."
    writeToDebug(msg);
    alert(msg);

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

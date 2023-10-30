/**
 * Get the WebAuthn results given the authenticator PRF salt
 *
 * @param {Uint8Array | null} userID - The userID as a Uint8Array
 * @param {string | null} userName - The username as a string
 * @param {Uint8Array} prfSalt - The random PRF salt as a Uint8Array
 * @returns {Promise<ArrayBuffer>} - A promise that resolves to the credential ID [credentialID] as an ArrayBuffer
 */
async function registerWebAuthnAuthenticator({ userID, userName, prfSalt }) {
  try {
    if (!userID || !userName || !prfSalt) throw new Error('Input objects for registerWebAuthnAuthenticator are undefined or missing.');

    const regCredential = await navigator.credentials.create({
      publicKey: {
        challenge: getRandomBytes(),
        rp: { name: 'Project Skynet' },
        user: {
          id: userID,
          name: userName,
          displayName: userName,
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256
          { alg: -257, type: 'public-key' }, // RS256
        ],
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'required', // ie. a "passkey" which is saved on the authenticator
          authenticatorAttachment: 'cross-platform',
        },
        extensions: {
          prf: { eval: { first: prfSalt } }, // should do second as well?
        },
      },
    });

    const extResults = regCredential.getClientExtensionResults();

    if (!extResults.prf?.enabled) {
      writeToDebug(`extResults: ${JSON.stringify(extResults)}`);
      const message = 'Your current OS, browser, and security key combination cannot be used with this site.';
      writeToDebug(message);
      alert(message);
      throw Error(message);
    }

    const credentialID = base64URLStringToBuffer(regCredential.id);

    if (!credentialID || credentialID === undefined) {
      throw new Error('Credential ID is missing or undefined');
    } else if (!(credentialID instanceof ArrayBuffer)) {
      throw new Error('Credential ID is not an ArrayBuffer');
    } else if (!credentialID.byteLength >= 16) {
      throw new Error('Credential ID byte length is not equal to or greater than 16'); // 16 for Android, 48 for YubiKey 5C NFC Firmware >5.2
    }

    return credentialID;
  } catch (err) {
    console.error(err.stack);
  }
}

/**
 * Retrieve the WebAuthn PRF extension results [prfOutput], credential ID [credentialID] 
 * and the corresponding cross-platfrom authenticator PRF handle
 *
 * @param {any[]} prfHandles - array containing all of the saved PRF handles
 * @returns {Promise<{credentialID: ArrayBuffer, prfOutput: ArrayBuffer, prfHandle: any }>} - A promise that resolves to an object containing the credential ID, PRF output and associated PRF handle
 */
async function getWebAuthnResults({ prfHandles }) {
  try {
    if (!prfHandles || !prfHandles.length) throw new Error('Input elements for getPRFHandle are undefined or missing');

    let authOptions;
    for (const h of prfHandles) {
      authOptions = {
        publicKey: {
          challenge: getRandomBytes(),
          userVerification: 'discouraged', // standard says evalByCredential allows skipping UV?
          extensions: {
            prf: { evalByCredential: { [bufferToBase64URLString(h.credentialID)]: { first: h.prfSalt } } },
          },
          allowCredentials: [{ id: h.credentialID, type: 'public-key' }],
        },
      };
    }
     
    console.log("Getting PRF results...");

    const authCredential = await navigator.credentials.get(authOptions);
    const extResults = authCredential.getClientExtensionResults();

    const prfOutput = extResults.prf?.results?.first;
    if (!prfOutput || prfOutput === undefined) {
      throw new Error('PRF output is missing or undefined');
    } else if (!(prfOutput instanceof ArrayBuffer)) {
      throw new Error('PRF output is not an ArrayBuffer');
    } else if (prfOutput.byteLength !== 32) {
      throw new Error('PRF output byte length is not equal to 32');
    }

    const credentialID = base64URLStringToBuffer(authCredential.id);
     if (!credentialID || credentialID === undefined) {
      throw new Error('Credential ID is missing or undefined');
    } else if (!(credentialID instanceof ArrayBuffer)) {
      throw new Error('Credential ID is not an ArrayBuffer');
    } else if (!credentialID.byteLength >= 16) {
      throw new Error('Credential ID byte length is not equal to or greater than 16'); // 16 for Android, 48 for YubiKey 5C NFC Firmware >5.2
    }

    const prfHandle = prfHandles.find(h => bufferToBase64URLString(h.credentialID) === bufferToBase64URLString(credentialID));
    if (!prfHandle) throw new Error('Could not retrieve the associated PRF handle');

    return { credentialID, prfOutput, prfHandle };
  } catch (err) {
    console.error(err.stack);
  }
}

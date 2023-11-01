/**
 * Convert the given array buffer into a Base64URL-encoded string. Ideal for converting various
 * credential response ArrayBuffers to string for sending back to the server as JSON.
 *
 * Helper method to compliment `base64URLStringToBuffer`
 *
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function bufferToBase64URLString(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Convert from a Base64URL-encoded string to an Array Buffer. Best used when converting a
 * credential ID from a JSON string to an ArrayBuffer, like in allowCredentials or
 * excludeCredentials
 *
 * Helper method to compliment `bufferToBase64URLString`
 *
 * @param {string} base64URLString
 * @returns {ArrayBuffer}
 */
function base64URLStringToBuffer(base64URLString) {
  // Convert from Base64URL to Base64
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
  /**
   * Pad with '=' until it's a multiple of four
   * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
   * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
   * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
   * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
   */
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, '=');

  // Convert to a binary string
  const binary = atob(padded);

  // Convert binary string to buffer
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return buffer;
}

/**
 * Generate random bytes
 *
 * @param {number} length The number of bytes to return
 * @returns {Uint8Array}
 */
function getRandomBytes(length = 16) {
  const arrayBuffer = new Uint8Array(new Array(length));
  return crypto.getRandomValues(arrayBuffer);
}

const elemDebugContainer = document.querySelector('#debug');
const elemDebugConsole = document.querySelector('#debug p');
const elemOutput = document.querySelector('#output p');

/**
 * Output a message to the on-page console
 *
 * @param {string} text
 */
function writeToDebug(text) {
  elemDebugConsole.innerHTML = elemDebugConsole.innerHTML + `<br>\[${Date.now()}\] ${text}`;
}

/**
 * Display text that outputs from a protect or read operation
 *
 * @param {string} text
 */
function writeToOutput(text) {
  elemOutput.innerText = text;
}

/**
 * Write the error message to the debug console and output
 * and throw the error
 *
 * @param {string} msg
 */
function throwErrorMessage(msg) {
  writeToDebug(msg);
  writeToOutput(`Error: ${msg}`);
  throw new Error(msg);
}

/**
 * Show or hide the debug console, opposite of its current visibility
 */
function toggleDebugConsoleVisibility() {
  if (elemDebugContainer.classList.contains('hide')) {
    elemDebugContainer.classList.remove('hide');
  } else {
    elemDebugContainer.classList.add('hide');
  }
}

async function findPrfHandleIndex({encryptedEnvelope, credentialID}) {
  const results = await Promise.all(encryptedEnvelope.prfHandles.map(async (h, index) => {
    const a = bufferToBase64URLString(h.credentialID);
    const b = bufferToBase64URLString(credentialID);
    if (a === b) {
      return index;
    }
    return -1;
  }));

  const prfHandleIndex = results.find((index) => index !== -1);
  if (prfHandleIndex === undefined) {
    throw new Error('Could not retrieve the associated PRF handle');
  }

  return prfHandleIndex;
}
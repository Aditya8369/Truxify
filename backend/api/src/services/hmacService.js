import crypto from 'crypto';

const MIN_HMAC_SECRET_BYTES = 32;
const MAX_TIMESTAMP_DIFF_MS = 5 * 60 * 1000; // 5 minutes tolerance
const usedNonces = new Set();

const getHmacSecret = () => {
  const secret = process.env.HMAC_SECRET;
  if (!secret) {
    throw new Error('HMAC_SECRET is required; refusing to sign or verify HMAC requests without a configured secret.');
  }

  if (Buffer.byteLength(secret, 'utf8') < MIN_HMAC_SECRET_BYTES) {
    throw new Error(`HMAC_SECRET must contain at least ${MIN_HMAC_SECRET_BYTES} bytes.`);
  }

  return secret;
};

// Fail during application startup in production rather than silently running
// with an insecure or missing authentication secret.
if (process.env.NODE_ENV === 'production') {
  getHmacSecret();
}

export const isNonceValid = (nonce) => {
  if (usedNonces.has(nonce)) {
    return false;
  }
  usedNonces.add(nonce);
  return true;
};

export const isTimestampValid = (timestamp) => {
  const requestTime = parseInt(timestamp, 10);
  const currentTime = Date.now();
  return Math.abs(currentTime - requestTime) <= MAX_TIMESTAMP_DIFF_MS;
};

export const generateSignature = (payload, timestamp, nonce) => {
  const dataToSign = `${timestamp}.${nonce}.${payload}`;
  return crypto.createHmac('sha256', getHmacSecret()).update(dataToSign).digest('hex');
};

export const verifySignature = (signature, payload, timestamp, nonce) => {
  const expectedSignature = generateSignature(payload, timestamp, nonce);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch {
    return false;
  }
};

const hmacService = {
  isNonceValid,
  isTimestampValid,
  verifySignature,
  generateSignature,
};

export default hmacService;

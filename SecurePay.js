const express = require("express");
const bodyParser = require("body-parser");
const { subtle } = require("crypto").webcrypto;

const app = express();
const PORT = 3001;

app.use(bodyParser.json());
async function encryptData(cardNumber, cardCvv, publicKeyJwk) {
  const publicKey = await subtle.importKey(
    "jwk",
    {
      kty: publicKeyJwk.kty,
      n: publicKeyJwk.n,
      e: publicKeyJwk.e,
      ext: true,
    },
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-1" },
    },
    false,
    ["encrypt"]
  );

  const encryptedNumber = await subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    stringToArrayBuffer(cardNumber)
  );

  const encryptedCvv = await subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    stringToArrayBuffer(cardCvv)
  );

  return {
    instrument: arrayBufferToBase64(encryptedNumber),
    cvv: arrayBufferToBase64(encryptedCvv),
  };
}

function stringToArrayBuffer(str) {
  const buf = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    buf[i] = str.charCodeAt(i);
  }
  return buf.buffer;
}

function arrayBufferToBase64(buffer) {
  return Buffer.from(buffer).toString("base64");
}

const publicKeyJwk = {
  kty: "RSA",
  n: "24gKlX5n_yeOKYOyAQ4LCiZtzWrhU3SoHfHBVEYufsMvSA_BQ8M985Foj-LWuM3NleRJVTPptfaVS8Oryr5RYlNYxOtUcUw5MeVBbkSRr8k56NY4mN7XTAPHwvol2ZeFUWhPJrzEmvN-eiU1TXJF1lqe0CDoYILjb5oAcGzjiPyfUsxYokCR7AWytdIrqjmqqN9QoBiB1QdpABCEwmBFh5owOhOrm8l_V9KGScd0-hAXYr-uJrGqh12EUhmc5AL5jZPxtYvdTmutVZOwXhfNC1ywIjdsGBnsCKPRlcUunf_J-NbRiPKVepsTGFbu7QrurSmXN_-moBZ_unG4WQSpk0RDoFazf7L0X2bIyL1vj7HT3x-IB0F6nKCLiKeUBncxFgbgit2TGEf5IbscFMVMCscTQBjh4F_zUw1d1u2DKAvXsrylhk2D3X9T4NM6Bypb-zU0mKVXMv-gMaoYEknOm_prohDvY1idfkf0cqhlkEkV7Fe6cV4MxHxuR0ig3yvHjEu5BvO1Slhtc_uumZvHKfhC_4dR4ZN5gl_Zqrj8M157fSQP4juvBx_iKThDTSc9a6tW9B9AesY-imV2zxLNNbFSrA9E6OXqEJweLSOa-ulJi_Tzs9LtYgg5l3WvuiR2FF5dI8c5JQsMEnrsDwp4hzBCevkp7JbUU-b25ZhSa6U",
  e: "AQAB",
};

app.post("/encrypt", async (req, res) => {
  const { number, cvv } = req.body;

  if (!number || !cvv) {
    return res.status(400).json({ error: "Card number and CVV are required." });
  }

  try {
    const encryptedData = await encryptData(number, cvv, publicKeyJwk);
    console.log("Encrypted: ", number);
    return res.json(encryptedData);
  } catch (error) {
    console.error("Error encrypting data:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

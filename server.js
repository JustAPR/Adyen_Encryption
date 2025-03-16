const express = require("express");
const bodyParser = require("body-parser");
const jose = require("node-jose");

const app = express();
const port = 3000;
app.use(bodyParser.json());
async function parseKey(t) {
  function to(e) {
    return (function (e) {
      var t = e;
      for (var r = [], n = 0; n < t.length; n += 32768)
        r.push(String.fromCharCode.apply(null, t.subarray(n, n + 32768)));
      return btoa(r.join(""));
    })(e)
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  }

  function ro(e) {
    if (!e) return new Uint8Array(0);
    e.length % 2 == 1 && (e = "0" + e);
    for (var t = e.length / 2, r = new Uint8Array(t), n = 0; n < t; n++)
      r[n] = parseInt(e.substr(2 * n, 2), 16);
    return r;
  }

  const r = t.split("|");
  const n = r[0];
  const o = r[1];
  const i = ro(n);
  const a = ro(o);
  const c = to(i);
  const s = to(a);

  return jose.JWK.asKey({
    kty: "RSA",
    kid: "asf-key",
    e: c,
    n: s,
  });
}
async function encrypt(pubKey, fieldName, value, generationTime) {
  const formattedGenerationTime =
    generationTime.toISOString().split(".")[0] + "Z";

  let data;
  switch (fieldName) {
    case "number":
      data = {
        number: value,
        activate: "3",
        deactivate: "1",
        generationtime: formattedGenerationTime,
        numberBind: "1",
        numberFieldBlurCount: "1",
        numberFieldClickCount: "1",
        numberFieldFocusCount: "3",
        numberFieldKeyCount: "2",
        numberFieldLog:
          "fo@5956,cl@5960,bl@5973,fo@6155,fo@6155,Md@6171,KL@6173,pa@6173",
        numberFieldPasteCount: "1",
        referrer:
          "https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_DY4VMYQL5ZHXXE5NLG4RA5PYKYWDYAU2/4.5.0/securedFields.html?type=card&d=aHR0cHM6Ly9jaGVsc2VhZmMuM2RkaWdpdGFsdmVudWUuY29t",
      };
      break;

    case "expiryMonth":
      data = {
        expiryMonth: value,
        generationtime: formattedGenerationTime,
      };
      break;

    case "expiryYear":
      data = {
        expiryYear: value,
        generationtime: formattedGenerationTime,
      };
      break;

    case "cvc":
      data = {
        activate: "1",
        cvc: value,
        cvcBind: "1",
        cvcFieldClickCount: "1",
        cvcFieldFocusCount: "2",
        cvcFieldKeyCount: "4",
        cvcFieldLog:
          "fo@20328,fo@20328,cl@20329,KN@20344,KN@20347,KN@20349,KN@20351",
        generationtime: formattedGenerationTime,
        referrer:
          "https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_DY4VMYQL5ZHXXE5NLG4RA5PYKYWDYAU2/4.5.0/securedFields.html?type=card&d=aHR0cHM6Ly9jaGVsc2VhZmMuM2RkaWdpdGFsdmVudWUuY29t",
      };
      break;

    default:
      throw new Error("Invalid fieldName " + fieldName);
  }

  return jose.JWE.createEncrypt(
    {
      format: "compact",
      contentAlg: "A256CBC-HS512",
      fields: {
        alg: "RSA-OAEP",
        enc: "A256CBC-HS512",
        version: "1",
      },
    },
    { key: pubKey, reference: false }
  )
    .update(JSON.stringify(data))
    .final();
}
app.post("/encrypt", async (req, res) => {
  try {
    const { publicKey, cardNumber, expiryMonth, expiryYear, cvc } = req.body;
    const key = await parseKey(publicKey);
    const generationTime = new Date();
    const encryptedData = await Promise.all([
      encrypt(key, "number", cardNumber, generationTime),
      encrypt(key, "expiryMonth", expiryMonth, generationTime),
      encrypt(key, "expiryYear", expiryYear, generationTime),
      encrypt(key, "cvc", cvc, generationTime),
    ]);
    res.json({
      encryptedCardNumber: encryptedData[0],
      encryptedExpiryMonth: encryptedData[1],
      encryptedExpiryYear: encryptedData[2],
      encryptedSecurityCode: encryptedData[3],
    });
    console.log("Recived Data:", cardNumber);
  } catch (error) {
    console.error("Encryption failed:", error);
    res.status(500).send("Encryption failed: " + error.message);
  }
});
app.listen(port, () => {
  console.log(`Encryption service listening on port ${port}`);
});

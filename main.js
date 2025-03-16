const jose = require('node-jose');
async function parseKey(t) {
    function to(e) {
        return function(e) {
            var t = e;
            for (var r = [], n = 0; n < t.length; n += 32768)
                r.push(String.fromCharCode.apply(null, t.subarray(n, n + 32768)));
            return btoa(r.join(""));
        }(e).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    }

    function ro(e) {
        if (!e) return new Uint8Array(0);
        e.length % 2 == 1 && (e = "0" + e);
        var t = e.length / 2, r = new Uint8Array(t);
        for (var n = 0; n < t; n++) r[n] = parseInt(e.substr(2 * n, 2), 16);
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
    const formattedGenerationTime = generationTime.toISOString().split('.')[0] + "Z";
    
    let data;
    switch (fieldName) {
        case "number":
            data = {
                "number": value,
                "generationtime": formattedGenerationTime,
            };
            break;

        case "expiryMonth":
            data = {
                "expiryMonth": value,
                "generationtime": formattedGenerationTime,
            };
            break;

        case "expiryYear":
            data = {
                "expiryYear": value,
                "generationtime": formattedGenerationTime,
            };
            break;

        case "cvc":
            data = {
                "cvc": value,
                "generationtime": formattedGenerationTime,
            };
            break;
        case "bin":
                data = {
                    "bin": value,
                    "generationtime": formattedGenerationTime,
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
            }
        },
        { key: pubKey, reference: false }
    )
    .update(JSON.stringify(data))
    .final();
}
async function encryptCardDetails() {
    const key = await parseKey("10001|D24561475E5792627E1E9C25E66B894253E3239B803D118204DE1A38D4EC79CC075EF08D5843684D4141771DCAEC082571030209C182756FD25D033DA0F6B76BD7AE3DDC4DBDA88057876E7B01BFE9B5454F6DD0FF7A8869948EA3C82D7D457BD35FBC1358D7C0505F5EA9363BBB87EED12C4E9DC275EA9CE020F6C50B5B8C1E49BB8A4CB208596E700B38EE6B99006AA64AA1D2D1669F75189F4A604549539F2DB21A437012FEE405ADE875F5B7BD4070CBA11487E0C6FFCCC6D97F31F102A9C09C2AD391017D4542C475EC79B6F8EE385EE7041BF8B238FFDCBB45E318CF647E477D86BF8B63605A60415A149A4B02A3062D2EE664940DC9EA921A7E1E2355");
    const generationTime = new Date();
    const data = await Promise.all([
        encrypt(key, "number", "4266276049083212", generationTime),
        encrypt(key, "expiryMonth", "08", generationTime),
        encrypt(key, "expiryYear", "2027", generationTime),
        encrypt(key, "cvc", "925", generationTime),
        encrypt(key, "bin", "426627", generationTime)
    ]);
    return {
        encryptedCardNumber: data[0],
        encryptedSecurityCode: data[3],
        encryptedExpiryYear: data[2],
        encryptedExpiryMonth: data[1],
        encryptedBIN: data[4],
    };
}

encryptCardDetails().then(encryptedData => {
    var ded = JSON.stringify(encryptedData)
});


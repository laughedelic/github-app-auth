import { create, getNumericDate } from "jsr:@zaubrik/djwt@^v3.0.2";
import { decodeBase64 } from "jsr:@std/encoding@^1.0.5";

function pemToBinary(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----[A-Z ]*-----/g, "")
    .replace(/\s+/g, "");
  return decodeBase64(base64);
}

export async function appJwt(
  appId: string,
  pkcs8PrivateKey: string,
): Promise<string> {
  const buffer = pemToBinary(pkcs8PrivateKey);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    buffer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" },
    },
    true,
    ["sign"],
  );

  return create(
    { alg: "RS256", typ: "JWT" },
    {
      iss: appId, // issuer
      iat: getNumericDate(0), // issued at time (now)
      exp: getNumericDate(5 * 60), // expiration time (in 5 minutes)
    },
    key,
  );
}

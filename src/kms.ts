import { KeyManagementServiceClient } from "@google-cloud/kms";
import { createHash, createVerify, constants } from "node:crypto";
import { algorithmToHash } from "./jws";
import { encodeMessage, JWT } from "./jwt";
import { KeySigner, KeyVerifier } from "./signer";

export type KMSConfiguration = {
  name: string;
};

export type KMSServiceDeps = {
  config: KMSConfiguration;
};

export default ({ config }: KMSServiceDeps): KeySigner<JWT> & KeyVerifier => {
  const kms = new KeyManagementServiceClient();
  return {
    async sign(jwt: JWT) {
      const message = encodeMessage(jwt.header, jwt.claims);
      const alg = algorithmToHash(jwt.header.alg);
      if (alg === null) {
        throw new Error(`Unsupported algorithm: ${jwt.header.alg}`);
      }
      const digest = createHash(alg).update(message).digest();
      const [result] = await kms.asymmetricSign({
        name: config.name,
        digest: {
          [alg]: digest,
        },
      });
      if (result.signature === undefined || result.signature === null) {
        throw new Error(
          `Fail to sign message with ${jwt.header.alg} algorithm`
        );
      }
      const signature = Buffer.from(result.signature).toString("base64url");
      return { ...jwt, signature };
    },

    verify: async (token: string) => {
      const [h, c, s] = token.split(".");
      const header = JSON.parse(Buffer.from(h, "base64url").toString());

      const alg = algorithmToHash(header.alg);
      if (alg === null) {
        throw new Error(`Unsupported algorithm: ${header.alg}`);
      }

      const verifier = createVerify(alg);
      verifier.write([h, c].join("."));
      verifier.end();

      const [publicKey] = await kms.getPublicKey({ name: config.name });
      if (typeof publicKey.pem !== "string") {
        throw new Error(`Fail to get public key`);
      }

      return verifier.verify(
        {
          key: publicKey.pem,
          padding: constants.RSA_PKCS1_PSS_PADDING,
        },
        Buffer.from(s, "base64url")
      );
    },
  };
};

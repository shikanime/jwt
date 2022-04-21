export type Algorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "HS256"
  | "HS384"
  | "HS512"
  | "none";

export type Header = {
  alg: Algorithm;
  jku?: string;
  jwk?: string;
  kid?: string;
  x5u?: string;
  x5c?: string[];
  x5t?: string;
  "x5t#S256"?: string;
  typ?: string;
  [k: string]: any;
};

export const encodePart = (data: string): string =>
  Buffer.from(data, "utf8").toString("base64url");

export const decodePart = (data: string): string =>
  Buffer.from(data, "base64url").toString();

export const algorithmToHash = (alg: Algorithm) => {
  switch (alg) {
    case "RS256":
      return "sha256";
    case "RS384":
      return "sha384";
    case "RS512":
      return "sha512";
    case "PS256":
      return "sha256";
    case "PS384":
      return "sha384";
    case "PS512":
      return "sha512";
    case "HS256":
      return "sha256";
    case "HS384":
      return "sha384";
    case "HS512":
      return "sha512";
    case "ES256":
      return "sha256";
    case "ES384":
      return "sha384";
    case "ES512":
      return "sha512";
    default:
      return null;
  }
};

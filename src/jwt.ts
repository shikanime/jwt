import { Algorithm, decodePart, encodePart, Header } from "./jws";
import { dateToSeconds } from "./utils";

export type Claims = {
  iss?: string;
  sub?: string;
  aud?: string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [k: string]: any;
};

export type JWT = {
  header: Header;
  claims: Claims;
  signature?: string;
};

export const isBeforeIssueTime = (jwt: JWT): boolean => {
  if (typeof jwt.claims.iat !== "number") {
    return true;
  }
  return jwt.claims.iat > dateToSeconds(new Date());
};

export const isExpired = (jwt: JWT): boolean => {
  if (typeof jwt.claims.exp !== "number") {
    return true;
  }
  return jwt.claims.exp <= dateToSeconds(new Date());
};

export const isIntendedFor = (jwt: JWT, aud: string): boolean => {
  if (!Array.isArray(jwt.claims.aud)) {
    return true;
  }
  return jwt.claims.aud.includes(aud);
};

export type HeaderOptions = {
  notBefore?: number;
  issuer?: string;
  algorithm?: Algorithm;
};

export const createJWTHeader = (options: HeaderOptions): Header => {
  const nbf =
    typeof options.notBefore === "number"
      ? dateToSeconds(new Date()) + options.notBefore
      : undefined;
  return {
    alg: options.algorithm || "none",
    nbf,
    iss: options.issuer,
    typ: "JWT",
  };
};

export type ClaimsOptions = {
  expiresIn: number;
  audience?: string | string[];
};

export const createJWTClaims = (options: ClaimsOptions): Claims => {
  const exp = dateToSeconds(new Date()) + options.expiresIn;
  const aud = Array.isArray(options.audience)
    ? options.audience
    : options.audience !== undefined
    ? [options.audience]
    : undefined;
  const iat = dateToSeconds(new Date());
  return {
    iat,
    exp,
    aud,
  };
};

export type JWTOptions = HeaderOptions &
  ClaimsOptions & {
    header?: Header;
    payload?: Claims;
  };

export const createJWT = (options: JWTOptions): JWT => ({
  header: { ...createJWTHeader(options), ...options.header },
  claims: { ...createJWTClaims(options), ...options.payload },
});

export const encodeMessage = (header: Header, claims: Claims): string =>
  [encodePart(JSON.stringify(header)), encodePart(JSON.stringify(claims))].join(
    "."
  );

export const parse = (raw: string): JWT => {
  const [h, c, s] = raw.split(".");
  return {
    header: JSON.parse(decodePart(h)),
    claims: JSON.parse(decodePart(c)),
    signature: s,
  };
};

export const stringify = (jwt: JWT): string =>
  [encodeMessage(jwt.header, jwt.claims), jwt.signature].join(".");

export interface KeySigner<T> {
  sign(token: T): Promise<T>;
}

export interface KeyVerifier {
  verify(raw: string): Promise<boolean>;
}

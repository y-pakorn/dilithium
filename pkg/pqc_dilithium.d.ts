/* tslint:disable */
/* eslint-disable */
/**
* @returns {Keys}
*/
export function keypair(): Keys;
/**
* @param {Uint8Array} seed
* @returns {Keys}
*/
export function keypair_derive(seed: Uint8Array): Keys;
/**
* @param {Uint8Array} sig
* @param {Uint8Array} msg
* @param {Uint8Array} public_key
* @returns {boolean}
*/
export function verify(sig: Uint8Array, msg: Uint8Array, public_key: Uint8Array): boolean;
/**
*/
export class Keys {
  free(): void;
/**
*/
  constructor();
/**
* @param {Uint8Array} seed
* @returns {Keys}
*/
  static derive(seed: Uint8Array): Keys;
/**
* @param {Uint8Array} msg
* @returns {Uint8Array}
*/
  sign_bytes(msg: Uint8Array): Uint8Array;
/**
* @param {string} msg
* @returns {string}
*/
  sign_json(msg: string): string;
/**
* @returns {string}
*/
  pk_json(): string;
/**
* @returns {string}
*/
  expanded_pk_json(): string;
/**
*/
  readonly pubkey: Uint8Array;
/**
*/
  readonly secret: Uint8Array;
}
/**
*/
export class Params {
  free(): void;
/**
*/
  static readonly publicKeyBytes: number;
/**
*/
  static readonly secretKeyBytes: number;
/**
*/
  static readonly signBytes: number;
}

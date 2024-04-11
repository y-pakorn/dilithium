use tiny_keccak::{Hasher, Keccak};

use crate::fips202::*;
use crate::params::CRHBYTES;

#[derive(Debug, Clone, Copy, Default)]
pub struct State {
  pub s: [u8; 32],
}

pub type Stream128State = State;
pub type Stream256State = State;

pub const STREAM128_BLOCKBYTES: usize = SHAKE128_RATE;
pub const STREAM256_BLOCKBYTES: usize = SHAKE256_RATE;

pub fn _crh(out: &mut [u8], input: &[u8], inbytes: usize) {
  shake256(out, CRHBYTES, input, inbytes)
}

fn init(state: &mut State, seed: &[u8], nonce: u16) {
  let mut nonce_bytes = [0u8; 32];
  let mut hasher = Keccak::v256();
  hasher.update(seed);
  nonce_bytes[30..].copy_from_slice(&nonce.to_be_bytes());
  hasher.update(&nonce_bytes);
  hasher.finalize(&mut state.s);
}

fn squeezebytes(state: &mut State, out: &mut [u8], outlen: usize) {
  let mut idx = 0;
  while idx < outlen {
    let left = outlen - idx;
    if left >= 32 {
      out[idx..idx + 32].copy_from_slice(&state.s);
      idx += 32;
    } else {
      out[idx..idx + left].copy_from_slice(&state.s[..left]);
      idx = outlen;
    }
    let mut hasher = Keccak::v256();
    hasher.update(&state.s);
    hasher.finalize(&mut state.s);
  }
}

fn absorb(state: &mut State, input: &[u8]) {
  let mut hasher = Keccak::v256();
  hasher.update(&state.s);
  hasher.update(input);
  hasher.finalize(&mut state.s);
}

pub fn stream128_init(state: &mut Stream128State, seed: &[u8], nonce: u16) {
  init(state, seed, nonce);
}

pub fn stream128_squeezeblocks(
  out: &mut [u8],
  outblocks: u64,
  state: &mut Stream128State,
) {
  squeezebytes(state, out, outblocks as usize * SHAKE128_RATE);
}

pub fn stream128_absorb(state: &mut Stream128State, input: &[u8]) {
  absorb(state, input);
}

pub fn stream256_init(state: &mut Stream256State, seed: &[u8], nonce: u16) {
  init(state, seed, nonce);
}

pub fn stream256_squeezeblocks(
  out: &mut [u8],
  outblocks: u64,
  state: &mut Stream256State,
) {
  squeezebytes(state, out, outblocks as usize * SHAKE256_RATE);
}

pub fn stream256_absorb(state: &mut Stream256State, input: &[u8]) {
  absorb(state, input);
}

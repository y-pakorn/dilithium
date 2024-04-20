use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::{
  packing::{unpack_pk, unpack_sig},
  params::{K, PUBLICKEYBYTES, SECRETKEYBYTES, SEEDBYTES, SIGNBYTES},
  polyvec::{
    polyvec_matrix_expand, polyveck_ntt, polyveck_shiftl, Polyveck, Polyvecl,
  },
  sign::*,
};

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Keypair {
  pub public: [u8; PUBLICKEYBYTES],
  pub secret: [u8; SECRETKEYBYTES],
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default)]
pub struct PublicKey {
  pub rho: [u8; SEEDBYTES],
  pub t1: Polyveck,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default)]
pub struct ExpandedPublicKey {
  pub packed: [u8; SEEDBYTES],
  pub mat: [Polyvecl; K],
  pub t1: Polyveck,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default)]
pub struct Signature {
  pub c: [u8; SEEDBYTES],
  pub z: Polyvecl,
  pub h: Polyveck,
}

/// Secret key elided
impl std::fmt::Debug for Keypair {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

#[derive(Debug)]
pub enum SignError {
  Input,
  Verify,
}

impl Keypair {
  pub fn expose_secret(&self) -> &[u8] {
    &self.secret
  }

  pub fn generate() -> Keypair {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, None);
    Keypair { public, secret }
  }

  pub fn derive(seed: &[u8]) -> Keypair {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, Some(seed));
    Keypair { public, secret }
  }

  pub fn sign(&self, msg: &[u8], random: bool) -> [u8; SIGNBYTES] {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret, random);
    sig
  }

  pub fn sig_from_bytes(sig: [u8; SIGNBYTES]) -> Result<Signature, SignError> {
    let mut c = [0u8; SEEDBYTES];
    let mut z = Polyvecl::default();
    let mut h = Polyveck::default();

    unpack_sig(&mut c, &mut z, &mut h, &sig)?;

    Ok(Signature { c, z, h })
  }

  pub fn pk(&self) -> PublicKey {
    let mut rho = [0u8; SEEDBYTES];
    let mut t1 = Polyveck::default();

    unpack_pk(&mut rho, &mut t1, &self.secret);

    PublicKey { rho, t1 }
  }

  pub fn expanded_pk(&self) -> ExpandedPublicKey {
    let mut tr = [0u8; SEEDBYTES];
    let mut hasher = Keccak::v256();
    hasher.update(&self.public);
    hasher.finalize(&mut tr);

    let pk = self.pk();
    let mut epk = ExpandedPublicKey::default();
    epk.packed = tr;
    epk.t1 = pk.t1;
    polyveck_shiftl(&mut epk.t1);
    polyveck_ntt(&mut epk.t1);
    polyvec_matrix_expand(&mut epk.mat, &pk.rho);

    epk
  }
}

pub fn verify(
  sig: &[u8],
  msg: &[u8],
  public_key: &[u8],
) -> Result<(), SignError> {
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  crypto_sign_verify(&sig, &msg, public_key)
}

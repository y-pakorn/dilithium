#![allow(non_snake_case)]
extern crate alloc;

use super::*;
use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use alloc::boxed::Box;
use serde_json::to_string;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Keys {
  keypair: api::Keypair,
}

#[wasm_bindgen]
pub fn keypair() -> Keys {
  Keys {
    keypair: api::Keypair::generate(),
  }
}

#[wasm_bindgen]
pub fn keypair_derive(seed: Box<[u8]>) -> Keys {
  Keys {
    keypair: api::Keypair::derive(&seed),
  }
}

#[wasm_bindgen]
impl Keys {
  #[wasm_bindgen(constructor)]
  pub fn new() -> Keys {
    keypair()
  }

  #[wasm_bindgen]
  pub fn derive(seed: Box<[u8]>) -> Keys {
    keypair_derive(seed)
  }

  #[wasm_bindgen(getter)]
  pub fn pubkey(&self) -> Box<[u8]> {
    Box::new(self.keypair.public)
  }

  #[wasm_bindgen(getter)]
  pub fn secret(&self) -> Box<[u8]> {
    self.keypair.expose_secret().to_vec().into_boxed_slice()
  }

  #[wasm_bindgen]
  pub fn sign_bytes(&self, msg: Box<[u8]>) -> Box<[u8]> {
    Box::new(self.keypair.sign(&msg))
  }

  #[wasm_bindgen]
  pub fn sign_json(&self, msg: &str) -> String {
    let sig = Keypair::sig_from_bytes(self.keypair.sign(msg.as_bytes()))
      .expect("Should not fail");
    to_string(&sig).expect("Should not fail")
  }

  #[wasm_bindgen]
  pub fn pk_json(&self) -> String {
    to_string(&self.keypair.pk()).expect("Should serialize pk")
  }

  #[wasm_bindgen]
  pub fn expanded_pk_json(&self) -> String {
    to_string(&self.keypair.expanded_pk())
      .expect("Should serialize expanded pk")
  }
}

#[wasm_bindgen]
pub fn verify(sig: Box<[u8]>, msg: Box<[u8]>, public_key: Box<[u8]>) -> bool {
  api::verify(&sig, &msg, &public_key).is_ok()
}

#[wasm_bindgen]
pub struct Params {
  #[wasm_bindgen(readonly)]
  pub publicKeyBytes: usize,
  #[wasm_bindgen(readonly)]
  pub secretKeyBytes: usize,
  #[wasm_bindgen(readonly)]
  pub signBytes: usize,
}

#[wasm_bindgen]
impl Params {
  #[wasm_bindgen(getter)]
  pub fn publicKeyBytes() -> usize {
    PUBLICKEYBYTES
  }

  #[wasm_bindgen(getter)]
  pub fn secretKeyBytes() -> usize {
    SECRETKEYBYTES
  }

  #[wasm_bindgen(getter)]
  pub fn signBytes() -> usize {
    SIGNBYTES
  }
}

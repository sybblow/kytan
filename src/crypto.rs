// Copyright 2016-2017 Chang Lan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::num::NonZeroU32;

use bincode::{deserialize, serialize};
use ring::{aead, pbkdf2};

use crate::proto::*;

const KEY_LEN: usize = 32;

pub fn derive_keys(password: &str) -> aead::LessSafeKey {
    let mut key = [0; KEY_LEN];
    let salt = vec![0; 64];
    let pbkdf2_iterations: NonZeroU32 = NonZeroU32::new(1024).unwrap();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        pbkdf2_iterations,
        &salt,
        password.as_bytes(),
        &mut key,
    );
    let less_safe_key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
    less_safe_key
}

pub fn encap_msg(msg: &Message, key: &aead::LessSafeKey) -> Vec<u8> {
    let mut buf: Vec<u8> = serialize(&msg).unwrap();
    buf.resize(buf.len() + key.algorithm().tag_len(), 0);
    let (aad, nonce) = generate_add_nonce();
    key.seal_in_place_append_tag(nonce, aad, &mut buf).unwrap();

    buf
}

pub fn decap_msg(buf: &mut [u8], key: &aead::LessSafeKey) -> bincode::Result<Message> {
    let (aad, nonce) = generate_add_nonce();
    let decrypted_buf = key.open_in_place(nonce, aad, buf).unwrap();

    deserialize(&decrypted_buf)
}

fn generate_add_nonce() -> (aead::Aad<[u8; 0]>, aead::Nonce) {
    (
        aead::Aad::empty(),
        aead::Nonce::assume_unique_for_key([0; 12]),
    )
}

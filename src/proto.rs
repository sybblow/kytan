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

use serde_derive::{Deserialize, Serialize};

pub type Id = u8;
pub type Token = u64;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Message {
    Request,
    Response { id: Id, token: Token },
    Data { id: Id, token: Token, data: Vec<u8> },
    RequestWithID { id: Id },
}

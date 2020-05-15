// Copyright 2020 Damir Jelić
// Copyright 2020 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Error conditions.

use serde_json::Error as JsonError;
use std::io::Error as IoError;
use thiserror::Error;

#[cfg(feature = "encryption")]
use matrix_sdk_crypto::{MegolmError, OlmError};

/// Result type of the rust-sdk.
pub type Result<T> = std::result::Result<T, Error>;

/// Internal representation of errors.
#[derive(Error, Debug)]
pub enum Error {
    /// Queried endpoint requires authentication but was called on an anonymous client.
    #[error("the queried endpoint requires authentication but was called before logging in")]
    AuthenticationRequired,

    /// An error de/serializing type for the `StateStore`
    #[error(transparent)]
    SerdeJson(#[from] JsonError),

    /// An error de/serializing type for the `StateStore`
    #[error(transparent)]
    IoError(#[from] IoError),

    /// An error occurred during a E2EE operation.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    #[error(transparent)]
    OlmError(#[from] OlmError),

    /// An error occurred during a E2EE group operation.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    #[error(transparent)]
    MegolmError(#[from] MegolmError),
}
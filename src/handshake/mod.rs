//! WebSocket handshake control.

pub mod client;
pub mod headers;
pub mod server;

mod machine;

use std::{
    error::Error as ErrorTrait,
    fmt,
    io::{Read, Write},
};

use sha1::{Digest, Sha1};

use self::machine::{HandshakeMachine, RoundResult, StageResult, TryParse};
use crate::error::Error;

/// A WebSocket handshake that doesn't own the underlying stream
#[derive(Debug)]
pub struct NonOwningMidHandshake<Role: HandshakeRole> {
    role: Role,
    machine: HandshakeMachine,
}

impl<Role: HandshakeRole> NonOwningMidHandshake<Role> {
    /// Restarts the handshake process.
    pub fn handshake<S: Read + Write>(
        mut self,
        stream: &mut S,
    ) -> Result<Role::FinalResult, NonOwningHandshakeError<Role>> {
        let mut mach = self.machine;
        loop {
            mach = match mach.single_round(stream)? {
                RoundResult::WouldBlock(m) => {
                    return Err(NonOwningHandshakeError::Interrupted(NonOwningMidHandshake {
                        machine: m,
                        ..self
                    }))
                }
                RoundResult::Incomplete(m) => m,
                RoundResult::StageFinished(s) => match self.role.stage_finished(s)? {
                    ProcessingResult::Continue(m) => m,
                    ProcessingResult::Done(result) => return Ok(result),
                },
            }
        }
    }
}

/// A handshake result that doesn't own the underlying stream
pub enum NonOwningHandshakeError<Role: HandshakeRole> {
    /// Handshake was interrupted (would block).
    Interrupted(NonOwningMidHandshake<Role>),
    /// Handshake failed.
    Failure(Error),
}

impl<Role: HandshakeRole> fmt::Debug for NonOwningHandshakeError<Role> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NonOwningHandshakeError::Interrupted(_) => {
                write!(f, "NonOwningHandshakeError::Interrupted(...)")
            }
            NonOwningHandshakeError::Failure(ref e) => {
                write!(f, "NonOwningHandshakeError::Failure({:?})", e)
            }
        }
    }
}

impl<Role: HandshakeRole> fmt::Display for NonOwningHandshakeError<Role> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NonOwningHandshakeError::Interrupted(_) => {
                write!(f, "Interrupted handshake (WouldBlock)")
            }
            NonOwningHandshakeError::Failure(ref e) => write!(f, "{}", e),
        }
    }
}

impl<Role: HandshakeRole> ErrorTrait for NonOwningHandshakeError<Role> {}

impl<Role: HandshakeRole> From<Error> for NonOwningHandshakeError<Role> {
    fn from(err: Error) -> Self {
        NonOwningHandshakeError::Failure(err)
    }
}

/// A WebSocket handshake.
#[derive(Debug)]
pub struct MidHandshake<Role: HandshakeRole, S> {
    role: Role,
    machine: HandshakeMachine,
    stream: S,
}

impl<Role: HandshakeRole, S: Read + Write> MidHandshake<Role, S> {
    /// Restarts the handshake process.
    pub fn handshake(mut self) -> Result<(Role::FinalResult, S), HandshakeError<Role, S>> {
        let mut mach = self.machine;
        loop {
            mach = match mach.single_round(&mut self.stream)? {
                RoundResult::WouldBlock(m) => {
                    return Err(HandshakeError::Interrupted(MidHandshake { machine: m, ..self }))
                }
                RoundResult::Incomplete(m) => m,
                RoundResult::StageFinished(s) => match self.role.stage_finished(s)? {
                    ProcessingResult::Continue(m) => m,
                    ProcessingResult::Done(result) => return Ok((result, self.stream)),
                },
            }
        }
    }
}

/// A handshake result.
pub enum HandshakeError<Role: HandshakeRole, S> {
    /// Handshake was interrupted (would block).
    Interrupted(MidHandshake<Role, S>),
    /// Handshake failed.
    Failure(Error),
}

impl<Role: HandshakeRole, S> HandshakeError<Role, S> {
    /// Construct a HandshakeError from a NonOwningHandshakeError and an owned Stream
    pub fn from_non_owning(e: NonOwningHandshakeError<Role>, stream: S) -> Self {
        match e {
            NonOwningHandshakeError::Interrupted(m) => {
                Self::Interrupted(MidHandshake { stream, role: m.role, machine: m.machine })
            }
            NonOwningHandshakeError::Failure(e) => Self::Failure(e),
        }
    }
}

impl<Role: HandshakeRole, S> fmt::Debug for HandshakeError<Role, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HandshakeError::Interrupted(_) => write!(f, "HandshakeError::Interrupted(...)"),
            HandshakeError::Failure(ref e) => write!(f, "HandshakeError::Failure({:?})", e),
        }
    }
}

impl<Role: HandshakeRole, S> fmt::Display for HandshakeError<Role, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HandshakeError::Interrupted(_) => write!(f, "Interrupted handshake (WouldBlock)"),
            HandshakeError::Failure(ref e) => write!(f, "{}", e),
        }
    }
}

impl<Role: HandshakeRole, S> ErrorTrait for HandshakeError<Role, S> {}

impl<Role: HandshakeRole, S> From<Error> for HandshakeError<Role, S> {
    fn from(err: Error) -> Self {
        HandshakeError::Failure(err)
    }
}

/// Handshake role.
pub trait HandshakeRole {
    #[doc(hidden)]
    type IncomingData: TryParse;
    #[doc(hidden)]
    type FinalResult;
    #[doc(hidden)]
    fn stage_finished(
        &mut self,
        finish: StageResult<Self::IncomingData>,
    ) -> Result<ProcessingResult<Self::FinalResult>, Error>;
}

/// Stage processing result.
#[doc(hidden)]
#[derive(Debug)]
pub enum ProcessingResult<FinalResult> {
    Continue(HandshakeMachine),
    Done(FinalResult),
}

/// Derive the `Sec-WebSocket-Accept` response header from a `Sec-WebSocket-Key` request header.
///
/// This function can be used to perform a handshake before passing a raw TCP stream to
/// [`WebSocket::from_raw_socket`][crate::protocol::WebSocket::from_raw_socket].
pub fn derive_accept_key(request_key: &[u8]) -> String {
    // ... field is constructed by concatenating /key/ ...
    // ... with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" (RFC 6455)
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut sha1 = Sha1::default();
    sha1.update(request_key);
    sha1.update(WS_GUID);
    base64::encode(&sha1.finalize())
}

#[cfg(test)]
mod tests {
    use super::derive_accept_key;

    #[test]
    fn key_conversion() {
        // example from RFC 6455
        assert_eq!(derive_accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}

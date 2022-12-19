//! WebSocket handshake machine.

use bytes::Buf;
use log::*;
use std::io::{Cursor, Read, Write};

use crate::{
    error::{Error, ProtocolError, Result},
    util::NonBlockingResult,
    ReadBuffer,
};

/// A generic handshake state machine.
#[derive(Debug)]
pub struct HandshakeMachine {
    state: HandshakeState,
}

impl HandshakeMachine {
    /// Start reading data from the peer.
    pub fn start_read() -> Self {
        HandshakeMachine { state: HandshakeState::Reading(ReadBuffer::new()) }
    }
    /// Start writing data to the peer.
    pub fn start_write<D: Into<Vec<u8>>>(data: D) -> Self {
        HandshakeMachine { state: HandshakeState::Writing(Cursor::new(data.into())) }
    }

    /// Perform a single handshake round.
    pub fn single_round<Obj: TryParse, Stream: Read + Write>(
        self,
        stream: &mut Stream,
    ) -> Result<RoundResult<Obj>> {
        trace!("Doing handshake round.");
        match self.state {
            HandshakeState::Reading(mut buf) => {
                let read = buf.read_from(stream).no_block()?;
                match read {
                    Some(0) => Err(Error::Protocol(ProtocolError::HandshakeIncomplete)),
                    Some(_) => Ok(if let Some((size, obj)) = Obj::try_parse(Buf::chunk(&buf))? {
                        buf.advance(size);
                        RoundResult::StageFinished(StageResult::DoneReading {
                            result: obj,
                            tail: buf.into_vec(),
                        })
                    } else {
                        RoundResult::Incomplete(HandshakeMachine {
                            state: HandshakeState::Reading(buf),
                        })
                    }),
                    None => Ok(RoundResult::WouldBlock(HandshakeMachine {
                        state: HandshakeState::Reading(buf),
                    })),
                }
            }
            HandshakeState::Writing(mut buf) => {
                assert!(buf.has_remaining());
                if let Some(size) = stream.write(Buf::chunk(&buf)).no_block()? {
                    assert!(size > 0);
                    buf.advance(size);
                    Ok(if buf.has_remaining() {
                        RoundResult::Incomplete(HandshakeMachine {
                            state: HandshakeState::Writing(buf),
                        })
                    } else {
                        RoundResult::StageFinished(StageResult::DoneWriting)
                    })
                } else {
                    Ok(RoundResult::WouldBlock(HandshakeMachine {
                        state: HandshakeState::Writing(buf),
                    }))
                }
            }
        }
    }
}

/// The result of the round.
#[derive(Debug)]
pub enum RoundResult<Obj> {
    /// Round not done, I/O would block.
    WouldBlock(HandshakeMachine),
    /// Round done, state unchanged.
    Incomplete(HandshakeMachine),
    /// Stage complete.
    StageFinished(StageResult<Obj>),
}

/// The result of the stage.
#[derive(Debug)]
pub enum StageResult<Obj> {
    /// Reading round finished.
    #[allow(missing_docs)]
    DoneReading { result: Obj, tail: Vec<u8> },
    /// Writing round finished.
    DoneWriting,
}

/// The parseable object.
pub trait TryParse: Sized {
    /// Return Ok(None) if incomplete, Err on syntax error.
    fn try_parse(data: &[u8]) -> Result<Option<(usize, Self)>>;
}

/// The handshake state.
#[derive(Debug)]
enum HandshakeState {
    /// Reading data from the peer.
    Reading(ReadBuffer),
    /// Sending data to the peer.
    Writing(Cursor<Vec<u8>>),
}

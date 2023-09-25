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
        HandshakeMachine { state: HandshakeState::Reading(ReadBuffer::new(), AttackCheck::new()) }
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
            HandshakeState::Reading(mut buf, mut attack_check) => {
                let read = buf.read_from(stream).no_block()?;
                match read {
                    Some(0) => Err(Error::Protocol(ProtocolError::HandshakeIncomplete)),
                    Some(count) => {
                        attack_check.check_incoming_packet_size(count)?;
                        // TODO: this is slow for big headers with too many small packets.
                        // The parser has to be reworked in order to work on streams instead
                        // of buffers.
                        Ok(if let Some((size, obj)) = Obj::try_parse(Buf::chunk(&buf))? {
                            buf.advance(size);
                            RoundResult::StageFinished(StageResult::DoneReading {
                                result: obj,
                                tail: buf.into_vec(),
                            })
                        } else {
                            RoundResult::Incomplete(HandshakeMachine {
                                state: HandshakeState::Reading(buf, attack_check),
                            })
                        })
                    }
                    None => Ok(RoundResult::WouldBlock(HandshakeMachine {
                        state: HandshakeState::Reading(buf, attack_check),
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
    Reading(ReadBuffer, AttackCheck),
    /// Sending data to the peer.
    Writing(Cursor<Vec<u8>>),
}

/// Attack mitigation. Contains counters needed to prevent DoS attacks
/// and reject valid but useless headers.
#[derive(Debug)]
pub(crate) struct AttackCheck {
    /// Number of HTTP header successful reads (TCP packets).
    number_of_packets: usize,
    /// Total number of bytes in HTTP header.
    number_of_bytes: usize,
}

impl AttackCheck {
    /// Initialize attack checking for incoming buffer.
    fn new() -> Self {
        Self { number_of_packets: 0, number_of_bytes: 0 }
    }

    /// Check the size of an incoming packet. To be called immediately after `read()`
    /// passing its returned bytes count as `size`.
    fn check_incoming_packet_size(&mut self, size: usize) -> Result<()> {
        self.number_of_packets += 1;
        self.number_of_bytes += size;

        // TODO: these values are hardcoded. Instead of making them configurable,
        // rework the way HTTP header is parsed to remove this check at all.
        const MAX_BYTES: usize = 65536;
        const MAX_PACKETS: usize = 512;
        const MIN_PACKET_SIZE: usize = 128;
        const MIN_PACKET_CHECK_THRESHOLD: usize = 64;

        if self.number_of_bytes > MAX_BYTES {
            return Err(Error::AttackAttempt);
        }

        if self.number_of_packets > MAX_PACKETS {
            return Err(Error::AttackAttempt);
        }

        if self.number_of_packets > MIN_PACKET_CHECK_THRESHOLD {
            if self.number_of_packets * MIN_PACKET_SIZE > self.number_of_bytes {
                return Err(Error::AttackAttempt);
            }
        }

        Ok(())
    }
}

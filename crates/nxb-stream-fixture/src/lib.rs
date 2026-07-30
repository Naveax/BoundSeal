use std::collections::VecDeque;

use nxb_stream::{
    BackendReadReport, BackendReadStatus, BackendWriteReport, BackendWriteStatus,
    ByteStreamBackend,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureReadEvent {
    Bytes {
        bytes: Vec<u8>,
        elapsed_milliseconds: u64,
    },
    Eof {
        elapsed_milliseconds: u64,
    },
    Backpressure {
        elapsed_milliseconds: u64,
    },
    Timeout {
        elapsed_milliseconds: u64,
    },
    Reset {
        elapsed_milliseconds: u64,
    },
    Truncated {
        bytes: Vec<u8>,
        elapsed_milliseconds: u64,
    },
    Failure {
        code: String,
        elapsed_milliseconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureWriteEvent {
    Accept {
        maximum_bytes: u64,
        elapsed_milliseconds: u64,
    },
    Backpressure {
        elapsed_milliseconds: u64,
    },
    Timeout {
        elapsed_milliseconds: u64,
    },
    Reset {
        elapsed_milliseconds: u64,
    },
    Closed {
        elapsed_milliseconds: u64,
    },
    Failure {
        code: String,
        elapsed_milliseconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadObservation {
    pub maximum_bytes: u64,
    pub deadline_milliseconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteObservation {
    pub supplied_bytes: u64,
    pub deadline_milliseconds: u64,
}

#[derive(Debug, Default)]
pub struct InMemoryDuplex {
    read_events: VecDeque<FixtureReadEvent>,
    write_events: VecDeque<FixtureWriteEvent>,
    read_fragment_limit: Option<u64>,
    write_fragment_limit: Option<u64>,
    captured_writes: Vec<Vec<u8>>,
    read_observations: Vec<ReadObservation>,
    write_observations: Vec<WriteObservation>,
    closed: bool,
}

impl InMemoryDuplex {
    pub fn new(
        read_events: impl IntoIterator<Item = FixtureReadEvent>,
        write_events: impl IntoIterator<Item = FixtureWriteEvent>,
    ) -> Self {
        Self {
            read_events: read_events.into_iter().collect(),
            write_events: write_events.into_iter().collect(),
            ..Self::default()
        }
    }

    pub fn with_read_fragment_limit(mut self, maximum_bytes: u64) -> Self {
        self.read_fragment_limit = (maximum_bytes > 0).then_some(maximum_bytes);
        self
    }

    pub fn with_write_fragment_limit(mut self, maximum_bytes: u64) -> Self {
        self.write_fragment_limit = (maximum_bytes > 0).then_some(maximum_bytes);
        self
    }

    pub fn captured_writes(&self) -> &[Vec<u8>] {
        &self.captured_writes
    }

    pub fn read_observations(&self) -> &[ReadObservation] {
        &self.read_observations
    }

    pub fn write_observations(&self) -> &[WriteObservation] {
        &self.write_observations
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn fragment_limit(&self, requested: u64, configured: Option<u64>) -> usize {
        requested
            .min(configured.unwrap_or(u64::MAX))
            .min(usize::MAX as u64) as usize
    }

    fn split_read_bytes(
        &mut self,
        bytes: Vec<u8>,
        elapsed_milliseconds: u64,
        requested: u64,
        truncated: bool,
    ) -> BackendReadReport {
        let maximum = self.fragment_limit(requested, self.read_fragment_limit);
        let transferred = bytes.len().min(maximum);
        let remainder = bytes[transferred..].to_vec();
        let output = bytes[..transferred].to_vec();
        if !remainder.is_empty() && !truncated {
            self.read_events.push_front(FixtureReadEvent::Bytes {
                bytes: remainder,
                elapsed_milliseconds: 0,
            });
        }
        BackendReadReport {
            elapsed_milliseconds,
            status: if truncated {
                BackendReadStatus::Truncated(output)
            } else {
                BackendReadStatus::Data(output)
            },
        }
    }
}

impl ByteStreamBackend for InMemoryDuplex {
    fn read(&mut self, maximum_bytes: u64, deadline_milliseconds: u64) -> BackendReadReport {
        self.read_observations.push(ReadObservation {
            maximum_bytes,
            deadline_milliseconds,
        });
        if self.closed {
            return BackendReadReport {
                elapsed_milliseconds: 0,
                status: BackendReadStatus::Eof,
            };
        }

        match self.read_events.pop_front() {
            Some(FixtureReadEvent::Bytes {
                bytes,
                elapsed_milliseconds,
            }) => self.split_read_bytes(bytes, elapsed_milliseconds, maximum_bytes, false),
            Some(FixtureReadEvent::Eof {
                elapsed_milliseconds,
            }) => BackendReadReport {
                elapsed_milliseconds,
                status: BackendReadStatus::Eof,
            },
            Some(FixtureReadEvent::Backpressure {
                elapsed_milliseconds,
            }) => BackendReadReport {
                elapsed_milliseconds,
                status: BackendReadStatus::Backpressure,
            },
            Some(FixtureReadEvent::Timeout {
                elapsed_milliseconds,
            }) => BackendReadReport {
                elapsed_milliseconds,
                status: BackendReadStatus::Timeout,
            },
            Some(FixtureReadEvent::Reset {
                elapsed_milliseconds,
            }) => BackendReadReport {
                elapsed_milliseconds,
                status: BackendReadStatus::Reset,
            },
            Some(FixtureReadEvent::Truncated {
                bytes,
                elapsed_milliseconds,
            }) => self.split_read_bytes(bytes, elapsed_milliseconds, maximum_bytes, true),
            Some(FixtureReadEvent::Failure {
                code,
                elapsed_milliseconds,
            }) => BackendReadReport {
                elapsed_milliseconds,
                status: BackendReadStatus::Failure(code),
            },
            None => BackendReadReport {
                elapsed_milliseconds: 0,
                status: BackendReadStatus::Eof,
            },
        }
    }

    fn write(&mut self, bytes: &[u8], deadline_milliseconds: u64) -> BackendWriteReport {
        self.write_observations.push(WriteObservation {
            supplied_bytes: bytes.len() as u64,
            deadline_milliseconds,
        });
        if self.closed {
            return BackendWriteReport {
                elapsed_milliseconds: 0,
                status: BackendWriteStatus::Closed,
            };
        }

        match self.write_events.pop_front() {
            Some(FixtureWriteEvent::Accept {
                maximum_bytes,
                elapsed_milliseconds,
            }) => {
                let configured = self.write_fragment_limit.unwrap_or(u64::MAX);
                let accepted = (bytes.len() as u64).min(maximum_bytes).min(configured);
                self.captured_writes
                    .push(bytes[..accepted as usize].to_vec());
                BackendWriteReport {
                    elapsed_milliseconds,
                    status: BackendWriteStatus::Written(accepted),
                }
            }
            Some(FixtureWriteEvent::Backpressure {
                elapsed_milliseconds,
            }) => BackendWriteReport {
                elapsed_milliseconds,
                status: BackendWriteStatus::Backpressure,
            },
            Some(FixtureWriteEvent::Timeout {
                elapsed_milliseconds,
            }) => BackendWriteReport {
                elapsed_milliseconds,
                status: BackendWriteStatus::Timeout,
            },
            Some(FixtureWriteEvent::Reset {
                elapsed_milliseconds,
            }) => BackendWriteReport {
                elapsed_milliseconds,
                status: BackendWriteStatus::Reset,
            },
            Some(FixtureWriteEvent::Closed {
                elapsed_milliseconds,
            }) => BackendWriteReport {
                elapsed_milliseconds,
                status: BackendWriteStatus::Closed,
            },
            Some(FixtureWriteEvent::Failure {
                code,
                elapsed_milliseconds,
            }) => BackendWriteReport {
                elapsed_milliseconds,
                status: BackendWriteStatus::Failure(code),
            },
            None => {
                let configured = self.write_fragment_limit.unwrap_or(u64::MAX);
                let accepted = (bytes.len() as u64).min(configured);
                self.captured_writes
                    .push(bytes[..accepted as usize].to_vec());
                BackendWriteReport {
                    elapsed_milliseconds: 0,
                    status: BackendWriteStatus::Written(accepted),
                }
            }
        }
    }

    fn close(&mut self) {
        self.closed = true;
    }
}

#[cfg(test)]
mod tests;

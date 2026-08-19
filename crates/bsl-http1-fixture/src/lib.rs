use nxb_stream_fixture::{FixtureReadEvent, FixtureWriteEvent, InMemoryDuplex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http1FixtureConfig {
    pub read_fragment_bytes: u64,
    pub write_fragment_bytes: u64,
    pub read_elapsed_milliseconds: u64,
    pub write_elapsed_milliseconds: u64,
}

impl Http1FixtureConfig {
    pub fn conservative_default() -> Self {
        Self {
            read_fragment_bytes: 7,
            write_fragment_bytes: 11,
            read_elapsed_milliseconds: 1,
            write_elapsed_milliseconds: 1,
        }
    }
}

impl Default for Http1FixtureConfig {
    fn default() -> Self {
        Self::conservative_default()
    }
}

pub fn conversation_fixture(
    response_wire: impl Into<Vec<u8>>,
    config: Http1FixtureConfig,
) -> InMemoryDuplex {
    InMemoryDuplex::new(
        [
            FixtureReadEvent::Bytes {
                bytes: response_wire.into(),
                elapsed_milliseconds: config.read_elapsed_milliseconds,
            },
            FixtureReadEvent::Eof {
                elapsed_milliseconds: 0,
            },
        ],
        [FixtureWriteEvent::Accept {
            maximum_bytes: u64::MAX,
            elapsed_milliseconds: config.write_elapsed_milliseconds,
        }],
    )
    .with_read_fragment_limit(config.read_fragment_bytes)
    .with_write_fragment_limit(config.write_fragment_bytes)
}

pub fn scripted_fixture(
    reads: impl IntoIterator<Item = FixtureReadEvent>,
    writes: impl IntoIterator<Item = FixtureWriteEvent>,
) -> InMemoryDuplex {
    InMemoryDuplex::new(reads, writes)
}

#[cfg(test)]
mod tests;

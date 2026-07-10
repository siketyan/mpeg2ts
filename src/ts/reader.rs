use crate::Result;
use crate::es::StreamType;
use crate::ts::payload::{Bytes, Null, Pat, Pes, Pmt, Section};
use crate::ts::{AdaptationField, Pid, TransportScramblingControl, TsHeader, TsPacket, TsPayload};
use std::collections::HashMap;
use std::io::Read;

/// The `ReadTsPacket` trait allows for reading TS packets from a source.
pub trait ReadTsPacket {
    /// Reads a TS packet.
    ///
    /// If the end of the stream is reached, it will return `Ok(None)`.
    fn read_ts_packet(&mut self) -> Result<Option<TsPacket>>;
}

/// TS packet reader.
#[derive(Debug)]
pub struct TsPacketReader<R> {
    stream: R,
    pids: HashMap<Pid, PidKind>,
    psi_buffers: HashMap<Pid, Vec<u8>>,
}
impl<R: Read> TsPacketReader<R> {
    /// Makes a new `TsPacketReader` instance.
    pub fn new(stream: R) -> Self {
        TsPacketReader {
            stream,
            pids: HashMap::new(),
            psi_buffers: HashMap::new(),
        }
    }

    /// Returns a reference to the underlaying byte stream.
    pub fn stream(&self) -> &R {
        &self.stream
    }

    /// Converts `TsPacketReader` into the underlaying byte stream `R`.
    pub fn into_stream(self) -> R {
        self.stream
    }

    /// Registers a PID that should be read as PSI sections.
    pub fn add_section_pid(&mut self, pid: Pid) {
        self.pids.insert(pid, PidKind::Section);
    }
}
impl<R: Read> ReadTsPacket for TsPacketReader<R> {
    fn read_ts_packet(&mut self) -> Result<Option<TsPacket>> {
        // Read a complete TS packet before parsing it. If parsing directly from
        // the underlying stream fails partway through a packet, dropping a
        // partially consumed `Take` leaves the stream between packet boundaries.
        let mut packet = [0; TsPacket::SIZE];
        if let Err(error) = self.stream.read_exact(&mut packet) {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(error.into());
        }
        let mut reader = &packet[..];

        let (header, adaptation_field_control) = TsHeader::read_from(&mut reader)?;

        let adaptation_field = if adaptation_field_control.has_adaptation_field() {
            AdaptationField::read_from(&mut reader)?
        } else {
            None
        };

        let payload = if adaptation_field_control.has_payload() {
            if header.transport_scrambling_control != TransportScramblingControl::NotScrambled {
                let bytes = Bytes::read_from(&mut reader)?;
                return Ok(Some(TsPacket {
                    header,
                    adaptation_field,
                    payload: Some(TsPayload::Raw(bytes)),
                }));
            }

            let payload = match header.pid.as_u16() {
                Pid::PAT => {
                    let bytes = Bytes::read_from(&mut reader)?;
                    if let Some(section) = read_psi_section(
                        &mut self.psi_buffers,
                        header.pid,
                        header.payload_unit_start_indicator,
                        &bytes,
                    )? {
                        let pat = Pat::read_from(&section[..])?;
                        for pa in &pat.table {
                            if pa.program_num != 0 {
                                self.pids.insert(pa.program_map_pid, PidKind::Pmt);
                            }
                        }
                        TsPayload::Pat(pat)
                    } else {
                        TsPayload::Raw(bytes)
                    }
                }
                Pid::NULL => {
                    let null = Null::read_from(&mut reader)?;
                    TsPayload::Null(null)
                }
                _ => {
                    let Some(kind) = self.pids.get(&header.pid).cloned() else {
                        let bytes = Bytes::read_from(&mut reader)?;
                        return Ok(Some(TsPacket {
                            header,
                            adaptation_field,
                            payload: Some(TsPayload::Raw(bytes)),
                        }));
                    };
                    match kind {
                        PidKind::Pmt => {
                            let bytes = Bytes::read_from(&mut reader)?;
                            if let Some(section) = read_psi_section(
                                &mut self.psi_buffers,
                                header.pid,
                                header.payload_unit_start_indicator,
                                &bytes,
                            )? {
                                let pmt = Pmt::read_from(&section[..])?;
                                for es in &pmt.es_info {
                                    let kind = match es.stream_type {
                                        StreamType::DsmCcTabledData => PidKind::Section,
                                        _ => PidKind::Pes,
                                    };

                                    self.pids.insert(es.elementary_pid, kind);
                                }
                                TsPayload::Pmt(pmt)
                            } else {
                                TsPayload::Raw(bytes)
                            }
                        }
                        PidKind::Pes => {
                            if header.payload_unit_start_indicator {
                                let pes = Pes::read_from(&mut reader)?;
                                TsPayload::PesStart(pes)
                            } else {
                                let bytes = Bytes::read_from(&mut reader)?;
                                TsPayload::PesContinuation(bytes)
                            }
                        }
                        PidKind::Section => {
                            let bytes = Bytes::read_from(&mut reader)?;
                            if header.payload_unit_start_indicator {
                                let pointer_field = bytes.first().copied().unwrap_or_default();
                                let data = Bytes::new(bytes.get(1..).unwrap_or_default())?;
                                TsPayload::Section(Section {
                                    pointer_field,
                                    data,
                                })
                            } else {
                                TsPayload::Section(Section {
                                    pointer_field: 0,
                                    data: bytes,
                                })
                            }
                        }
                    }
                }
            };
            Some(payload)
        } else {
            None
        };

        if !reader.is_empty() {
            return Err(crate::Error::invalid_input(
                "Unexpected remaining data in TS packet",
            ));
        }
        Ok(Some(TsPacket {
            header,
            adaptation_field,
            payload,
        }))
    }
}

fn read_psi_section(
    psi_buffers: &mut HashMap<Pid, Vec<u8>>,
    pid: Pid,
    payload_unit_start_indicator: bool,
    payload: &[u8],
) -> Result<Option<Vec<u8>>> {
    let buffer = psi_buffers.entry(pid).or_default();

    if payload_unit_start_indicator {
        let Some(pointer_field) = payload.first().copied() else {
            return Ok(None);
        };
        let section_offset = 1 + usize::from(pointer_field);
        if section_offset >= payload.len() {
            buffer.clear();
            return Ok(None);
        }

        buffer.clear();
        buffer.extend_from_slice(&payload[section_offset..]);
    } else if !buffer.is_empty() {
        buffer.extend_from_slice(payload);
    } else {
        return Ok(None);
    }

    if buffer.len() < 3 {
        return Ok(None);
    }

    let section_length = usize::from(u16::from_be_bytes([buffer[1] & 0x0F, buffer[2]]));
    let section_end = 3 + section_length;
    if buffer.len() < section_end {
        return Ok(None);
    }

    let mut section = Vec::with_capacity(section_end + 1);
    section.push(0); // pointer_field
    section.extend_from_slice(&buffer[..section_end]);
    buffer.drain(..section_end);

    Ok(Some(section))
}

#[derive(Debug, Clone)]
enum PidKind {
    Pmt,
    Pes,
    Section,
}

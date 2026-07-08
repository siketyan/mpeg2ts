use crate::Result;
use crate::ts::payload::{Bytes, Null, Pat, Pes, Pmt, Section};
use crate::ts::{AdaptationField, Pid, TsHeader, TsPacket, TsPayload};
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
        let mut reader = self.stream.by_ref().take(TsPacket::SIZE as u64);
        let mut peek = [0; 1];
        let eos = reader.read(&mut peek)? == 0;
        if eos {
            return Ok(None);
        }

        let (header, adaptation_field_control, payload_unit_start_indicator) =
            TsHeader::read_from(peek.chain(&mut reader))?;

        let adaptation_field = if adaptation_field_control.has_adaptation_field() {
            AdaptationField::read_from(&mut reader)?
        } else {
            None
        };

        let payload = if adaptation_field_control.has_payload() {
            let payload = match header.pid.as_u16() {
                Pid::PAT => {
                    let bytes = Bytes::read_from(&mut reader)?;
                    if let Some(section) = read_psi_section(
                        &mut self.psi_buffers,
                        header.pid,
                        payload_unit_start_indicator,
                        &bytes,
                    )? {
                        let pat = Pat::read_from(&section[..])?;
                        for pa in &pat.table {
                            self.pids.insert(pa.program_map_pid, PidKind::Pmt);
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
                0x01..=0x1F | 0x1FFB => {
                    // Unknown (unsupported) packets
                    let bytes = Bytes::read_from(&mut reader)?;
                    TsPayload::Raw(bytes)
                }
                _ => {
                    let Some(kind) = self.pids.get(&header.pid).cloned() else {
                        let _ = Bytes::read_from(&mut reader)?;
                        return Err(crate::Error::invalid_input(format!(
                            "Unknown PID: header={:?}",
                            header
                        )));
                    };
                    match kind {
                        PidKind::Pmt => {
                            let bytes = Bytes::read_from(&mut reader)?;
                            if let Some(section) = read_psi_section(
                                &mut self.psi_buffers,
                                header.pid,
                                payload_unit_start_indicator,
                                &bytes,
                            )? {
                                let pmt = Pmt::read_from(&section[..])?;
                                for es in &pmt.es_info {
                                    self.pids.insert(es.elementary_pid, PidKind::Pes);
                                }
                                TsPayload::Pmt(pmt)
                            } else {
                                TsPayload::Raw(bytes)
                            }
                        }
                        PidKind::Pes => {
                            if payload_unit_start_indicator {
                                let pes = Pes::read_from(&mut reader)?;
                                TsPayload::PesStart(pes)
                            } else {
                                let bytes = Bytes::read_from(&mut reader)?;
                                TsPayload::PesContinuation(bytes)
                            }
                        }
                        PidKind::Section => {
                            let bytes = Bytes::read_from(&mut reader)?;
                            if let Some(section) = read_psi_section(
                                &mut self.psi_buffers,
                                header.pid,
                                payload_unit_start_indicator,
                                &bytes,
                            )? {
                                let pointer_field = section[0];
                                let data = Bytes::new(&section[1..])?;
                                TsPayload::Section(Section {
                                    pointer_field,
                                    data,
                                })
                            } else {
                                TsPayload::Raw(bytes)
                            }
                        }
                    }
                }
            };
            Some(payload)
        } else {
            None
        };

        if reader.limit() != 0 {
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

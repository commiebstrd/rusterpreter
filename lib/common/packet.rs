use alloc::vec::Vec;
use alloc::string::String;

use super::tlv::*;
use super::utils::*;

pub const XOR_KEY_SIZE: usize = 4;
pub type XorKey = [u8; XOR_KEY_SIZE];
pub const GUID_SIZE: usize = 16;
pub type GuidBytes = [u8; GUID_SIZE];

pub const PACKET_HEADER_SIZE: usize = XOR_KEY_SIZE + GUID_SIZE + 12;
#[derive(Copy,Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub struct PacketHeader {
  key: XorKey,
  session_guid: GuidBytes,
  encryption_flags: u32,
  length: u32,
  type_: TlvPacketType,
}
impl PacketHeader {
  pub fn new() -> PacketHeader {
    PacketHeader {
      key: [0x00; XOR_KEY_SIZE],
      session_guid: [0x00; GUID_SIZE],
      encryption_flags: 0,
      length: PACKET_HEADER_SIZE as u32,
      type_: TlvPacketType::Request,
    }
  }
  pub fn key(&self) -> &XorKey {
    &self.key
  }
  pub fn mut_key(&mut self) -> &mut XorKey {
    &mut self.key
  }
  pub fn set_key(mut self, key:XorKey) -> Self {
    self.key = key;
    self
  }
  pub fn set_key_ref(&mut self, key:XorKey) {
    self.key = key;
  }
  pub fn guid(&self) -> &GuidBytes {
    &self.session_guid
  }
  pub fn mut_guid(&mut self) -> &mut GuidBytes {
    &mut self.session_guid
  }
  pub fn set_guid(mut self, guid:GuidBytes) -> Self {
    self.session_guid = guid;
    self
  }
  pub fn set_guid_ref(&mut self, guid:GuidBytes) {
    self.session_guid = guid;
  }
  pub fn enc_flags(&self) -> u32 {
    self.encryption_flags
  }
  pub fn set_enc_flags(mut self, flags:u32) -> Self {
    self.encryption_flags = flags;
    self
  }
  pub fn set_enc_flags_ref(&mut self, flags:u32) {
    self.encryption_flags = flags;
  }
  pub fn length(&self) -> u32 {
    self.length
  }
  pub fn set_length(mut self, length: u32) -> Self {
    self.set_length_ref(length);
    self
  }
  pub fn set_length_ref(&mut self, length: u32) {
    self.length = length;
  }
  pub fn get_type(&self) -> &TlvPacketType {
    &self.type_
  }
  pub fn get_mut_type(&mut self) -> &mut TlvPacketType {
    &mut self.type_
  }
  pub fn set_type<T>(mut self, ty:T) -> Self
    where T: Into<TlvPacketType>
  {
    self.type_ = ty.into();
    self
  }
  pub fn set_type_ref<T>(&mut self, ty:T)
    where T: Into<TlvPacketType>
  {
    self.type_ = ty.into();
  }
}
impl From<&[u8]> for PacketHeader {
  fn from(val: &[u8]) -> PacketHeader {
    if val.len() < PACKET_HEADER_SIZE {
      panic!{"PacketHeader::From::<&[u8]> length < {}: {}", PACKET_HEADER_SIZE, val.len()};
    }
    let (key_, val) = val.split_at(XOR_KEY_SIZE);
    let mut key: XorKey = [0; XOR_KEY_SIZE];
    key.copy_from_slice(key_);
    let (guid_, val) = val.split_at(GUID_SIZE);
    let mut guid: GuidBytes = [0; GUID_SIZE];
    guid.copy_from_slice(guid_);
    let (flags, val) = val.split_at(4);
    let flags: u32 = slice_to_u32_ntoh(flags);
    let (length, val) = val.split_at(4);
    let length: u32 = slice_to_u32_ntoh(length);
    let type_: TlvPacketType = val.into();

    PacketHeader {
      key: key,
      session_guid: guid,
      encryption_flags: flags,
      length: length,
      type_: type_,
    }
  }
}
impl From<Vec<u8>> for PacketHeader {
  fn from(val: Vec<u8>) -> PacketHeader {
    if val.len() < PACKET_HEADER_SIZE {
      panic!{"PacketHeader::From::<Vec<u8>> length < {}: {}", PACKET_HEADER_SIZE, val.len()};
    }
    let val: &[u8] = &val;
    val.into()
  }
}
impl Into<Vec<u8>> for PacketHeader {
  fn into(self) -> Vec<u8> {
    let mut header: Vec<u8> = Vec::with_capacity(PACKET_HEADER_SIZE);
    header.append(&mut self.key.to_vec());
    header.append(&mut self.session_guid.to_vec());
    header.append(&mut u32_to_vec_hton(self.encryption_flags));
    header.append(&mut u32_to_vec_hton(self.length));
    header.append(&mut self.type_.into());
    header
  }
}

pub const NULL_PACKET_SIZE: usize = PACKET_HEADER_SIZE + 5;
#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub struct Packet {
  header: PacketHeader,
  payload: Option<Vec<Tlv>>,
  // payload_length: u32 // dynamically generated
  decompressed_buffers: Option<Vec<DecompressedBuffer>>,
  local: bool,
}
impl Packet {
  pub fn new() -> Packet {
    Packet {
      header: PacketHeader::new(),
      payload: None,
      decompressed_buffers: None,
      local: true,
    }
  }
  pub fn header(&self) -> &PacketHeader {
    &self.header
  }
  pub fn mut_header(&mut self) -> &mut PacketHeader {
    &mut self.header
  }
  pub fn set_header(mut self, header: PacketHeader) -> Self {
    self.set_header_ref(header);
    self
  }
  pub fn set_header_ref(&mut self, header: PacketHeader) {
    self.header = header;
  }
  pub fn payload(&self) -> &Option<Vec<Tlv>> {
    &self.payload
  }
  pub fn set_payload<V>(mut self, payload: V) -> Self
    where V: Into<Vec<Tlv>>
  {
    self.set_payload_ref(payload);
    self
  }
  pub fn set_payload_ref<V>(&mut self, payload: V)
    where V: Into<Vec<Tlv>>
  {
    let buf: Vec<Tlv> = payload.into();
    self.payload = Some(buf);
  }
  pub fn payload_length(&self) -> u32 {
    match self.payload {
      None => 0,
      Some(ref p) => {
        p.iter().fold(0u32, |mut sum, tlv| {
          sum+=tlv.header().length();
          sum
        })
      }
    }
  }
  pub fn decompressed_buffers(&self) -> &Option<Vec<DecompressedBuffer>> {
    &self.decompressed_buffers
  }
  pub fn set_decompressed_buffers(mut self, buf:Vec<DecompressedBuffer>) -> Self {
    self.set_decompressed_buffers_ref(buf);
    self
  }
  pub fn set_decompressed_buffers_ref(&mut self, buf:Vec<DecompressedBuffer>) {
    self.decompressed_buffers = Some(buf);
  }
  pub fn local(&self) -> bool {
    self.local
  }
  pub fn set_local<B>(mut self, local:B) -> Self
    where B: Into<bool>
  {
    self.set_local_ref(local);
    self
  }
  pub fn set_local_ref<B>(&mut self, local:B)
    where B: Into<bool>
  {
    self.local = local.into();
  }
  pub fn add_tlv(mut self, tlv: Tlv) -> Self {
    self.add_tlv_ref(tlv);
    self
  }
  pub fn add_tlv_ref(&mut self, tlv: Tlv) {
    if let Some(ref mut p) = self.payload {
      p.push(tlv);
    } else {
      let mut vec: Vec<Tlv> = Vec::with_capacity(5);
      vec.push(tlv);
      self.payload = Some(vec);
    }
  }
  pub fn create<T>(pkt_type: TlvPacketType, tlv: T) -> Packet
    where T: Into<Tlv>
  {
    let header = PacketHeader::new()
      .set_type(pkt_type);
    Packet::new()
      .set_header(header)
      .add_tlv(tlv.into())
  }
}
impl From<&[u8]> for Packet {
  fn from(val: &[u8]) -> Packet {
    if val.len() < PACKET_HEADER_SIZE {
      panic!{"Packet::From::<&[u8]> length < {} : {}", PACKET_HEADER_SIZE, val.len()};
    }
    let (header, val) = val.split_at(PACKET_HEADER_SIZE);
    let header: PacketHeader = header.into();
    let mut payload: Option<Vec<Tlv>> = None;
    if header.length() - PACKET_HEADER_SIZE as u32 != 0 {
      let (payload_, val) = val.split_at(header.length() as usize - PACKET_HEADER_SIZE);
      payload = Tlv::slice_to_tlv_vec(payload_);
    }

    Packet {
      header: header,
      payload: payload,
      decompressed_buffers: None,
      local: false,
    }
  }
}
impl From<Vec<u8>> for Packet {
  fn from(val: Vec<u8>) -> Packet {
    if val.len() < PACKET_HEADER_SIZE {
      panic!{"Packet::From::<Vec<u8>> length < {} : {}", PACKET_HEADER_SIZE, val.len()};
    }
    let val: &[u8] = &val;
    val.into()
  }
}
impl Into<Vec<u8>> for Packet {
  fn into(self) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(self.header.length() as usize);
    vec.append(&mut self.header.into());
    if let Some(pay) = self.payload {
      for tlv in pay.into_iter() {
        let mut tlv: Vec<u8> = tlv.into();
        vec.append(&mut tlv);
      }
    }
    vec
  }
}

#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub struct DecompressedBuffer {
  buffer: Vec<u8>,
  length: u32,
}

#[derive(Copy,Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub struct PacketRequestCompletion {

}

#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub struct PacketCompletionRoutineEntry {
  request_id: String,
  handler: PacketRequestCompletion,
}
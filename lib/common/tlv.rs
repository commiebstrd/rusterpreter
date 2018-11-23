use alloc::vec::*;
use super::utils::*;

macro_rules! tlv_value {
  ($meta:expr, $actual:expr) => {
    $actual | $meta
  };
  ($meta:ident, $base:ident, $actual:ident) => {
    ($base + $actual) | $meta
  };
}

pub const BASE_RESERVED:               u32 = 0;
pub const BASE_EXTENSIONS:             u32 = 20000;
pub const BASE_USER:                   u32 = 40000;
pub const BASE_TEMP:                   u32 = 60000;
pub const META_TYPE_NONE:              u32 = 0;
pub const META_TYPE_STRING:            u32 = 0x10000;    // 1 << 16
pub const META_TYPE_UINT:              u32 = 0x20000;    // 1 << 17
pub const META_TYPE_RAW:               u32 = 0x40000;    // 1 << 18
pub const META_TYPE_BOOL:              u32 = 0x80000;    // 1 << 19
pub const META_TYPE_QWORD:             u32 = 0x100000;   // 1 << 20
pub const META_TYPE_COMPRESSED:        u32 = 0x20000000; // 1 << 29
pub const META_TYPE_GROUP:             u32 = 0x40000000; // 1 << 30
pub const META_TYPE_COMPLEX:           u32 = 0x80000000; // 1 << 31
pub const LOAD_LIBRARY_FLAG_ON_DISK:   u32 = 1;          // 1 << 0
pub const LOAD_LIBRARY_FLAG_EXTENSION: u32 = 2;          // 1 << 1
pub const LOAD_LIBRARY_FLAG_LOCAL:     u32 = 4;          // 1 << 2
pub const CHANNEL_FLAG_SYNCHRONOUS:    u32 = 1;          // 1 << 0
pub const CHANNEL_FLAG_COMPRESS:       u32 = 2;          // 1 << 1

pub const TLV_PACKET_TYPE_SIZE: usize = 4;
#[repr(u32)]
#[derive(Copy,Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub enum TlvPacketType {
  Request       = 0,
  Response      = 1,
  PlainRequest  = 10,
  PlainResponse = 11,
  Invalid       = 0xFFFF,
}
impl TlvPacketType {
  pub fn new() -> Self {
    TlvPacketType::Request
  }
}
// instead of Into, use `as u32` to get value
impl From<u32> for TlvPacketType {
  fn from(val: u32) -> TlvPacketType {
    match val {
      0 => TlvPacketType::Request,
      1 => TlvPacketType::Response,
      10 => TlvPacketType::PlainRequest,
      11 => TlvPacketType::PlainResponse,
      _ => TlvPacketType::Invalid,
    }
  }
}
impl From<&[u8]> for TlvPacketType {
  fn from(val: &[u8]) -> TlvPacketType {
    if val.len() < TLV_PACKET_TYPE_SIZE {
      panic!{"Tlv::From::<&[u8]> length < {}: {}", TLV_PACKET_TYPE_SIZE, val.len()};
    }
    let val: u32 = slice_to_u32_ntoh(val);
    TlvPacketType::from(val)
  }
}
impl From<Vec<u8>> for TlvPacketType {
  fn from(val: Vec<u8>) -> TlvPacketType {
    if val.len() < TLV_PACKET_TYPE_SIZE {
      panic!{"Tlv::From::<Vec<u8>> length < {}: {}", TLV_PACKET_TYPE_SIZE, val.len()};
    }
    let val: u32 = slice_to_u32_ntoh(&val);
    TlvPacketType::from(val)
  }
}
impl Into<Vec<u8>> for TlvPacketType {
  fn into(self) -> Vec<u8> {
    u32_to_vec_hton(self as u32)
  }
}

pub const TLV_TYPE_SIZE: usize = 4;
#[repr(u32)]
#[derive(Copy,Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub enum TlvType {
  Any                        = tlv_value!(META_TYPE_NONE,   0),
  Method                     = tlv_value!(META_TYPE_STRING, 1),
  RequestId                  = tlv_value!(META_TYPE_STRING, 2),
  Exception                  = tlv_value!(META_TYPE_GROUP,  3),
  Result                     = tlv_value!(META_TYPE_UINT,   4),
  // Arguments
  String                     = tlv_value!(META_TYPE_STRING, 10),
  Uint                       = tlv_value!(META_TYPE_UINT,   11),
  Bool                       = tlv_value!(META_TYPE_BOOL,   12),
  // Extended
  Length                     = tlv_value!(META_TYPE_UINT,   25),
  Data                       = tlv_value!(META_TYPE_RAW,    26),
  Flags                      = tlv_value!(META_TYPE_UINT,   27),
  // Channels
  ChannelId                  = tlv_value!(META_TYPE_UINT,   50),
  ChannelType                = tlv_value!(META_TYPE_STRING, 51),
  ChanneData                 = tlv_value!(META_TYPE_RAW,    52),
  ChannelClass               = tlv_value!(META_TYPE_UINT,   53),
  ChannelParentId            = tlv_value!(META_TYPE_UINT,   54),
  // Channel Extended
  SeekWhence                 = tlv_value!(META_TYPE_UINT,   70),
  SeekOffset                 = tlv_value!(META_TYPE_UINT,   71),
  SeekPos                    = tlv_value!(META_TYPE_UINT,   72),
  // Group Ids
  ExceptionCode              = tlv_value!(META_TYPE_UINT,   300),
  ExceptionString            = tlv_value!(META_TYPE_STRING, 301),
  // Libraries
  LibraryPath                = tlv_value!(META_TYPE_STRING, 400),
  TargetPath                 = tlv_value!(META_TYPE_STRING, 401),
  MigratePid                 = tlv_value!(META_TYPE_UINT,   402),
  MigratePayloadLength       = tlv_value!(META_TYPE_UINT,   403),
  MigratePayload             = tlv_value!(META_TYPE_STRING, 404),
  MigrateArch                = tlv_value!(META_TYPE_UINT,   405),
  MigrateTechnique           = tlv_value!(META_TYPE_UINT,   406),
  MigrateBaseAddress         = tlv_value!(META_TYPE_UINT,   407),
  MigrateEntryPoint          = tlv_value!(META_TYPE_UINT,   408),
  MigrateSocketPath          = tlv_value!(META_TYPE_STRING, 409),
  MigrateStubLength          = tlv_value!(META_TYPE_UINT,   410),
  MigrateStub                = tlv_value!(META_TYPE_STRING, 411),
  // Transports
  TransportType              = tlv_value!(META_TYPE_UINT,   430),
  TransportUrl               = tlv_value!(META_TYPE_STRING, 431),
  TransportUserAgent         = tlv_value!(META_TYPE_STRING, 432),
  TransportTimeout           = tlv_value!(META_TYPE_UINT,   433),
  TransportSessionExpiration = tlv_value!(META_TYPE_UINT,   434),
  TransportCertificateHash   = tlv_value!(META_TYPE_RAW,    435),
  TransportProxyHost         = tlv_value!(META_TYPE_STRING, 436),
  TransportProxyUser         = tlv_value!(META_TYPE_STRING, 437),
  TransportProxyPass         = tlv_value!(META_TYPE_STRING, 438),
  TransportRetryTotal        = tlv_value!(META_TYPE_UINT,   439),
  TransportRetryWait         = tlv_value!(META_TYPE_UINT,   440),
  TransportHeaders           = tlv_value!(META_TYPE_STRING, 441),
  TransportGroup             = tlv_value!(META_TYPE_GROUP,  442),
  // Ident
  MachineId                  = tlv_value!(META_TYPE_STRING, 460),
  Uuid                       = tlv_value!(META_TYPE_RAW,    461),
  SessionGuid                = tlv_value!(META_TYPE_RAW,    462),
  // Encryption
  RsaPubKey                  = tlv_value!(META_TYPE_STRING, 550),
  SymetricKeyType            = tlv_value!(META_TYPE_UINT,   551),
  SymetricKey                = tlv_value!(META_TYPE_RAW,    552),
  EncryptedSymetricKey       = tlv_value!(META_TYPE_RAW,    553),
  // Pivots
  PivotId                    = tlv_value!(META_TYPE_RAW,    650),
  PivotStageData             = tlv_value!(META_TYPE_RAW,    651),
  PivotStageDataSize         = tlv_value!(META_TYPE_UINT,   652),
  PivotNamedPipeName         = tlv_value!(META_TYPE_STRING, 653),
  // Peering
  PeerHost                   = tlv_value!(META_TYPE_STRING, 1500),
  PeerPort                   = tlv_value!(META_TYPE_UINT,   1501),
  LocalHost                  = tlv_value!(META_TYPE_STRING, 1502),
  LocalPort                  = tlv_value!(META_TYPE_UINT,   1503),
  // Generic
  Extensions                 = tlv_value!(META_TYPE_COMPLEX, BASE_EXTENSIONS),
  User                       = tlv_value!(META_TYPE_COMPLEX, BASE_USER),
  Temp                       = tlv_value!(META_TYPE_COMPLEX, BASE_TEMP),
  Invalid                    = 0xFFFFFFFF
}
impl TlvType {
  pub fn get_type(&self) -> u32 {
    *self as u32 & 0xffff0000
  }
  pub fn get_value(&self) -> u32 {
    *self as u32 & 0x0000ffff
  }
  pub fn is_compressed(&self) -> bool {
    self.get_type() == META_TYPE_COMPRESSED
  }
}
// instead of Into, use `as u32` to get value
impl From<u32> for TlvType {
  fn from(val: u32) -> TlvType {
    match val {
      0x0        => TlvType::Any,
      0x10001    => TlvType::Method,
      0x10002    => TlvType::RequestId,
      0x40000003 => TlvType::Exception,
      0x20004    => TlvType::Result,
      0x1000A    => TlvType::String,
      0x2000B    => TlvType::Uint,
      0x8000C    => TlvType::Bool,
      0x20019    => TlvType::Length,
      0x4001A    => TlvType::Data,
      0x2001B    => TlvType::Flags,
      0x20032    => TlvType::ChannelId,
      0x10033    => TlvType::ChannelType,
      0x40034    => TlvType::ChanneData,
      0x20035    => TlvType::ChannelClass,
      0x20036    => TlvType::ChannelParentId,
      0x20046    => TlvType::SeekWhence,
      0x20047    => TlvType::SeekOffset,
      0x20048    => TlvType::SeekPos,
      0x2012C    => TlvType::ExceptionCode,
      0x1012D    => TlvType::ExceptionString,
      0x10190    => TlvType::LibraryPath,
      0x10191    => TlvType::TargetPath,
      0x20192    => TlvType::MigratePid,
      0x20193    => TlvType::MigratePayloadLength,
      0x10194    => TlvType::MigratePayload,
      0x20195    => TlvType::MigrateArch,
      0x20196    => TlvType::MigrateTechnique,
      0x20197    => TlvType::MigrateBaseAddress,
      0x20198    => TlvType::MigrateEntryPoint,
      0x10199    => TlvType::MigrateSocketPath,
      0x2019A    => TlvType::MigrateStubLength,
      0x1019B    => TlvType::MigrateStub,
      0x201AE    => TlvType::TransportType,
      0x101AF    => TlvType::TransportUrl,
      0x101B0    => TlvType::TransportUserAgent,
      0x201B1    => TlvType::TransportTimeout,
      0x201B2    => TlvType::TransportSessionExpiration,
      0x401B3    => TlvType::TransportCertificateHash,
      0x101B4    => TlvType::TransportProxyHost,
      0x101B5    => TlvType::TransportProxyUser,
      0x101B6    => TlvType::TransportProxyPass,
      0x201B7    => TlvType::TransportRetryTotal,
      0x201B8    => TlvType::TransportRetryWait,
      0x101B9    => TlvType::TransportHeaders,
      0x400001BA => TlvType::TransportGroup,
      0x101CC    => TlvType::MachineId,
      0x401CD    => TlvType::Uuid,
      0x401CE    => TlvType::SessionGuid,
      0x10226    => TlvType::RsaPubKey,
      0x20227    => TlvType::SymetricKeyType,
      0x40228    => TlvType::SymetricKey,
      0x40229    => TlvType::EncryptedSymetricKey,
      0x4028A    => TlvType::PivotId,
      0x4028B    => TlvType::PivotStageData,
      0x2028C    => TlvType::PivotStageDataSize,
      0x1028D    => TlvType::PivotNamedPipeName,
      0x105DC    => TlvType::PeerHost,
      0x205DD    => TlvType::PeerPort,
      0x105DE    => TlvType::LocalHost,
      0x205DF    => TlvType::LocalPort,
      0x80004E20 => TlvType::Extensions,
      0x80009C40 => TlvType::User,
      0x8000EA60 => TlvType::Temp,
      _          => TlvType::Invalid,
    }
  }
}
impl From<&[u8]> for TlvType {
  fn from(val: &[u8]) -> TlvType {
    if val.len() < TLV_TYPE_SIZE {
      panic!{"TlvType::From:<&[u8]> length < {}: {}", TLV_TYPE_SIZE, val.len()};
    }
    let ty: u32 = slice_to_u32_ntoh(val);
    TlvType::from(ty)
  }
}
impl From<Vec<u8>> for TlvType {
  fn from(val: Vec<u8>) -> TlvType {
    if val.len() < TLV_TYPE_SIZE {
      panic!{"TlvType::From:<Vec<u8>> length < {}: {}", TLV_TYPE_SIZE, val.len()};
    }
    let ty: u32 = slice_to_u32_ntoh(&val);
    TlvType::from(ty)
  }
}
impl Into<Vec<u8>> for TlvType {
  fn into(self) -> Vec<u8> {
    u32_to_vec_hton(self as u32)
  }
}
pub const TLV_HEADER_SIZE: usize = 8;
#[derive(Copy,Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub struct TlvHeader {
  length: u32,
  type_: TlvType,
}
impl TlvHeader {
  pub fn new() -> Self {
    TlvHeader {
      length: 8,
      type_: TlvType::Any,
    }
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
  pub fn get_type(&self) -> TlvType {
    self.type_
  }
  pub fn get_mut_type(&mut self) -> &mut TlvType {
    &mut self.type_
  }
  pub fn set_type<T>(mut self, ty: T) -> Self
    where T: Into<TlvType>
  {
    self.set_type_ref(ty);
    self
  }
  pub fn set_type_ref<T>(&mut self, ty: T)
    where T: Into<TlvType>
  {
    self.type_ = ty.into();
  }
}
impl From<&[u8]> for TlvHeader {
  fn from(val: &[u8]) -> TlvHeader {
    if val.len() < TLV_HEADER_SIZE {
      panic!{"TlvHeader::From::<&[u8]> length"}
    }
    let length: u32 = slice_to_u32_ntoh(val);

    let type_: &[u8] = &val[4..];
    let type_: TlvType = type_.into();

    TlvHeader {
      length: length,
      type_: type_,
    }
  }
}
impl From<Vec<u8>> for TlvHeader {
  fn from(val: Vec<u8>) -> TlvHeader {
    if val.len() < TLV_HEADER_SIZE {
      panic!{"TlvHeader::From::<Vec<u8>> length"}
    }
    let header: &[u8] = &val[..];
    let header: TlvHeader = header.into();
    header
  }
}
impl Into<Vec<u8>> for TlvHeader {
  fn into(self) -> Vec<u8> {
    let mut vec: Vec<u8> = u32_to_vec_hton(self.length);
    let mut ty: Vec<u8> = self.type_.into();
    vec.append(&mut ty);
    vec
  }
}

#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub struct Tlv {
  header: TlvHeader,
  buffer: Vec<u8>,
}
impl Tlv {
  pub fn header(&self) -> &TlvHeader {
    &self.header
  }
  pub fn mut_header(&mut self) -> &mut TlvHeader {
    &mut self.header
  }
  pub fn set_header<T>(mut self, header: T) -> Self
    where T: Into<TlvHeader>
  {
    self.set_header_ref(header);
    self
  }
  pub fn set_header_ref<T>(&mut self, header: T)
    where T: Into<TlvHeader>
  {
    self.header = header.into();
  }
  pub fn buffer(&self) -> &Vec<u8> {
    self.buffer.as_ref()
  }
  pub fn mut_buffer(&mut self) -> &mut Vec<u8> {
    &mut self.buffer
  }
  pub fn set_buffer<B>(mut self, buf: B) -> Self
    where B: Into<Vec<u8>>
  {
    self.set_buffer_ref(buf);
    self
  }
  pub fn set_buffer_ref<B>(&mut self, buf: B)
    where B: Into<Vec<u8>>
  {
    self.buffer = buf.into();
  }
  pub fn slice_to_tlv_vec(slice: &[u8]) -> Option<Vec<Tlv>> {
    if slice.len() < TLV_HEADER_SIZE {
      return None
    }
    let mut vec: Vec<Tlv> = Vec::with_capacity(slice.len() / TLV_HEADER_SIZE);
    while TLV_HEADER_SIZE <= slice.len() {
      let (header, slice) = slice.split_at(TLV_HEADER_SIZE);
      let header: TlvHeader = header.into();
      let (buffer, slice) = slice.split_at(header.length() as usize);
      let buffer: Vec<u8> = buffer.to_vec();
      let tlv = Tlv {
        header: header,
        buffer: buffer,
      };
      vec.push(tlv);
    }

    Some(vec)
  }
}
impl From<&[u8]> for Tlv {
  fn from(val: &[u8]) -> Tlv {
    if val.len() < TLV_HEADER_SIZE {
      panic!{"Tlv::From:<&[u8]> length < {}: {}", TLV_HEADER_SIZE, val.len()};
    }

    let (header, buffer) = val.split_at(TLV_HEADER_SIZE);
    let header: TlvHeader = header.into();
    let buffer: Vec<u8> = buffer.to_vec();

    Tlv {
      header: header,
      buffer: buffer,
    }
  }
}
impl From<Vec<u8>> for Tlv {
  fn from(val: Vec<u8>) -> Tlv {
    if val.len() < TLV_HEADER_SIZE {
      panic!{"Tlv::From:<Vec<u8>> length < {}: {}", TLV_HEADER_SIZE, val.len()};
    }
    let val: &[u8] = &val[..];
    let tlv: Tlv = val.into();
    tlv
  }
}
impl Into<Vec<u8>> for Tlv {
  fn into(self) -> Vec<u8> {
    let mut tlv: Vec<u8> = self.header.into();
    tlv.extend(self.buffer.iter().clone());
    tlv
  }
}

pub mod utils;
pub mod tlv;
pub mod packet;

pub mod prelude {
  pub use super::tlv::TlvPacketType;
  pub use super::tlv::TLV_PACKET_TYPE_SIZE;
  pub use super::tlv::TlvType;
  pub use super::tlv::TLV_TYPE_SIZE;
  pub use super::tlv::TlvHeader;
  pub use super::tlv::TLV_HEADER_SIZE;
  pub use super::tlv::Tlv;

  pub use super::packet::XorKey;
  pub use super::packet::XOR_KEY_SIZE;
  pub use super::packet::GuidBytes;
  pub use super::packet::GUID_SIZE;
  pub use super::packet::PacketHeader;
  pub use super::packet::PACKET_HEADER_SIZE;
  pub use super::packet::Packet;
  pub use super::packet::NULL_PACKET_SIZE;
  pub use super::packet::DecompressedBuffer;
}

#[cfg(test)] mod test;
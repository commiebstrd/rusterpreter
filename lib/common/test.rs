pub use super::prelude::*;
pub use core::mem::size_of;
use alloc::vec::*;

mod tlv {
  use super::*;
  use crate::common::tlv::*;

  #[test]
  fn static_lengths() {
    assert_eq!{size_of::<TlvPacketType>(), TLV_PACKET_TYPE_SIZE};
    assert_eq!{size_of::<TlvType>(), TLV_TYPE_SIZE};
    assert_eq!{size_of::<TlvHeader>(), TLV_HEADER_SIZE};
  }
  #[test]
  fn type_to_u32() {
    assert_eq!{TlvType::Any as u32, 0x0};
    assert_eq!{TlvType::Method as u32, 0x10001};
    assert_eq!{TlvType::RequestId as u32, 0x10002};
    assert_eq!{TlvType::Exception as u32, 0x40000003};
    assert_eq!{TlvType::Result as u32, 0x20004};
    assert_eq!{TlvType::String as u32, 0x1000A};
    assert_eq!{TlvType::Uint as u32, 0x2000B};
    assert_eq!{TlvType::Bool as u32, 0x8000C};
    assert_eq!{TlvType::Length as u32, 0x20019};
    assert_eq!{TlvType::Data as u32, 0x4001A};
    assert_eq!{TlvType::Flags as u32, 0x2001B};
    assert_eq!{TlvType::ChannelId as u32, 0x20032};
    assert_eq!{TlvType::ChannelType as u32, 0x10033};
    assert_eq!{TlvType::ChanneData as u32, 0x40034};
    assert_eq!{TlvType::ChannelClass as u32, 0x20035};
    assert_eq!{TlvType::ChannelParentId as u32, 0x20036};
    assert_eq!{TlvType::SeekWhence as u32, 0x20046};
    assert_eq!{TlvType::SeekOffset as u32, 0x20047};
    assert_eq!{TlvType::SeekPos as u32, 0x20048};
    assert_eq!{TlvType::ExceptionCode as u32, 0x2012C};
    assert_eq!{TlvType::ExceptionString as u32, 0x1012D};
    assert_eq!{TlvType::LibraryPath as u32, 0x10190};
    assert_eq!{TlvType::TargetPath as u32, 0x10191};
    assert_eq!{TlvType::MigratePid as u32, 0x20192};
    assert_eq!{TlvType::MigratePayloadLength as u32, 0x20193};
    assert_eq!{TlvType::MigratePayload as u32, 0x10194};
    assert_eq!{TlvType::MigrateArch as u32, 0x20195};
    assert_eq!{TlvType::MigrateTechnique as u32, 0x20196};
    assert_eq!{TlvType::MigrateBaseAddress as u32, 0x20197};
    assert_eq!{TlvType::MigrateEntryPoint as u32, 0x20198};
    assert_eq!{TlvType::MigrateSocketPath as u32, 0x10199};
    assert_eq!{TlvType::MigrateStubLength as u32, 0x2019A};
    assert_eq!{TlvType::MigrateStub as u32, 0x1019B};
    assert_eq!{TlvType::TransportType as u32, 0x201AE};
    assert_eq!{TlvType::TransportUrl as u32, 0x101AF};
    assert_eq!{TlvType::TransportUserAgent as u32, 0x101B0};
    assert_eq!{TlvType::TransportTimeout as u32, 0x201B1};
    assert_eq!{TlvType::TransportSessionExpiration as u32, 0x201B2};
    assert_eq!{TlvType::TransportCertificateHash as u32, 0x401B3};
    assert_eq!{TlvType::TransportProxyHost as u32, 0x101B4};
    assert_eq!{TlvType::TransportProxyUser as u32, 0x101B5};
    assert_eq!{TlvType::TransportProxyPass as u32, 0x101B6};
    assert_eq!{TlvType::TransportRetryTotal as u32, 0x201B7};
    assert_eq!{TlvType::TransportRetryWait as u32, 0x201B8};
    assert_eq!{TlvType::TransportHeaders as u32, 0x101B9};
    assert_eq!{TlvType::TransportGroup as u32, 0x400001BA};
    assert_eq!{TlvType::MachineId as u32, 0x101CC};
    assert_eq!{TlvType::Uuid as u32, 0x401CD};
    assert_eq!{TlvType::SessionGuid as u32, 0x401CE};
    assert_eq!{TlvType::RsaPubKey as u32, 0x10226};
    assert_eq!{TlvType::SymetricKeyType as u32, 0x20227};
    assert_eq!{TlvType::SymetricKey as u32, 0x40228};
    assert_eq!{TlvType::EncryptedSymetricKey as u32, 0x40229};
    assert_eq!{TlvType::PivotId as u32, 0x4028A};
    assert_eq!{TlvType::PivotStageData as u32, 0x4028B};
    assert_eq!{TlvType::PivotStageDataSize as u32, 0x2028C};
    assert_eq!{TlvType::PivotNamedPipeName as u32, 0x1028D};
    assert_eq!{TlvType::PeerHost as u32, 0x105DC};
    assert_eq!{TlvType::PeerPort as u32, 0x205DD};
    assert_eq!{TlvType::LocalHost as u32, 0x105DE};
    assert_eq!{TlvType::LocalPort as u32, 0x205DF};
    assert_eq!{TlvType::Extensions as u32, 0x80004E20};
    assert_eq!{TlvType::User as u32, 0x80009C40};
    assert_eq!{TlvType::Temp as u32, 0x8000EA60};
    assert_eq!{TlvType::Invalid as u32, 0xFFFFFFFF};
  }
  #[test]
  fn type_from_u32() {
    let tlv: TlvType = 0x0.into();
    assert_eq!{tlv, TlvType::Any};
    let tlv: TlvType = 0x10001.into();
    assert_eq!{tlv, TlvType::Method};
    let tlv: TlvType = 0x10002.into();
    assert_eq!{tlv, TlvType::RequestId};
    let tlv: TlvType = 0x40000003.into();
    assert_eq!{tlv, TlvType::Exception};
    let tlv: TlvType = 0x20004.into();
    assert_eq!{tlv, TlvType::Result};
    let tlv: TlvType = 0x1000A.into();
    assert_eq!{tlv, TlvType::String};
    let tlv: TlvType = 0x2000B.into();
    assert_eq!{tlv, TlvType::Uint};
    let tlv: TlvType = 0x8000C.into();
    assert_eq!{tlv, TlvType::Bool};
    let tlv: TlvType = 0x20019.into();
    assert_eq!{tlv, TlvType::Length};
    let tlv: TlvType = 0x4001A.into();
    assert_eq!{tlv, TlvType::Data};
    let tlv: TlvType = 0x2001B.into();
    assert_eq!{tlv, TlvType::Flags};
    let tlv: TlvType = 0x20032.into();
    assert_eq!{tlv, TlvType::ChannelId};
    let tlv: TlvType = 0x10033.into();
    assert_eq!{tlv, TlvType::ChannelType};
    let tlv: TlvType = 0x40034.into();
    assert_eq!{tlv, TlvType::ChanneData};
    let tlv: TlvType = 0x20035.into();
    assert_eq!{tlv, TlvType::ChannelClass};
    let tlv: TlvType = 0x20036.into();
    assert_eq!{tlv, TlvType::ChannelParentId};
    let tlv: TlvType = 0x20046.into();
    assert_eq!{tlv, TlvType::SeekWhence};
    let tlv: TlvType = 0x20047.into();
    assert_eq!{tlv, TlvType::SeekOffset};
    let tlv: TlvType = 0x20048.into();
    assert_eq!{tlv, TlvType::SeekPos};
    let tlv: TlvType = 0x2012C.into();
    assert_eq!{tlv, TlvType::ExceptionCode};
    let tlv: TlvType = 0x1012D.into();
    assert_eq!{tlv, TlvType::ExceptionString};
    let tlv: TlvType = 0x10190.into();
    assert_eq!{tlv, TlvType::LibraryPath};
    let tlv: TlvType = 0x10191.into();
    assert_eq!{tlv, TlvType::TargetPath};
    let tlv: TlvType = 0x20192.into();
    assert_eq!{tlv, TlvType::MigratePid};
    let tlv: TlvType = 0x20193.into();
    assert_eq!{tlv, TlvType::MigratePayloadLength};
    let tlv: TlvType = 0x10194.into();
    assert_eq!{tlv, TlvType::MigratePayload};
    let tlv: TlvType = 0x20195.into();
    assert_eq!{tlv, TlvType::MigrateArch};
    let tlv: TlvType = 0x20196.into();
    assert_eq!{tlv, TlvType::MigrateTechnique};
    let tlv: TlvType = 0x20197.into();
    assert_eq!{tlv, TlvType::MigrateBaseAddress};
    let tlv: TlvType = 0x20198.into();
    assert_eq!{tlv, TlvType::MigrateEntryPoint};
    let tlv: TlvType = 0x10199.into();
    assert_eq!{tlv, TlvType::MigrateSocketPath};
    let tlv: TlvType = 0x2019A.into();
    assert_eq!{tlv, TlvType::MigrateStubLength};
    let tlv: TlvType = 0x1019B.into();
    assert_eq!{tlv, TlvType::MigrateStub};
    let tlv: TlvType = 0x201AE.into();
    assert_eq!{tlv, TlvType::TransportType};
    let tlv: TlvType = 0x101AF.into();
    assert_eq!{tlv, TlvType::TransportUrl};
    let tlv: TlvType = 0x101B0.into();
    assert_eq!{tlv, TlvType::TransportUserAgent};
    let tlv: TlvType = 0x201B1.into();
    assert_eq!{tlv, TlvType::TransportTimeout};
    let tlv: TlvType = 0x201B2.into();
    assert_eq!{tlv, TlvType::TransportSessionExpiration};
    let tlv: TlvType = 0x401B3.into();
    assert_eq!{tlv, TlvType::TransportCertificateHash};
    let tlv: TlvType = 0x101B4.into();
    assert_eq!{tlv, TlvType::TransportProxyHost};
    let tlv: TlvType = 0x101B5.into();
    assert_eq!{tlv, TlvType::TransportProxyUser};
    let tlv: TlvType = 0x101B6.into();
    assert_eq!{tlv, TlvType::TransportProxyPass};
    let tlv: TlvType = 0x201B7.into();
    assert_eq!{tlv, TlvType::TransportRetryTotal};
    let tlv: TlvType = 0x201B8.into();
    assert_eq!{tlv, TlvType::TransportRetryWait};
    let tlv: TlvType = 0x101B9.into();
    assert_eq!{tlv, TlvType::TransportHeaders};
    let tlv: TlvType = 0x400001BA.into();
    assert_eq!{tlv, TlvType::TransportGroup};
    let tlv: TlvType = 0x101CC.into();
    assert_eq!{tlv, TlvType::MachineId};
    let tlv: TlvType = 0x401CD.into();
    assert_eq!{tlv, TlvType::Uuid};
    let tlv: TlvType = 0x401CE.into();
    assert_eq!{tlv, TlvType::SessionGuid};
    let tlv: TlvType = 0x10226.into();
    assert_eq!{tlv, TlvType::RsaPubKey};
    let tlv: TlvType = 0x20227.into();
    assert_eq!{tlv, TlvType::SymetricKeyType};
    let tlv: TlvType = 0x40228.into();
    assert_eq!{tlv, TlvType::SymetricKey};
    let tlv: TlvType = 0x40229.into();
    assert_eq!{tlv, TlvType::EncryptedSymetricKey};
    let tlv: TlvType = 0x4028A.into();
    assert_eq!{tlv, TlvType::PivotId};
    let tlv: TlvType = 0x4028B.into();
    assert_eq!{tlv, TlvType::PivotStageData};
    let tlv: TlvType = 0x2028C.into();
    assert_eq!{tlv, TlvType::PivotStageDataSize};
    let tlv: TlvType = 0x1028D.into();
    assert_eq!{tlv, TlvType::PivotNamedPipeName};
    let tlv: TlvType = 0x105DC.into();
    assert_eq!{tlv, TlvType::PeerHost};
    let tlv: TlvType = 0x205DD.into();
    assert_eq!{tlv, TlvType::PeerPort};
    let tlv: TlvType = 0x105DE.into();
    assert_eq!{tlv, TlvType::LocalHost};
    let tlv: TlvType = 0x205DF.into();
    assert_eq!{tlv, TlvType::LocalPort};
    let tlv: TlvType = 0x80004E20.into();
    assert_eq!{tlv, TlvType::Extensions};
    let tlv: TlvType = 0x80009C40.into();
    assert_eq!{tlv, TlvType::User};
    let tlv: TlvType = 0x8000EA60.into();
    assert_eq!{tlv, TlvType::Temp};
    let tlv: TlvType = 0xFFFFFFFF.into();
    assert_eq!{tlv, TlvType::Invalid};
  }
  #[test]
  fn pkt_type_convert() {
    let pkt: Vec<u8> = TlvPacketType::Request.into();
    let rst: Vec<u8> = [0u8,0u8,0u8,0u8].to_vec();
    assert_eq!{pkt, rst};
    assert_eq!{TlvPacketType::Request, rst.into()};

    let pkt: Vec<u8> = TlvPacketType::Response.into();
    let rst: Vec<u8> = [1u8,0u8,0u8,0u8].to_vec();
    assert_eq!{pkt, rst};
    assert_eq!{TlvPacketType::Response, rst.into()};

    let pkt: Vec<u8> = TlvPacketType::PlainRequest.into();
    let rst: Vec<u8> = [10u8,0u8,0u8,0u8].to_vec();
    assert_eq!{pkt, rst};
    assert_eq!{TlvPacketType::PlainRequest, rst.into()};

    let pkt: Vec<u8> = TlvPacketType::PlainResponse.into();
    let rst: Vec<u8> = [11u8,0u8,0u8,0u8].to_vec();
    assert_eq!{pkt, rst};
    assert_eq!{TlvPacketType::PlainResponse, rst.into()};
  }
}

mod packet {
  use super::*;
  use crate::common::packet::*;

  #[test]
  fn static_lengths() {
    assert_eq!{size_of::<XorKey>(), XOR_KEY_SIZE};
    assert_eq!{size_of::<GuidBytes>(), GUID_SIZE};
    assert_eq!{size_of::<PacketHeader>(), PACKET_HEADER_SIZE};
  }
}
#!python3

consts = {
  'BASE_RESERVED': 0,
  'BASE_EXTENSIONS': 20000,
  'BASE_USER': 40000,
  'BASE_TEMP': 60000,
  'META_TYPE_NONE': 0,
  'META_TYPE_STRING': 0x10000,
  'META_TYPE_UINT': 0x20000,
  'META_TYPE_RAW': 0x40000,
  'META_TYPE_BOOL': 0x80000,
  'META_TYPE_QWORD': 0x100000,
  'META_TYPE_COMPRESSED': 0x20000000,
  'META_TYPE_GROUP': 0x40000000,
  'META_TYPE_COMPLEX': 0x80000000,
  'LOAD_LIBRARY_FLAG_ON_DISK': 1,
  'LOAD_LIBRARY_FLAG_EXTENSION': 2,
  'LOAD_LIBRARY_FLAG_LOCAL': 4,
  'CHANNEL_FLAG_SYNCHRONOUS': 1,
  'CHANNEL_FLAG_COMPRESS': 2,
}
types = [
  ('Any', ('META_TYPE_NONE', 0)),
  ('Method', ('META_TYPE_STRING', 1)),
  ('RequestId', ('META_TYPE_STRING', 2)),
  ('Exception', ('META_TYPE_GROUP', 3)),
  ('Result', ('META_TYPE_UINT', 4)),
  # Arguments
  ('String', ('META_TYPE_STRING', 10)),
  ('Uint', ('META_TYPE_UINT', 11)),
  ('Bool', ('META_TYPE_BOOL', 12)),
  # Extended
  ('Length', ('META_TYPE_UINT', 25)),
  ('Data', ('META_TYPE_RAW', 26)),
  ('Flags', ('META_TYPE_UINT', 27)),
  # Channels
  ('ChannelId', ('META_TYPE_UINT', 50)),
  ('ChannelType', ('META_TYPE_STRING', 51)),
  ('ChanneData', ('META_TYPE_RAW', 52)),
  ('ChannelClass', ('META_TYPE_UINT', 53)),
  ('ChannelParentId', ('META_TYPE_UINT', 54)),
  # Channel Extended
  ('SeekWhence', ('META_TYPE_UINT', 70)),
  ('SeekOffset', ('META_TYPE_UINT', 71)),
  ('SeekPos', ('META_TYPE_UINT', 72)),
  # Group Ids
  ('ExceptionCode', ('META_TYPE_UINT', 300)),
  ('ExceptionString', ('META_TYPE_STRING', 301)),
  # Libraries
  ('LibraryPath', ('META_TYPE_STRING', 400)),
  ('TargetPath', ('META_TYPE_STRING', 401)),
  ('MigratePid', ('META_TYPE_UINT', 402)),
  ('MigratePayloadLength', ('META_TYPE_UINT', 403)),
  ('MigratePayload', ('META_TYPE_STRING', 404)),
  ('MigrateArch', ('META_TYPE_UINT', 405)),
  ('MigrateTechnique', ('META_TYPE_UINT', 406)),
  ('MigrateBaseAddress', ('META_TYPE_UINT', 407)),
  ('MigrateEntryPoint', ('META_TYPE_UINT', 408)),
  ('MigrateSocketPath', ('META_TYPE_STRING', 409)),
  ('MigrateStubLength', ('META_TYPE_UINT', 410)),
  ('MigrateStub', ('META_TYPE_STRING', 411)),
  # Transports
  ('TransportType', ('META_TYPE_UINT', 430)),
  ('TransportUrl', ('META_TYPE_STRING', 431)),
  ('TransportUserAgent', ('META_TYPE_STRING', 432)),
  ('TransportTimeout', ('META_TYPE_UINT', 433)),
  ('TransportSessionExpiration', ('META_TYPE_UINT', 434)),
  ('TransportCertificateHash', ('META_TYPE_RAW', 435)),
  ('TransportProxyHost', ('META_TYPE_STRING', 436)),
  ('TransportProxyUser', ('META_TYPE_STRING', 437)),
  ('TransportProxyPass', ('META_TYPE_STRING', 438)),
  ('TransportRetryTotal', ('META_TYPE_UINT', 439)),
  ('TransportRetryWait', ('META_TYPE_UINT', 440)),
  ('TransportHeaders', ('META_TYPE_STRING', 441)),
  ('TransportGroup', ('META_TYPE_GROUP', 442)),
  # Ident
  ('MachineId', ('META_TYPE_STRING', 460)),
  ('Uuid', ('META_TYPE_RAW', 461)),
  ('SessionGuid', ('META_TYPE_RAW', 462)),
  # Encryption
  ('RsaPubKey', ('META_TYPE_STRING', 550)),
  ('SymetricKeyType', ('META_TYPE_UINT', 551)),
  ('SymetricKey', ('META_TYPE_RAW', 552)),
  ('EncryptedSymetricKey', ('META_TYPE_RAW', 553)),
  # Pivots
  ('PivotId', ('META_TYPE_RAW', 650)),
  ('PivotStageData', ('META_TYPE_RAW', 651)),
  ('PivotStageDataSize', ('META_TYPE_UINT', 652)),
  ('PivotNamedPipeName', ('META_TYPE_STRING', 653)),
  # Peering
  ('PeerHost', ('META_TYPE_STRING', 1500)),
  ('PeerPort', ('META_TYPE_UINT', 1501)),
  ('LocalHost', ('META_TYPE_STRING', 1502)),
  ('LocalPort', ('META_TYPE_UINT', 1503)),
  # Generic
  ('Extensions', ('META_TYPE_COMPLEX', 'BASE_EXTENSIONS')),
  ('User', ('META_TYPE_COMPLEX', 'BASE_USER')),
  ('Temp', ('META_TYPE_COMPLEX', 'BASE_TEMP')),
  ('Invalid', (None, 0xFFFFFFFF))
]

for ty, tup in types:
    meta, actual = tup
    meta_val = consts.get(meta) if isinstance(meta, str) else 0
    actual_val = actual if isinstance(actual, int) else consts.get(actual)
    print("0x{:X} => TlvType::{:s},".format(meta_val | actual_val, ty))
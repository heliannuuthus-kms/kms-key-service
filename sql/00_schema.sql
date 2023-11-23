CREATE TABLE IF NOT EXISTS t_kms (
  _id BIGINT NOT NULL AUTO_INCREMENT,
  kms_id VARCHAR(32) NOT NULL COMMENT "kms 实例标识",
  name VARCHAR(32) NOT NULL COMMENT "kms 实例名称",
  description TEXT COMMENT "kms 实例描述信息",
  updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT NOW(),
  PRIMARY KEY(_id),
  UNIQUE uniq_key_id(kms_id),
  INDEX idx_kms_name(kms_id)
);

CREATE TABLE IF NOT EXISTS t_key (
  _id BIGINT NOT NULL AUTO_INCREMENT,
  kms_id VARCHAR(32) NOT NULL COMMENT "kms 实例标识",
  key_id VARCHAR(32) NOT NULL COMMENT "主密钥标识",
  key_type ENUM('SYMMETRIC', "ASYMMETRIC", "UNKNWON") NOT NULL COMMENT "密钥类型 0: Symmetric，1: Asymmetric, 2: Unknown",
  key_pair JSON COMMENT "密钥内容",
  `version` VARCHAR(32) NOT NULL COMMENT "密钥版本",
  updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT NOW(),
  PRIMARY KEY(_id),
  INDEX idx_key_id(key_id),
  UNIQUE uniq_key_id_version(key_id, `version`),
  INDEX idx_kms_id(kms_id)
);

CREATE TABLE IF NOT EXISTS t_key_meta (
  _id BIGINT NOT NULL AUTO_INCREMENT,
  kms_id VARCHAR(32) NOT NULL COMMENT "kms 实例标识",
  key_id VARCHAR(32) NOT NULL COMMENT "主密钥标识",
  spec ENUM(
    "AES_128",
    "AES_256",
    "RSA_2048",
    "RSA_3072",
    "EC_P256",
    "EC_P256k"
  ) NOT NULL COMMENT "密钥规格",
  origin ENUM("KMS", "EXTERNAL") NOT NULL COMMENT "密钥来源，0: kms 创建，1: 密钥材料导入",
  description TEXT COMMENT "密钥描述",
  state ENUM(
    "ENABLE",
    "DISABLE",
    "PENDING_DELETION",
    "PENDING_IMPORT"
  ) NOT NULL COMMENT "密钥状态, 0: enable，1: disable，2: pending_deletion，3: pending_import",
  `usage` ENUM("ENCRYPT/DECRYPT", "SIGN/VERIFY") NOT NULL COMMENT "密钥用途，0: encrypt/decrypt，1: sign/verify",
  `version` VARCHAR(32) NOT NULL COMMENT "密钥版本",
  primary_version VARCHAR(32) NOT NULL COMMENT "主密钥版本",
  creator VARCHAR(32) NOT NULL COMMENT "密钥创建者",
  rotation_interval BIGINT NOT NULL COMMENT "密钥轮换周期，开启轮换 > 0，不开启为 -1",
  material_expire_at DATETIME COMMENT "密钥材料过期时间",
  last_rotation_at DATETIME COMMENT "密钥上次轮换事件，为 null 表示未发生过轮换",
  deletion_at DATETIME COMMENT "密钥预计删除时间 null 表示不删除",
  updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT NOW(),
  PRIMARY KEY(_id),
  INDEX idx_key_id(key_id),
  UNIQUE uniq_key_id_version(key_id, `version`)
);

CREATE TABLE IF NOT EXISTS t_key_alias (
  _id BIGINT NOT NULL AUTO_INCREMENT,
  key_id VARCHAR(32) NOT NULL COMMENT "主密钥标识",
  alias VARCHAR(255) NOT NULL COMMENT "密钥别名",
  updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT NOW(),
  PRIMARY KEY(_id),
  INDEX idx_key_id(key_id),
  UNIQUE uniq_key_alias(`alias`)
)
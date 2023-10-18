CREATE TABLE IF NOT EXISTS t_secret (
  id BIGINT NOT NULL AUTO_INCREMENT,
  key_id VARCHAR(128) NOT NULL COMMENT "密钥标识",
  primary_key_id VARCHAR(128) NOT NULL COMMENT "主密钥标识, 如果是主密钥及为 '#' 缺省值",
  key_type ENUM('SYMMETRIC', "ASYMMETRIC", "UNKNWON") NOT NULL COMMENT "密钥类型 0: Symmetric，1: Asymmetric, 2: Unknown",
  key_pair VARCHAR(512) COMMENT "对称密钥",
  pub_key VARCHAR(4096) COMMENT "非对称密钥公钥",
  pri_key VARCHAR(4096) COMMENT "非称密钥私钥",
  updated_at TIMESTAMP NOT NULL DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY(id),
  UNIQUE uniq_key_id(key_id),
  UNIQUE uniq_key_id_type(key_id, key_type),
  INDEX idx_primary_key_id(primary_key_id)
);
CREATE TABLE IF NOT EXISTS t_secret_meta (
  id BIGINT NOT NULL AUTO_INCREMENT,
  key_id VARCHAR(32) NOT NULL COMMENT "密钥标识",
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
    "IMPORT_DELETION"
  ) NOT NULL COMMENT "密钥状态, 0: enable，1: disable，2: pending_deletion，3: import_deletion",
  `usage` ENUM("ENCRYPT/DECRYPT", "SIGN/VERIFY") NOT NULL COMMENT "密钥用途，0: encrypt/decrypt，1: sign/verify",
  rotation_interval BIGINT NOT NULL COMMENT "密钥轮换周期，开启轮换 > 0，不开启为 -1",
  creator VARCHAR(32) NOT NULL COMMENT "密钥创建者",
  material_expire_at TIMESTAMP COMMENT "密钥材料过期时间",
  last_rotation_at TIMESTAMP COMMENT "密钥上次轮换事件，为 null 表示未发生过轮换",
  deletion_at TIMESTAMP COMMENT "密钥预计删除时间 null 表示不删除",
  updated_at TIMESTAMP NOT NULL DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY(id),
  UNIQUE uniq_key_id(key_id)
);
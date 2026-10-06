# Local X.509 Certificate Chain Verifier

一个完全本地的 X.509 证书链验证工具。所有证书、信任根（trust anchor）、
策略和验证结果只来源于本地文件或内存——**不访问**在线 CA、OCSP、CRL
分发点、AIA 或任何网络/外部服务。

## 信任模型

- 信任完全来自**显式本地配置**的 trust anchor 集合（`--root` 文件或
  `trust_anchors=[...]` 内存对象）。没有隐式系统信任库。
- 链的终止条件是：当前证书的 issuer 名称匹配某个 anchor 的 subject，
  **并且签名能用该 anchor 的公钥验证通过**。仅凭名称匹配绝不判定可信
  （见测试 `test_name_match_alone_is_not_trust`）。
- 如果 leaf 本身就是配置的 anchor，其（自）签名也必须验证通过。
- 不做吊销检查（无 OCSP/CRL），这是本工具有意划定的边界；/revocation
  状态不会从网络获取。

## 支持的加载方式

- PEM（单个或 bundle 文件）、DER 文件，来自本地路径（`load_certificates`）。
- 内存中的证书对象（`trust_anchors=[cert]` 直接传入）。

## 支持的扩展校验

- **Basic Constraints**：非 anchor 证书必须携带该扩展；被用作 issuer 的
  证书必须 `CA=TRUE`，否则报 `NOT_A_CA`（leaf 不会被误用作中间 CA）。
- **Key Usage**：issuer 的 Key Usage 若存在，必须包含 `keyCertSign`。
- **Extended Key Usage**：可通过 `required_eku` 要求 leaf 具备指定用途
  （如 `serverAuth`），缺失报 `EKU_MISMATCH` / `EKU_MISSING`。
- **Path Length Constraint**：CA 的 `pathLenConstraint` 限制其下允许的
  CA 证书数量，违反报 `PATH_LENGTH_EXCEEDED`。

## 验证顺序

1. **链构建**（`ChainBuilder`）：从 leaf 向上，按 issuer/subject 名称
   在本地证书池中找候选 issuer，并用候选者公钥实际验证签名：
   - 无候选 → `INCOMPLETE_CHAIN`
   - 名称匹配但签名全失败 → `SIGNATURE_INVALID`
   - 候选已在当前路径中 → `CHAIN_CYCLE`
   - 多个候选签名均有效 → 记录 `AMBIGUOUS_ISSUER` 警告并逐一回溯尝试
   - 超过 `max_depth` → `CHAIN_TOO_DEEP`
2. **链校验**（`ChainValidator`）：对签名已验证的候选链依次检查
   有效期（NotBefore/NotAfter，含 anchor）、Basic Constraints、
   Key Usage、path length、leaf EKU。

所有诊断都带 `code`、`position`（链中位置，0 = leaf）和 `subject`，
可精确定位问题证书。

## 时间注入

`LocalChainVerifier(at_time=...)` 与 `ChainValidator(at_time=...)` 接受
任意 `datetime`，默认当前时间。过期（`EXPIRED`）与尚未生效
（`NOT_YET_VALID`）证书因此可以稳定测试。

## 使用

```bash
# 直接验证（链终止于本地 root）
python -m x509chain --root root.pem --intermediate inter.pem \
    --leaf leaf.pem --at-time 2026-01-01T00:00:00+00:00

# 要求 leaf 具备 serverAuth EKU
python -m x509chain --root root.pem --intermediate inter.pem \
    --leaf leaf.pem --eku serverAuth
```

`LocalChainVerifier` 也可作为库使用（见 `x509chain/verifier.py`），
返回的 `VerificationResult` 包含完整诊断列表。

## 运行测试

```bash
python3 -m pytest            # 全部 20 个测试，纯本地执行
```

测试在 `tests/conftest.py` 中现场生成小型 root/intermediate/leaf 链，
覆盖：有效链（内存与 PEM/DER 文件）、过期、尚未生效、错误 issuer、
伪造签名、名称冒充信任根、leaf 误用作 CA、CA 缺少 keyCertSign、
path length 违反与满足、EKU 不匹配、循环链、多候选 issuer、
链深度限制、PEM bundle 加载。

## 项目结构

```
x509chain/
  __init__.py    # 包导出
  __main__.py    # CLI 入口（python -m x509chain）
  loader.py      # PEM/DER/内存加载
  crypto.py      # 签名验证原语
  builder.py     # 候选链构建（循环/歧义/深度诊断）
  validator.py   # 时间、BC、KU、EKU、path length 校验
  verifier.py    # 高层 API（LocalChainVerifier）
  errors.py      # 可定位诊断类型
tests/
  conftest.py    # 本地证书链生成夹具
  test_chain_verification.py
```

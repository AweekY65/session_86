# certchain — 完全本地的 X.509 证书链验证工具

`certchain` 在纯本地环境下构建并验证 X.509 证书链。所有证书、信任根、
策略与验证时间均来自本地文件或内存注入，**绝不访问** 在线 CA、OCSP、
CRL 分发点、AIA 抓取或任何网络 API / 外部服务。

## 信任模型

- 信任仅来源于**显式配置**的 trust anchor 集合（`CertStore(trust_anchors=...)`
  或 CLI 的 `--root`）。
- 链的终止条件：某一级证书的签名能被某个 trust anchor 的公钥验证，且该
  anchor 证书与配置项**完全相等**（而非仅 subject 名称相同）。名称匹配
  永远不足以判定可信——攻击者自签一张同名证书无法通过验证
  （见 `tests/test_verify.py::test_name_match_alone_is_not_trusted`）。
- 中间证书池是**不可信**的：其中证书只有在签名、有效期与各项扩展检查
  全部通过后才被采纳。

## 验证顺序

对每条候选链（leaf 在前）依次执行：

1. **链构建**：按 issuer/subject 名称匹配候选 issuer，并用候选 issuer 的
   公钥验证签名；签名不符的候选被丢弃并记录诊断。检测循环（A 签 B、B 签 A）。
2. **数字签名**：每一级都用 issuer 的公钥验证（支持 RSA、ECDSA、Ed25519/Ed448），
   直到 trust anchor。
3. **有效期**：对链上每张证书检查 NotBefore/NotAfter。验证时间通过
   `ChainVerifier(now=...)` 或 CLI `--at` 注入，过期/未生效证书可稳定复现测试。
4. **Basic Constraints**：除 leaf 外每张证书必须是 CA（CA=TRUE）；普通 leaf
   证书不能被当作中间 CA 使用。
5. **Key Usage**：CA 证书若带 Key Usage 扩展，必须断言 `keyCertSign`。
6. **Extended Key Usage**：若调用方指定了要求的 EKU（如 `serverAuth`），
   leaf 的 EKU 扩展必须包含该 OID（或 `anyExtendedKeyUsage`）。
7. **Path Length**：按 RFC 5280 语义统计下级非自签 CA 数量，超出任一 CA 的
   `pathLenConstraint` 即失败。

## 诊断

所有失败抛出带定位信息的异常（`certchain.errors`）：

- `IncompleteChainError` — 找不到 issuer 且未到达 trust anchor
- `CycleDetectedError` — issuer 图存在循环
- `SignatureError` — 某一级签名验证失败（指出子证书与候选 issuer）
- `AmbiguousIssuerError` — 存在多条互不相同的有效链
- `ValidityError` / `BasicConstraintsError` / `KeyUsageError` / `PathLengthError`

每个错误都携带 `path`（leaf 起的证书主题列表），`ChainBuildingError` 还会
汇总每个候选链各自的失败原因。

## 使用

### Python API

```python
import datetime
from certchain import CertStore, ChainVerifier, load_file

store = CertStore(
    intermediates=load_file("intermediate.pem"),
    trust_anchors=load_file("root.pem"),
)
leaf = load_file("leaf.pem")[0]
verifier = ChainVerifier(store, now=datetime.datetime(2026, 1, 1,
                                                      tzinfo=datetime.timezone.utc))
chain = verifier.verify(leaf)  # leaf 在前，trust anchor 在末
```

### CLI

```bash
python -m certchain.cli verify \
    --leaf leaf.pem \
    --intermediates-dir intermediates/ \
    --root root.pem \
    --at 2026-01-01T00:00:00Z \
    --eku serverAuth
```

支持 PEM（单文件可含多张证书）与 DER（自动嗅探），`--intermediate` /
`--intermediates-dir` / `--root` 均可重复。`--eku` 接受名称
（`serverAuth`、`clientAuth`、`codeSigning`、`emailProtection`、
`timeStamping`、`OCSPSigning`）或点分 OID。

## 测试

测试夹具在内存中现场生成 root/intermediate/leaf 证书链（RSA-2048/SHA-256），
覆盖：有效链、过期与未生效证书（注入时钟）、错误 issuer、伪造签名、
leaf 被当作 CA、缺少 keyCertSign、EKU 不匹配、path length 违规与满足、
链不完整、循环、多候选 issuer 歧义、PEM/DER 加载与 CLI 端到端。

```bash
python -m pytest tests -q
```

全部测试从终端本地执行，不访问互联网。

## 依赖

- Python 3.9+
- `cryptography` >= 41（使用了 `not_valid_before_utc` 等 API）
- 测试：`pytest`

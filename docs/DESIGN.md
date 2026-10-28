# veil-L7 設計メモ（Draft）

> **ステータス: 設計中。この文書に書かれたものはすべて未実装です。**
> 名前・フィールド・API・手順は、実装と検証の中で変わる前提です。

## English summary

veil-L7 is a research-stage design for an L7 defense line in Rust. A gateway scans and rebuilds (CDR) files in an isolated, network-less process and issues a signed verdict: an in-toto Statement wrapped in a DSSE envelope, whose subject is the SHA-256 of the exact post-rebuild bytes. Backends read a file into memory once, verify the verdict with a small Rust library (fail closed on every error), and parse only that same verified buffer. The MVP is just the verdict spec plus the verification library. It is designed on the assumption that there is always a gap somewhere; section 7 lists what it does not protect. Nothing here is implemented.

---

## 1. 目的と前提

- **前提: どこかに隙は必ずある。** 検査器にもパーサーにも鍵管理にも、見つかっていない穴があると考えて設計します。
- そのうえで、「一か所が破られても、すぐ次で止まる」層を内側から外側へ固めていきます（inside-out）。最初に固めるのは、一番内側にあるバックエンドの「中身を読む直前の検証」です。
- 目標は「何でも防ぐ」ことではなく、**守れる範囲と守れない範囲を明示する**ことです（6章・7章）。

## 2. アーキテクチャ案

| 項目 | 内容 | 時期 |
|---|---|---|
| (a) 検査器 / CDR の隔離 | ゲートウェイ本体とは別プロセスで動かす。ネットワークなし、seccomp（Linux）でシステムコールを制限、入力パーサーはファジングする | MVP 後 |
| (b) CDR の対象拡大 | まず JPEG / PNG。PDF / Office は後で検討（方式は未定、9章） | 後 |
| (c) 署名付き判定書 | 3章の形式。再構成後のバイト列に対して発行する | **MVP** |
| (d) 耐量子暗号 | ML-KEM を使ったハイブリッド暗号化、監査ログやルート鍵への ML-DSA 署名 | 後 |
| (e) ゲートウェイ間のハッシュ共有 | 既知の悪性ハッシュ等の共有 | 保留 |

検査器の候補は、VirusTotal による Rust 製の YARA 実装 [YARA-X](https://github.com/VirusTotal/yara-x)（[ドキュメント](https://virustotal.github.io/yara-x/)）です。

暗号ライブラリの候補は [aws-lc-rs](https://github.com/aws/aws-lc-rs) です。docs.rs 上の 1.18.2 では、`aws_lc_rs::signature` に Ed25519 と ML-DSA-44 / 65 / 87、`aws_lc_rs::kem` に ML-KEM-512 / 768 / 1024 があります（[signature](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html), [kem](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/kem/index.html)）。ソース上、ML-DSA-65 の公開鍵は 1952 バイト、署名は 3309 バイトです（[pqdsa.rs](https://github.com/aws/aws-lc-rs/blob/main/aws-lc-rs/src/pqdsa.rs)）。

`pqcrypto` クレート系は、上流の PQClean のアーカイブに伴い unmaintained とされているため使いません（[RUSTSEC-2026-0164](https://rustsec.org/advisories/RUSTSEC-2026-0164.html)）。

## 3. 判定書（verdict）の形式

### 方針

- [in-toto Attestation の Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) を [DSSE](https://github.com/secure-systems-lab/dsse) のエンベロープで包みます。DSSE は RFC ではなく、secure-systems-lab の仕様です（[protocol.md](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md), [envelope.md](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)）。
- DSSE は、ペイロードの**生のバイト列**を `PAE(payloadType, payload)` で包んで署名します。JSON を正規化して署名するわけではないので、シリアライザの違い（キー順・空白）で署名が壊れる問題を避けられます。
- `subject` は、**再構成後にバックエンドへ渡す正確なバイト列**の SHA-256 です。元ファイルのハッシュではありません。

### predicate に入れるもの（案）

| フィールド | 意味 |
|---|---|
| `policy_sha256` | ゲートウェイが適用したポリシーのハッシュ |
| `scanner.name` / `scanner.version` | 例: YARA-X とその版 |
| `rules_version` | 検査ルールの版 |
| `cdr` | 再構成の有無と方式 |
| `key_id` | 署名鍵の ID（署名で保護される側に置く。理由は5章） |
| `issued_at` / `expires_at` | 発行時刻と期限。有効期限は短く（数分程度を想定、値は未定） |
| `audience` | この判定書を受け取ってよいバックエンド |

### 署名方式

- 当面は Ed25519。
- ML-DSA-65 は、後でオプション、または Ed25519 との併用（DSSE の複数署名）として検討します。

### 例（説明用。値はすべて架空で、形式も未確定）

Statement（DSSE の `payload` に入る、デコード後の中身）:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "upload.png",
      "digest": { "sha256": "<再構成後バイト列の SHA-256（hex）>" }
    }
  ],
  "predicateType": "https://github.com/mt4110/veil-L7/verdict/v0-draft",
  "predicate": {
    "verdict": "allow",
    "policy_sha256": "<ポリシーの SHA-256>",
    "scanner": { "name": "yara-x", "version": "<版>" },
    "rules_version": "<ルールの版>",
    "cdr": { "applied": true, "method": "png-reencode" },
    "key_id": "gw-ed25519-example-01",
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2026-01-01T00:05:00Z",
    "audience": "backend-example"
  }
}
```

DSSE エンベロープ:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<Base64(上の Statement のバイト列)>",
  "signatures": [
    { "keyid": "gw-ed25519-example-01", "sig": "<Base64(署名)>" }
  ]
}
```

`predicateType` の URI は仮置きです。

## 4. 検証ライブラリの API（Rust）

### 方針

- `VerifiedFile` はフィールドを private にし、`verify()` 以外では作れないようにします。考え方は Alexis King の [Parse, don't validate](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/) です。
- バックエンドはファイルを**1 回だけ**メモリに読み、検証し、**その同じバッファ**をパースします。ストレージから読み直さないので、検証と利用の間のすり替え（TOCTOU）を避けられます。
- パーサー側は `&VerifiedFile` / `as_bytes()` を受け取ります。`into_bytes()` で `Vec<u8>` に戻すと、型による保証がそこで途切れるためです。
- エラーはすべて fail closed（エラーなら捨てる）。「判定書がない」「形式が読めない」も拒否です。
- DSSE の仕様も、検証したペイロードのバイト列をそのままアプリケーションに渡し、検証後にエンベロープを再パースしないことを求めています（envelope.md の Security considerations）。

### 設計スケッチ（コンパイル未確認、実装ではありません）

```rust
pub mod verifier {
    /// 検証済みのバイト列。verify() 以外では作れない。
    pub struct VerifiedFile {
        bytes: Vec<u8>,          // private
        statement: Statement,    // 検証済み payload からパースしたもの
    }

    pub struct Policy {
        pub trusted_keys: KeyStore,    // key_id -> 公開鍵
        pub audience: String,
        pub max_clock_skew: Duration,
        pub min_rules_version: RulesVersion,
    }

    #[non_exhaustive]
    pub enum VerifyError { /* 各段階ごとのエラー */ }

    impl VerifiedFile {
        pub fn verify(
            raw: Vec<u8>,
            envelope: &[u8],
            policy: &Policy,
        ) -> Result<VerifiedFile, VerifyError> {
            // 5章の順で検証。どこかで失敗したら Err（fail closed）
            todo!()
        }

        pub fn as_bytes(&self) -> &[u8] { &self.bytes }
        pub fn statement(&self) -> &Statement { &self.statement }
    }
}

// バックエンド側: 未検証の Vec<u8> は渡せない
fn parse_image(file: &verifier::VerifiedFile) -> Result<Image, ParseError> {
    decode(file.as_bytes())
}
```

型で守れるのは「このライブラリを通った経路」だけです。ライブラリを使わない経路は守れません（7章）。

## 5. 検証の手順（この順で行う）

1. **エンベロープのパース**: `payload` / `payloadType` / `signatures` を読む。サイズ上限を超えたら拒否。
2. **鍵の特定**: `keyid` で信頼済み鍵を探す。DSSE の `keyid` は署名で保護されない「ヒント」なので、これだけで信頼を決めない。
3. **署名の検証**: `PAE(payloadType, payload)` に対して署名を検証する。
4. **payloadType の確認**: 想定した型（`application/vnd.in-toto+json`）か。
5. **Statement のパース**: 3 で検証した payload のバイト列からだけパースする。`_type` と `predicateType` を確認し、predicate の `key_id` が 2・3 で使った鍵と一致するか確認する。
6. **subject の照合**: `subject.digest.sha256 == SHA-256(raw)`。
7. **audience**: 自分宛てか。
8. **有効期限**: `issued_at` と `expires_at` を、許容する時計のずれ（`max_clock_skew`）込みで確認する。
9. **ルールの版**: `rules_version` がバックエンド設定の最低版以上か。
10. **OK**: `VerifiedFile` を返す。

## 6. MVP が守れるもの（意図）

バックエンドが検証ライブラリを必ず通す前提で、次を狙います。

- **偽造された判定書**: 信頼済み鍵の署名がなければ拒否。
- **ゲートウェイの迂回**: 判定書なしのファイルは拒否。
- **判定書の付け替え**: 別のファイルの判定書は subject のハッシュが合わないので拒否。
- **古いルールで検査されたファイル**: 最低ルール版より古ければ拒否。

## 7. MVP が守れないもの

- **パーサーのゼロデイ**: バックエンドや CDR のパーサー自体の脆弱性。判定書は「ゲートウェイがこう判断した」証拠にすぎず、中身が安全だという保証ではありません。
- **ライブラリを使わない経路**: 検証を通さないバックエンドやコードパスは、まったく守れません。
- **署名鍵やゲートウェイが乗っ取られている間の悪用**: 正規の署名がついた判定書が作られてしまいます。MVP では失効リストを持たないので、被害を抑えるのは短い有効期限と鍵のローテーションだけです。
- **リプレイ**: 有効期限内に、同じファイルを同じ audience へ再送することは防げません。
- **時計のずれの境界**: 許容ずれの設定次第で、期限切れ直後の判定書が通る、または正当なものが落ちる場合があります。

## 8. 鍵

- 署名鍵は KMS か、それに相当する仕組みで保管する想定です。
- ローテーションは `key_id` で新旧の鍵を並行運用して行う想定です。
- 詳細（配布、保管、ローテーション周期）は未定です。

## 9. MVP でやらないこと・未解決の問題

### やらないこと（MVP）

- 検査器・CDR の実装（隔離、seccomp、ファジングを含む）
- PDF / Office の CDR
- ML-KEM による暗号化、ML-DSA 署名
- 失効リスト
- ゲートウェイ間のハッシュ共有

### 未解決の問題

- 鍵のプロビジョニング: 署名側の鍵をどうメモリに載せるか（KMS、Vault 等）
- ルール版の配布: バックエンドの「最低ルール版」をどう同期するか
- 失効: 短い有効期限だけで足りるか、いつ失効の仕組みが必要になるか
- PDF / Office の CDR に何を使うか
- 判定書をどう運ぶか（HTTP ヘッダー、別ファイル、マルチパート等）

## 10. MVP の範囲

**判定書の仕様 ＋ 検証ライブラリ**だけです。

1. 判定書（in-toto Statement + DSSE）の仕様を文書にする
2. Rust の検証ライブラリ（`VerifiedFile` / `verify()`）を作り、テストする
3. テスト用の署名ツール（本番用ではない）

ゲートウェイ本体、検査器、CDR は MVP の後です。

## 参考（一次ソース）

- DSSE: https://github.com/secure-systems-lab/dsse
- in-toto Attestation Statement v1: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- aws-lc-rs: https://github.com/aws/aws-lc-rs / https://docs.rs/aws-lc-rs/latest/aws_lc_rs/
- YARA-X: https://github.com/VirusTotal/yara-x
- RUSTSEC-2026-0164: https://rustsec.org/advisories/RUSTSEC-2026-0164.html
- Alexis King, "Parse, don't validate" (2019): https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/

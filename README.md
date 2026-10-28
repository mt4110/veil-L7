# veil-L7

## 調査・判断の追記（2026-10-28）

**今回検討したクラウドDBの個人データ保護案は、いったん見送りとしました。未実装です。**
対象は、既存DBに暗号文を保存して独立した端末側画面で機密欄を扱う案と、開示制限ゲートとの融合案です。
調査結果、見送り理由、再開条件は [調査・判断記録](docs/2026-10-28-cloud-db-protection-decision.md) に保存しています。

ファイル検査・再構成（CDR）と署名付き判定書の旧案は、READMEの既存の未コミット本文と `docs/DESIGN.md` に、ローカル作業ツリーで保全しています。これらは今回の判断記録のコミットには含めていません。
旧案の「設計中」やMVPの記述は検討時点の内容であり、現在の実装計画や着手・再開の決定を示すものではありません。
今回の判断で旧案の採否を再評価したものではありません。リポジトリは削除せず、2026-10-28 に GitHub 上でアーカイブ（読み取り専用）にしました。

**Decision update (2026-10-28): the cloud database personal-data protection proposal is deferred and remains unimplemented.**
This covers client-side confidential fields stored as ciphertext in the existing database, and their combination with a disclosure-control gate.
See the [research and decision record](docs/2026-10-28-cloud-db-protection-decision.md) (Japanese).
The earlier file-scanning/CDR and signed-verdict proposal is preserved locally in the pre-existing uncommitted README content and `docs/DESIGN.md`; neither is included in this decision-record commit.
Its "in design" status and MVP descriptions reflect that earlier proposal; they are not a current implementation plan or a decision to start or resume work.
This decision does not reassess the earlier proposal. The repository was not deleted; it was archived (read-only) on GitHub on 2026-10-28.

---

> **ステータス: アーカイブ済み（開発見送り）。コードは 1 行も実装されていません。以下は旧案の設計中だった時点の記述です。**
> このリポジトリにあるのは設計メモだけです。動くもの・使えるものはありません。

[日本語](#日本語) | [English](#english)

---

## 日本語

### これは何か

veil-L7 は、Veil シリーズの L7（アプリケーション層）防衛ラインを Rust で作るための研究プロジェクトです。

構想はこうです。

1. ゲートウェイが、受け取ったファイルを隔離した環境で検査し、必要なら再構成（CDR）する
2. 再構成後のバイト列に対して、署名付きの「判定書」（verdict）を発行する
3. バックエンドは、ファイルの中身をパースする**前に**判定書を検証し、通らないものは捨てる

判定書の形式は、[in-toto Attestation](https://github.com/in-toto/attestation) の Statement を [DSSE](https://github.com/secure-systems-lab/dsse) で包む案で設計しています。詳細は [docs/DESIGN.md](docs/DESIGN.md) を見てください。

### 誰のためのものか

- 自分でバックエンドを管理していて、サービスがファイルに触れる前に、隔離環境で検査・再構成させたい人
- 「判定書を検証しないと中身を読めない」構造を、型（Rust）で強制する設計を学びたい・研究したい人

### 使わないほうがいい人

- 本番運用できる保護や、認証・認定を受けた製品が必要な人（このリポジトリはそのどちらでもありません）
- パーサーのゼロデイ脆弱性を防いでくれることを期待している人（防げません）
- ゲートウェイ自体や署名鍵が乗っ取られた場合でも守ってくれることを期待している人（守れません）

### 想定する使い方（設計段階）

```text
[クライアント] → [veil-L7 ゲートウェイ]
                    ├─ 隔離プロセスで検査（YARA-X 等）・再構成
                    └─ 再構成後のバイト列に署名付き判定書を発行
                 → [バックエンド]
                    ├─ ファイルを 1 回だけメモリに読む
                    ├─ 判定書を検証（失敗したら捨てる＝fail closed）
                    └─ 検証済みの同じバッファだけをパースする
```

### 価値（目指しているもの）

- ゲートウェイを迂回したファイルや、偽造された判定書を、バックエンド側で機械的に弾けるようにする
- 判定書をファイルのハッシュに結び付けて、別ファイルへの付け替えを防ぐ
- 「検証したバイト列」と「使うバイト列」を同じものにする設計で、検証と利用の間のすり替え（TOCTOU）を避ける

> [!CAUTION]
> **セキュリティは完璧ではありません。どこかに隙は必ずあります。**
> veil-L7 はその前提で、「何を守れて、何を守れないか」を明示して作る方針です。
> 守れない範囲は [docs/DESIGN.md の「守れないもの」](docs/DESIGN.md#7-mvp-が守れないもの) にまとめています。
> 現時点では未実装のため、何も守れません。

### 関連リポジトリ

- [veil-rs](https://github.com/mt4110/veil-rs)
- [veil-blackhole](https://github.com/mt4110/veil-blackhole)
- [veil-arena](https://github.com/mt4110/veil-arena)
- [veil-drop](https://github.com/mt4110/veil-drop)
- [veil-mesh-consensus](https://github.com/mt4110/veil-mesh-consensus)（開発終了・アーカイブ）
- [zt-gateway](https://github.com/mt4110/zt-gateway)（Go。ローカルファーストのファイル転送ツールとして別に続けます。veil-L7 との接点は署名付き判定書の形式です）

---

## English

> **Status: archived (development deferred). Nothing was implemented. The text below describes the earlier proposal as it stood while in design.**

### What it is

veil-L7 is a research project for an L7 (application-layer) defense line in the Veil series, written in Rust. The plan:

1. A gateway scans incoming files in an isolated environment and, where needed, rebuilds them (CDR).
2. It issues a signed **verdict** over the exact post-rebuild bytes.
3. The backend verifies the verdict **before** parsing the file, and drops anything that fails.

The verdict is planned as an [in-toto Attestation](https://github.com/in-toto/attestation) Statement wrapped in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope. See [docs/DESIGN.md](docs/DESIGN.md) (Japanese, with an English summary).

### Who it is for

- People who run their own backends and want files scanned/rebuilt in isolation before their services touch them.
- People who want to learn about or research enforcing "verify before you parse" with Rust's type system.

### Who should NOT use it

- Anyone who needs production-ready or certified protection. This is neither.
- Anyone expecting it to stop parser zero-days. It won't.
- Anyone expecting protection after the gateway or its signing key is compromised. It can't provide that.

### Intended use (design only)

Gateway scans and rebuilds → issues a signed verdict → backend reads the file into memory once, verifies the verdict (fail closed), and parses only that same verified buffer.

### Value (goals)

- Let backends mechanically reject files that bypassed the gateway, and forged verdicts.
- Bind each verdict to a file hash so it cannot be moved onto another file.
- Use the same bytes for checking and for use, to avoid check/use swaps (TOCTOU).

> [!CAUTION]
> **Security is never perfect. There is always a gap somewhere.**
> veil-L7 is designed on that assumption and documents what it can and cannot protect.
> Right now nothing is implemented, so it protects nothing.

### Related repositories

[veil-rs](https://github.com/mt4110/veil-rs) · [veil-blackhole](https://github.com/mt4110/veil-blackhole) · [veil-arena](https://github.com/mt4110/veil-arena) · [veil-drop](https://github.com/mt4110/veil-drop) · [veil-mesh-consensus](https://github.com/mt4110/veil-mesh-consensus) (archived) · [zt-gateway](https://github.com/mt4110/zt-gateway) (Go, separate local-first file transfer tool; linked to veil-L7 only through the verdict format)

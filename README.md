# veil-L7

## 調査・判断の追記（2026-10-28）

**今回検討したクラウドDBの個人データ保護案は、いったん見送りとしました。未実装です。**
対象は、既存DBに暗号文を保存して独立した端末側画面で機密欄を扱う案と、開示制限ゲートとの融合案です。
調査結果、見送り理由、再開条件は [調査・判断記録](docs/2026-10-28-cloud-db-protection-decision.md) に保存しています。

ファイル検査・再構成（CDR）と署名付き判定書の旧案は、READMEの既存の未コミット本文と `docs/DESIGN.md` に、ローカル作業ツリーで保全しています。これらは今回の判断記録のコミットには含めていません。
旧案の「設計中」やMVPの記述は検討時点の内容であり、現在の実装計画や着手・再開の決定を示すものではありません。
今回の判断で旧案の採否を再評価したものではなく、リポジトリの削除・アーカイブも行っていません。

**Decision update (2026-10-28): the cloud database personal-data protection proposal is deferred and remains unimplemented.**
This covers client-side confidential fields stored as ciphertext in the existing database, and their combination with a disclosure-control gate.
See the [research and decision record](docs/2026-10-28-cloud-db-protection-decision.md) (Japanese).
The earlier file-scanning/CDR and signed-verdict proposal is preserved locally in the pre-existing uncommitted README content and `docs/DESIGN.md`; neither is included in this decision-record commit.
Its "in design" status and MVP descriptions reflect that earlier proposal; they are not a current implementation plan or a decision to start or resume work.
This decision does not reassess the earlier proposal or delete or archive the repository.

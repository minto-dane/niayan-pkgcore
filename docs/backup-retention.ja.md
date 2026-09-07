# 今回の保持計画の修正

`Minimum_Restore_Points`はmanifest数ではなく、復元可能と検査された異なる`Through_Position`の数で判定します。
`Minimum_Recovery_Span`を追加しました。0なら期間条件を増やさず、非0なら同じ信頼時刻単位で期間幅を要求します。
期間幅は、各位置の最も早い保持中の有効Completed_Atを代表として計算します。変化のない位置を後から再コピーして期間幅を水増ししません。
`run_retention_batch_tests`は、個々には復元可能でも同じ位置の重複では必要数を満たさないこと、期間境界、コピーによる期間の水増しを拒否する試験を追加しました（Ada実行は未実施）。
実削除は依然として別アダプターです。

---

## 以前の版の説明（変更点は上記を優先）

# バックアップ受入と一括保持計画

## 型と境界

MC_Backupsは最大64世代、各8copyを扱う純粋な判定器です。対象scope/dataset/lineage、manifest/payload、full/incrementalのparent、データ位置、完了・復元試験時刻、trust epoch、キーの利用可否/失効、完全性事故、pin/in-use/legal hold、各copyのstore/domain、receipt・object hash、保持期限を扱います。

適合したfullからterminalまで、欠けないparent閉包、位置の連続性、同じdataset/lineage、非循環を要求します。チェーンcommitmentはfullから順に `SHA256("MCBCH001" || manifest32 || previous_commitment32)` を計算します。terminalの復元試験はこのexact commitmentを対象にしていなければなりません。

各祖先について十分な数の異なるstoreと障害domain、freshな認証済みreceipt、payload一致、耐久化確認、保持期間、鍵の利用可能性を検査します。同じstore IDを別domainとして重複計上しません。

Authenticated、Integrity_Verified、Durableの真偽はアダプターが認証・観測して設定する事後条件です。HTTP JSONの真偽値をそのまま通さないでください。別domainという申告だけで、実際の独立性を証明する機能ではありません。

## 不確かな時計

Now_Lower/Now_UpperでUTCの区間を入力します。完了/試験が過去である判定は下限、receiptの有効性と試験の古さは上限を使います。不可逆な削除ではobject lockが下限時刻でも終了していることを要求します。信頼できる時刻区間が得られない場合は変更を保留します。

## 一括削除

Pkg_Retention_Batch.Planはcatalogue revision、reference revision、完全な参照scan、writer静止、audit exportを要求します。
Requested集合を一件ずつ許可するのではなく、**全件消えた後に**最低限の復元可能なterminalが残るか再計算します。残る増分backupが参照する祖先は消せません。pin/in-use/legal hold、保持期限、最低age、object lockを尊重します。

削除候補自身にも認証されたmanifestとpayload binding、配置先のfreshな認証済み保持receiptが必要です。受入可能な復元点だけを認証して、削除対象の保全情報を未認証のまま使うことを避けています。

## 実削除は未実装

Planの返す集合は削除認可ではなく検査済み提案です。実executorは認可と変更停止を再確認し、同じcatalogue/reference revisionと静止条件をCASで保持し、対象オブジェクトと保持期限を再照合してから削除します。途中で結果不明になったら個別に照合し、最新の参照情報で再計画する必要があります。
現版はS3/Object Lock、テープ、別拠点backup、DB固有restore、CAS/WALの実GCを自動実行しません。監査・信頼・秘密情報・業務データを一括削除集合へ混ぜないでください。

# パッケージファイルのscrubと制約付き自己修復

## 実装

`Pkg_Inventory`は受け入れ済みファイルのroot ID、generation、package set、path、content digest、owner/mode/xattrs等を正規形式へまとめます。`Pkg_Scrubber`は実ファイルをfdベースで観測し、検査の前後でroot generation/active transactionとファイル同一性を再確認します。

```
pkg_scrubctl scan ROOT STATE-DIRECTORY INVENTORY-FILE EXPECTED-SHA256
```

このCLIは受動検査です。独立管理ルートのみを扱い、`/`は拒否します。引数hashは内容照合であって、引数を渡した者の信頼を作りません。受け入れ情報の署名検証・最新trust・独立したbaseline承認は、通常gateのサイト認可から供給する必要があります。

`Pkg_Self_Repair.Build`は不一致を、既存`Pkg_File_Plan`の正確なBefore/Afterへ変換します。純粋な提案器で、ファイルを変更しません。承認・署名済み計画を前版からのpkg worker/File_Engineへ渡すと、CAS保存・WAL・適用・確定・復旧の実コードを利用できます。scan→署名→要求配布→inventory再承認の常駐パイプラインまでは完成していません。

## 自動修復を許可する対象

明示的にautomatic repairを認可した通常のpackaged regular fileが対象です。既定のcritical指定はTrueです。パスが`usr/`か`opt/`だから安全、と自動推定しません。kernel modules、firmware、systemd/security等の保護パスは除外していますが、すべての重要ファイルをパスだけで分類することはできません。署名するinventory側でcritical属性を正しく付ける責任があります。

データ、設定、秘密、鍵、失効状態、監査、boot-critical、未対応型、未知の実状態は対象外です。一つでも除外driftやunknownがあれば、そのbatchの自動修復を止めます。missing fileは別の明示許可が必要です。変更数と総byte数に上限があります。

侵害・ハードウェア障害の疑い、未解決変更、保守状態、容量不足、排他的所有権や停止確認が不明なときは、自動修復しません。侵害の痕跡を正常ファイルで覆い隠す「修復」はしません。

## 正常状態の更新

修復前の内容と属性を保存し、実行直前に計画のBeforeとの一致を再検査します。対象サービスのquiescence/再起動/正常性は別の変更調整で確認します。署名したinventoryを古いgenerationのまま再利用すると次のscan/repairは拒否されるため、確定後に新generationと受け入れ集合を再承認する手順が必要です。

RPMDBとの全面所有権移行、任意のRPMスクリプト、全部の依存/トリガー、ホスト`/`でのin-place自動修復は未完成です。既存OS上で試す場合も、破棄可能な別rootと実サービスに接続しない試験から始めてください。

## 回復点

`Pkg_Recovery_Catalog`は、root・信頼epoch・失効・禁止脆弱版・data schema・artifact存在・完全性・復元試験の情報から候補を選びます。active/last accepted/unresolved/pinnedな点を保持し、最低保持数と経過時間を検査します。

これは選択/削除可否の判断器で、実際のsnapshot作成、DB backup/restore、CAS自動GC、鍵の破棄、bootloaderの書き換えは行いません。`Restoration_Tested=True`は実復元試験の証拠に基づいてsiteが認証すべき値であり、テンプレートのチェックボックスではありません。

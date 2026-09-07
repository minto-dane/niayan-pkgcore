# パッケージ変更と全対象停止確認の接続

`Pkg_Quiescent_Engine`は既存`Pkg_File_Engine`へ実際に認可callbackを渡すgeneric SDKです。
パッケージダウンロードや計画の生成だけでなく、既存の実ファイル適用・確定・復旧の認可点へ接続するためのものです。
**既存のpkg_workerが自動的にこのSDKへ変更されたわけではありません。** 統合側で利用するengine instanceを選び、対応する観測・認可を接続します。

## 2つの必要callback

`Authorize`は元の権限・root ID・transaction ID・phase・epoch・fence・plan/evidenceを検査する処理です。
`Observe_Barrier`は、認可済みPolicy、最新のauthoritative State、受信側clock/bootを取得し、現在のheld guardも照合します。
保存済みのsealファイルを読み返すだけのcallbackや、常にOKを返すcallbackは使用できません。
最新状態は、隔離された信頼経路から、anti-rollbackと必要なetcd整合性を満たして取得します。
PolicyのInventory digestだけでは完全性は証明されません。実際の全対象を確定した方針が必要です。

## 実行の検査順

元の認可 → 現在の停止確認の観測 → 共有profile・正確なplan・対象root・epoch/boot・Usableの照合 → 元の認可の再確認。
復旧が古いトランザクションに関係する場合、現在のbarrier epochは古いepochより大きくても構いませんが、元の認可がその復旧を明示的に許可することが必要です。
自動的に古いfencing tokenを信用したり、更新世代を下げたりしません。

## 単一ノード

同じPolicyを1対象として使用できます。quorum不要という理由でキュー閉鎖・未確定操作・停止ラッチの条件を省略しません。
サービスのファイルを操作する場合、そのサービスが単にinactiveという観測だけでは、他のwriterがいないとは保証されません。
サイトの対象一覧・制御契約で全書込経路を含めてください。

## 限界

認可直後のファイル変更とetcd更新を一つの原子操作にしません。外部writerや侵害rootまで本SDKのみで防げません。
長い更新の途中で観測期限が切れた場合は停止し、回復記録を保持して新しい認可済み観測へ進みます。
無期限有効・鮮度検査の無効化・不明操作の自動完了を復旧手段にしません。
元の独立管理ルート制約、WAL、変更前保存、任意scriptletの拒否、ホスト`/`の全面管理が未完成である境界はそのままです。

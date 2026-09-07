> Edition note: this document describes inherited v2 components. For the current resilience extension, implementation limits and evidence, start with `assurance/docs/resilience.ja.md` in the source bundle. Earlier qualification counts do not apply to the new sources.

# パッケージ側の操作経路 v2

## 対象範囲

明示的に作成・管理する専用ルートを扱います。既存のホストRPMDBと同じ`/usr`を二重管理するためのプログラムではありません。
通常ファイル、新しいディレクトリ、相対symlink、明示的設定ファイル計画を対象とし、特殊ファイル/hardlink/任意setuid/任意capabilitiesは拒否します。
管理対象の既存ディレクトリを削除・置換せず、未管理データへの再帰削除は行いません。

## 管理ディレクトリ

policy、state、store、ledger、spool、リクエスト別ディレクトリは所有者を限定した0700、秘密/方針ファイルは0400/0600にします。
state/store/trust/ledgerを管理対象ルートとは独立して保持し、通常のロールバックで消えないようにします。
各root/CAS/ledgerは排他ロックを使用します。別ツールによる同一所有者/root書き込みの隔離は運用・MAC側の責任です。

`POLICY-DIR/paths.conf`は改行終端の厳密なkey=valueで、次の五キーだけを許可します。

```text
root=/srv/mission/managed-root
state=/srv/mission/control/root-state
store=/srv/mission/control/objects
ledger=/srv/mission/control/requests
spool=/srv/mission/control/spool
```

追加/欠落キーは拒否されます。実際には既存OSの業務データ・鍵・監査と分離した専用ディレクトリを用意してください。

## ローカル初期化とステージング

CLI引数は以下です。権限と署名ポリシーを事前に準備して使います。これらをインターネットから受け取ってそのまま実行しないでください。

```text
pkgctl provision-store EMPTY-PRIVATE-STORE
pkgctl provision-root ROOT STATE ROOT-ID-HEX
pkgctl cas-import STORE ABSOLUTE-FILE
pkgctl fetch-rpm STORE REPO-POLICY TRUST-STATE GRANT SIGNATURE DEADLINE-MS TOOL-POLICY KEYRING
pkgctl stage-rpm STORE RPM-SHA256 TOOL-POLICY KEYRING DEADLINE-MS
pkgctl compile-plan MANIFEST-DIRECTORY OUTPUT-DIRECTORY
pkgctl check-plan PLAN-FILE
pkg_worker POLICY-DIRECTORY REQUEST-ID-HEX
```

`provision-root`は既存root.stateを上書きせず、世代/再送情報をリセットしません。
`fetch-rpm`のgrantは`Pkg_Artifact_Grant`の正規形＋domain `MC-ARTIFACT-v2`の署名です。
HTTPS origin、固定サイズ、SHA-256、受入snapshot/契約/版/有効期限を検査します。
repo鍵/URLは任意ダウンロードで自動導入せず、ローカルに用意します。

`stage-rpm`は保護された独立keyringとハッシュ固定した`rpmkeys`を使用します。通常ホストのRPMDBへインストールしません。
署名検査後、libarchiveの認めたフォーマット/filterだけを用い、RPMヘッダーとパス・型・モード・サイズ・SHA-256を照合してCASへ入れます。
実行されるのは署名検査プログラムであり、RPMのscriptletではありません。

### ツールの固定

`TOOL-POLICY/rpmkeys.tool`は次の二行の形式です。

```text
/usr/bin/rpmkeys
<信頼済み配布物から確認した64桁のSHA-256>
```

ELFをディスクリプタで開き直し、ハッシュを照合してシェルなしで実行します。
このハッシュを、攻撃を疑う稼働ホスト上のバイナリから無検証で作らないでください。
ライブラリ/ローダー/RPM設定/keyringも別途信頼対象です。

## plan.conf

`compile-plan`の入力ディレクトリには `plan.conf` と `change-1.conf`...を置きます。
plan.confは root,transaction（各32桁hex）、base,target,epoch,fence,count（正規10進）、package-set,effect-contract（各64桁hex）の9キーです。

各changeは path,domain と、before-/after-それぞれのkind,mode,uid,gid,size,mtime,nsec,content,xattrsです。
modeも**10進**（0644相当は420）です。kindはabsent/regular/directory/symlink、domainはpackaged/configuration。
absentの属性/サイズ/時刻/ダイジェストは全0。他は`Pkg_File_Plan.Valid`の条件に従います。
xattrsは`MC_FS`の正規化済み属性blobのCASハッシュで、空集合も「2バイトの0」の非ゼロSHA-256を使います。
SELinuxラベルを含む実際の属性方針を確認し、保護を無効にして空集合へ合わせないでください。

計画生成は署名承認ではありません。根拠となるRPM、効果契約、前後像、データ互換性を確認した発行元だけが要求に署名します。
受信側は対象root ID、plan hash、package-set、base generation、policy serialを再検査します。

## 要求と復旧

spoolの`REQUEST-ID-HEX/`にenvelope.bin、plan.bin、必要なwitness-N.binを認証済み配送経路で置きます。
署名の作成形式はassurance/docs/protocol.mdを参照してください。

- Prepare: 前像の照合・回復用CAS・plan pin・Prepared WAL・active state公開。
- Apply/Recover: 意図記録の後に一時ファイル作成、属性照合、再認可、公開。実状態が前像/後像以外なら停止。
- Commit: 認証済みhealth receipt、後像照合、commit intent、root generation公開、完了記録、active解除。
- Restore: quiescenceとdata-backward-compatible証拠、逆順に前像へ。確定後の自動巻き戻しは拒否。
- Reconcile: 完了済みだが応答を失った場合も保存plan/世代/ファイル/WALを照合し、変更を再実行しない。
- Repair: 部分最終WALだけをCAS保存・別repair auditへ記録して切り詰める。完全レコードの破損を切り捨てない。

同じrequest ID/sequenceの再送は保存結果の参照です。結果不明なら、新しい署名済みのRecover/Restore/Reconcile/Repair要求が必要です。
盲目的な再実行はしません。途中失敗と部分変更がある場合、依頼台帳上もUNKNOWNとして保持します。

復旧とアプリケーションデータの復旧は別です。before/afterを満たさないファイルを強制上書きするオプションは提供しません。

`provision-store`だけが新しい空の私有storeを初期化する。通常Open/cas-import/worker/recoveryは欠落lock・objects・incoming・pinsを作り直さない。初期化途中の失敗は保全し、既存storeを空として再設定しない。

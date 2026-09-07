> 過去の別系統版から統合した参考文書です。記載された実装モデルの復元を意味し、収集器・実機接続・形式証明の完成を意味しません。現在の統合範囲は `assurance/docs/engineering/specs/unified-management.ja.md` と機能台帳を参照してください。

# Enterprise maintenance model

Mission Core package management は「dependency solver が通る = install 可」としない。

順序:

```text
repository trust -> package provenance -> exact incorporation -> HOLDS -> impact/rollback contract
-> plan -> recovery pin -> quiesce -> APPLY -> VERIFY/soak -> ACCEPT -> COMMIT
```

- `Pkg_Repository_Trust`: monotonic repository metadata。古い署名済み snapshot への rollback も拒否。
- `Pkg_Holds`: known-bad/system/security/site hold。local force flag で消さない。
- `Pkg_Exposure_Policy`: security fix の最大未適用時間。
- `Pkg_Rollback_Contract`: application data/schema の reverse 可否を binary rollback と分離。
- `Pkg_Maintenance_Bundle`: cumulative/group maintenance level。
- `Pkg_Incorporation`: tested system composition からの勝手な package substitution を拒否。
- `Pkg_Acceptance`: active trial と permanently accepted baseline を分離。

COMMIT は旧 recovery content を即時削除する命令ではない。retention/backup/legal hold policy を満たした後の GC は別処理である。

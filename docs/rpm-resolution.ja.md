# RPM source adapter / generic resolution boundary

`Pkg_RPM_Resolution`はgeneric resolverと別のnative layer。EVR、提供名、rich dependencyは
ここにだけ置く。libsolvから独立した`Pkg_EVR`/`Pkg_Versions`を使用する。
新しい本体は[独立検査仕様](../../resolvercore/docs/neutral-spec.ja.md)に従う。

## 意味の違い

`(a and b)`は選択集合全体にa提供者とb提供者がいればよい。
`(a with b)`は同じartifactがa/b両方を提供する必要がある。
`(a without b)`はaの提供者集合からbの提供者を引いた後に選択集合と交差する。
これを普通の全体Boolean Notへ変換すると別の意味になる。
`if/unless`は条件なしの`else`を真として扱い、else有りでは各枝を条件でguardする。
通常依存と競合はOwnerでguardし、未選択artifactが無条件の要求にならない。

同じmetadataに対し、`Check_Native`は集合で直接評価し、`Lower`はneutral DAGへ投影。
`Add_Rule`/`Check_Rule`はowner依存と競合を処理する。両方が同じBuild_Matchesを使うため、
互いに完全独立な実装二本を証明したわけではない。solverからの独立性とは区別する。

元RPMのCapability providersは全件、未選択のものも検査する。未versioned提供は
versioned依存を満たさない。epoch/version/releaseの比較はnative規則を使用する。
現在のプロファイルは比較に使う提供版を一点として扱う。範囲付きProvidesやBoolean
Providesを通常の名前へ平坦化してはならない。未知のnative tagはsource readerが拒否する。

RPMの文脈制限も対象。ifを含むOr文脈、unlessを含むAnd文脈、ifを含むConflictsを拒否。
with/without配下のconditionalは保守的に未対応として拒否する。この制限を満たすことと
RPM全構文/全バージョンへ互換であることは同義ではない。

## 閉包が必要な要素

Requires/Conflictsだけでなく、ファイルProvides、arch/multilib、Obsoletes、installonly、
ソースpriority/pin、weak dependenciesの扱い、scriptlet順序、file triggers、導入済み
trigger、RPMDB所有権、設定/生成物/rollback/署名を別々にインベントリ化する。
一つも扱わず成功するdefaultを設けない。empty inventoryにも認証した根拠が必要。

現コードはraw headerから全closureを自動生成するものではない。Factの抽出と原データへの
束縛は、独立に適格化したreaderを接続する。`Permitted=True`はsandboxや任意root scriptの
許可ではない。scriptlet/triggerを無検査実行して「generic checkerが通った」と呼ばない。

## 参照

https://rpm.org/docs/4.20.x/manual/boolean_dependencies.html
https://manpages.debian.org/testing/libsolv-doc/libsolv-bindings.3.en.html

libsolvのtransaction()はproblemがあっても結果を返し得るため、提案helperは非空problemを
必ず拒否する。問題を自動的に無視/緩和しない。返された候補は改めて全条件を検査する。

# keycloak-mcp

[English](README.md) | 日本語

[KeyCloak](https://www.keycloak.org/) Admin REST API のための MCP（Model Context Protocol）サーバ。

ドキュメント: <https://shigechika.github.io/keycloak-mcp/ja/>

Service Account（**Client Credentials Grant**）で認証するので、人間のユーザのパスワードや TOTP は一切不要。ユーザセッションも作らず userinfo も叩かないので Infinispan にも優しい作り。

## 機能

### ユーザ

| ツール | 説明 |
|------|------|
| `count_users` | Realm 内の総ユーザ数 |
| `search_users` | ユーザ名・メール・氏名の部分一致検索 |
| `get_user` | 指定ユーザ名の詳細情報 |
| `reset_password` | 1 ユーザのパスワードを再設定 |
| `reset_passwords_batch` | CSV（`username,password` 形式、パスワード空欄は自動生成）で一括リセット |
| `get_user_sessions` | ユーザのアクティブセッション（時刻はローカルタイム） |
| `logout_user` | ユーザのセッションをすべて強制終了 |
| `set_user_enabled` | ユーザを有効化 / 無効化。無効化で全ログインを遮断（独自属性は保持） |

### MFA・クレデンシャル

| Tool | Description |
|------|-------------|
| `get_user_credentials` | 1 ユーザに設定されたクレデンシャル種別。`otp` があれば TOTP/HOTP 設定済み |
| `get_totp_users` | レルム全体の TOTP 普及状況。`otp` クレデンシャルを持つユーザ数と割合（任意でユーザ一覧）を出力。全ユーザを列挙して 1 人ずつクレデンシャルを読むため N+1（`max_users` で件数を制限可能） |

### グループ

| ツール | 説明 |
|------|------|
| `list_user_groups` | ユーザが所属しているグループ |
| `list_users_by_group` | グループのメンバー |

### セキュリティ

| ツール | 説明 |
|------|------|
| `get_brute_force_status` | ブルートフォース検知でロック中かどうか |
| `get_realm_security_defenses` | Realm のセキュリティ設定：ブルートフォース検知の有効/無効と閾値、パスワードポリシー、ブラウザセキュリティヘッダ |
| `get_config_changes` | 保存した日次スナップショットから realm の設定がどう変わったか（「設定のスナップショット」参照）。読み取りのみ。`baseline_date` で比べる日を選べる |
| `get_login_failures_by_ip` | 送信元 IP 別のログイン失敗数（`KEYCLOAK_SITES_INI` 設定時は拠点ラベル付き） |
| `get_ip_activity` | 送信元 IP 1件の全活動を漏れなく調査：成功/失敗件数、対象ユーザ・クライアント、タイムライン。構造化 JSON を返す |
| `detect_login_loops` | 短時間に大量ログインしているユーザを検出（リダイレクトループの発見に） |

### イベント

| ツール | 説明 |
|------|------|
| `get_events` | 種別・ユーザ名・クライアント・IP・日付範囲でフィルタ。ユーザ名は内部でユーザ ID に解決。失敗イベントには KeyCloak の `error` フィールド（`invalid_user_credentials` など）も表示 |
| `get_login_stats` | ログイン成功/失敗の合計（全件ページネーション） |
| `get_login_stats_by_hour` | 時間帯別ログイン数（ローカルタイム） |
| `get_login_stats_by_client` | クライアント（SP）別ログイン数 |
| `get_password_update_events` | `UPDATE_PASSWORD` イベントの履歴 |

### 管理イベント

`get_events` が扱うのは *ユーザ* イベントだけなので、管理者やサービスアカウントがカスタム属性を書き換えたようなケースはそこに出てこない。その穴を埋めるのが admin-events エンドポイント。

| ツール | 説明 |
|------|------|
| `get_admin_events` | 操作種別（CREATE / UPDATE / DELETE / ACTION）、リソース種別（USER / CLIENT / ROLE / GROUP / …）、リソースパス、日付範囲でフィルタ |
| `get_user_attribute_history` | 特定ユーザに対する UPDATE/ACTION イベントを抽出。プロビジョニング処理が `provisioning_flag` のようなカスタム属性をいつ書き込んだかを追うのに便利 |

どちらも `max_repr` で representation ペイロードを制御できる: 正の数 = N 文字で切り詰め（デフォルト 500）、`0` = 省略、負の数 = 全文表示。

### セッション・クライアント

| ツール | 説明 |
|------|------|
| `get_session_stats` | クライアント別のアクティブセッション数 |
| `get_client_sessions` | 1 クライアント（SP）のアクティブセッション |
| `list_clients` | Realm の SAML / OIDC クライアント |
| `get_client` | クライアント1件の設定。認証フローのオーバーライド（SP 単位の MFA 切り替え）を含む。`attributes` と `protocolMappers` は出力しないので、クライアントシークレットや SAML の署名鍵はツール出力に出ない。 |
| `get_realm_roles` | Realm ロール |

### 朝のパトロール

| ツール | 説明 |
|------|------|
| `health_check` | 稼働中のサーババージョンを報告し、KeyCloak バックエンドへの到達性とサービスアカウントの認証可否を確認する。軽量（トークン取得1回のみ・ユーザ／イベント／セッションのスキャンは行わない）。`status`、`auth`、設定済み URL／Realm を含む固定キーの dict を返す。各フィールドが取りうる値はツール自身の description が列挙しており、列挙はそこ1か所にのみ置く。 |
| `daily_brief` | 朝のワンショット健全性チェック。ログイン統計・ブルートフォース IP・アクティブセッション・パスワード更新・管理者操作・設定の変更（ロール、ロールの割り当て、認証フロー、クライアントスコープ、プロトコルマッパー、コンポーネント、realm への管理操作と、`KEYCLOAK_STATE_DIR` があればスナップショットとの比較。どちらも `[CONFIG]` で示す）・ロールの付いたグループへの追加（読み取り専用の `query-*`／`view-*` 以外の `realm-management` ロールが付くグループなら `[PRIVILEGE]`）を1つの Markdown サマリーにまとめる。`ip_failure_threshold`（既定 50）件以上の失敗 IP は **WARNING**、API エラーは **CRITICAL** として表示。`since_hours` で遡及時間を指定（既定 18 h）。 |

## インストール

```bash
# uv
uv pip install keycloak-mcp

# pip
pip install keycloak-mcp
```

ソースから:

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp

# uv
uv sync

# pip
pip install -e .
```

## 設定

| 変数 | 説明 | デフォルト |
|---|---|---|
| `KEYCLOAK_URL` | ベース URL（例: `https://keycloak.example.com`） | *必須* |
| `KEYCLOAK_REALM` | Realm 名 | `master` |
| `KEYCLOAK_CLIENT_ID` | Service Account のクライアント ID | *必須* |
| `KEYCLOAK_CLIENT_SECRET` | クライアントシークレット | *必須* |
| `KEYCLOAK_SITES_INI` | IP→拠点名ラベル用の INI ファイル（後述） | *未設定* |
| `KEYCLOAK_DEFAULT_DATE_FROM_HOURS` | `date_from` 省略時のイベント検索範囲（時間）。`0` で全履歴スキャン（イベント数が多いレルムではハングの原因になる）。 | `24` |
| `KEYCLOAK_DEADLINE` | 重いイベント/TOTP 系ツール1回あたりの実時間バジェット（秒）。広い窓や大規模レルムで超過しそうなときは、クライアントの ~60秒ゲートウェイタイムアウトを超えて KeyCloak を叩き続ける代わりに、途中で打ち切って**部分結果（⚠️ 警告付き）**を返す。`0`/負の値で無効。 | `45` |
| `KEYCLOAK_MAX_EVENTS` | イベント系ツールの1ページングあたりのイベント取得上限（激遅化する深いオフセットの深さも制限）。上限超過時は部分結果を開示。`0`/負の値で無効。 | `200000` |
| `KEYCLOAK_MAX_USERS` | `get_totp_users` の `max_users` 引数が `0` のときの走査ユーザー数の既定上限（1ユーザーにつき credential 呼び出し1回）。`0`/負の値で無効（全レルム、`KEYCLOAK_DEADLINE` のみで制限）。 | `5000` |
| `KEYCLOAK_USER_ATTRIBUTE_WHITELIST` | `get_user` が出力してよいカスタム属性キーのカンマ区切りリスト。未設定時、`get_user` はユーザー名・氏名・メール・有効フラグ・作成日時のみを返す（ユーザー名解決に使う検索エンドポイントは brief representation を返し、`attributes` を一切含まないため）。キーをホワイトリストに入れると、`get_user` はその場でID指定の追加取得を1回行い、該当キーが存在すれば値を追記する。それ以外の属性は出力されない。安全弁として、`password`・`secret`・`token` などクレデンシャルらしき語を含むキー名はホワイトリストに入れても値を表示せずブロックされる（ただしこのパターンに当てはまらない名前のクレデンシャル属性までは防げない） | *未設定* |
| `KEYCLOAK_GROUP_WRITE_ROOT` | 任意で有効にするグループ変更ツール（`plan_group_changes`・`apply_group_changes`）を登録し、対象をこの絶対パス（例: `/Staff`）より下のグループに限る。未設定・空・不正な値のときは 2 つのツールを登録しない。承認の手順を前段に置く配備でだけ設定する | *未設定* |
| `KEYCLOAK_PROTECTED_GROUPS` | グループ変更ツールが追加・削除を拒否するグループの完全パス（`;` 区切り、配下も含む）。不正な項目があると保護を黙って落とさず、グループ変更ツールごと無効にする | *未設定* |
| `KEYCLOAK_GROUP_BATCH_MAX` | グループ変更 1 回あたりの最大行数 | `30` |
| `KEYCLOAK_GROUP_MODE` | `multi`（KeyCloak の既定。ユーザーは複数のグループに所属できる）または `single`（グループに追加すると他の所属がすべて外れる配備。所属を 1 つに保つイベントリスナーなど）。それ以外の値ではグループ変更ツールを無効にする | `multi` |
| `KEYCLOAK_STATE_DIR` | 設定の日次スナップショットを置くディレクトリ（`<dir>/config-snapshots`、ディレクトリは 0700、ファイルは 0600 で作る）。未設定ならスナップショットは取らず、`daily_brief` は設定に関わる管理操作だけを出す。「設定のスナップショット」参照 | *未設定* |
| `KEYCLOAK_GROUP_DEADLINE` | グループ変更ツールの実時間バジェット（秒）。30 名のバッチは既定の 45 秒では足りない。前段に ~60 秒のタイムアウトが無い配備（サーバを直接起動するクライアントなど）で長くする。未設定なら `KEYCLOAK_DEADLINE` | *未設定* |
| `KEYCLOAK_SESSION_PROBES` | `get_user_sessions`（と `set_user_enabled` が数える残りのセッション）で、別々の接続で取った一覧を重ねる回数。ロードバランサの後ろで、セッションを共有しない KeyCloak の各台（Infinispan の分散キャッシュ無し）は自分の分しか返さない | `8` |
| `KEYCLOAK_LOGOUT_CLEAN_PROBES` | `logout_user` は、接続ごとにセッションを一覧し、届いた台にセッションがあればそこでログアウトする試行を、続けてこの回数セッションが見えなくなるまで繰り返す。最初の試行は一覧が空でもログアウトを送る。データベースのユーザーの `notBefore` も書かれ、全台がそれを見るので、ツールはその時刻も返す。新しい接続がどの台へ届くかはロードバランサ次第で、送信元 IP で振り分ける設定では届かない台が残りうる。全台に効くのは `notBefore` のほう。セッションを共有している構成では、これと `KEYCLOAK_SESSION_PROBES` を `1` にする | `10` |
| `KEYCLOAK_LOGOUT_MAX_PROBES` | `logout_user` の試行の上限。上限でまだセッションが見えるときは成功と言わず ⚠️ で伝える。試行は `get_user_sessions`・`set_user_enabled` のセッション一覧と同じく `KEYCLOAK_DEADLINE` で打ち切り、打ち切ったときや要求が失敗したときは、確認が終わっていないことと、そこまでにしたことを ⚠️ で伝える | `40` |

### KeyCloak 側のクライアント設定

1. KeyCloak 管理コンソールで新しいクライアントを作成。
2. **Client authentication** と **Service account roles** をオンにする。
3. Realm ロールとして `view-users` / `view-events` / `view-clients` を付与。パスワードリセットも使うなら `manage-users` も追加。

### 状態を変えるツール

既定で状態を変えるのは次の 4 つだけです。ほかはすべて読み取りです。後述のグループ変更を有効にすると `apply_group_changes` が 5 つ目になります。

| ツール | Admin API |
|---|---|
| `reset_password` | `PUT /users/{id}/reset-password` |
| `reset_passwords_batch` | 同じ呼び出しを CSV の行数だけ繰り返す |
| `set_user_enabled` | `enabled` を変えて `PUT /users/{id}` |
| `logout_user` | `GET /users/{id}/sessions` と `POST /users/{id}/logout` を新しい接続で繰り返す（`KEYCLOAK_LOGOUT_CLEAN_PROBES`） |

4 つとも Service Account の `manage-users` が要ります。**このロールを付けなければ
読み取り専用**になり、上記 4 つだけが `403` で失敗して残りのツールはそのまま動きます。
realm を変更する権限を一切与えずに調査だけ任せられる，ということです。アカウント復旧や
封じ込めまで行う場合にのみ `manage-users` を付けてください。

### グループ変更（任意で有効化）

`plan_group_changes` と `apply_group_changes` は、ユーザーをグループ間で移動する（人事異動など）。
`KEYCLOAK_GROUP_WRITE_ROOT` を設定したときだけ存在するので、承認の手順を持たない配備で同じバイナリを使っても出てこない。

| ツール | Admin API |
|---|---|
| `plan_group_changes` | 読み取りのみ: `GET /users?username=...&exact=true`、`GET /group-by-path/...`、`GET /groups/{id}/role-mappings`、`GET /roles-by-id/{id}/composites`、`GET /clients/{id}`、`GET /users/{id}/groups` |
| `apply_group_changes` | `PUT /users/{id}/groups/{groupId}` のあと `DELETE /users/{id}/groups/{groupId}` |

- `plan_group_changes` はユーザーとグループを名前・パスの完全一致で解決し、行ごとに現在の直接所属、実行される操作、判定を返す。`digest` は解決した ID、各ユーザーの現在の所属、ポリシーを含む。
- `apply_group_changes` は計画をやり直し、全行がまだ実行可能で digest が承認時と一致するときだけ変更する。計画のあとに誰かが所属を変えていれば一括で中止する。追加してから削除し、追加の直前に追加先をもう一度審査し、書き込みの前に所属を読み直し、書き込みの後に読み戻し、最初の不一致、エラー、時間切れ（`KEYCLOAK_GROUP_DEADLINE`）で止まる。残り時間で全操作を終えられないユーザーには手を付けないので、止まっても追加と削除の間で分かれることはない。`applied` は `yes`、`no`、`partial`、`unknown`（読み戻せなかった書き込みがある）のいずれか。
- `KEYCLOAK_GROUP_MODE=single` では、移動は追加 1 回で済む。元のグループはサーバが外すので DELETE は送らず、読み戻しが追加先だけになっていることを確かめる。行には追加先が必須（削除だけの行は所属を 0 にするので拒否）。`remove` を省略すると現在の所属で埋め、承認者に外れるグループが見えるようにする。外れるグループは、計画のときと追加の直前の 2 回、`remove` と同じく審査する。2 つ以上のグループに所属しているユーザーは、サーバの決まりから外れているので拒否する（手で直す）。計画では元に戻せないユーザー（所属が無かった、またはサーバが入れ替えなかった）は `reverse` ではなく `manual_restore` に出す。KeyCloak がこの動きをするときに設定する。`multi` のままだと、そうしたサーバでは移動のたびに「途中で所属が変わった」として止まる。`single` で入れ替えないサーバだと、モードが合わないと告げて止まる。
- 拒否する対象: root の外、root 自身、保護グループとその配下。
- ロールを持つグループは拒否しない。部署の管理者グループへの異動は、承認する人が管理コンソールで同じことをできるなら、普通の異動である。計画の各行に `gained_roles` と `lost_roles` を載せる。移動によって、ユーザーがすべての所属を通して持つロールがどう変わるかの差である（共通の祖先や別の所属で持ち続けるロールはどちらにも入らない。ユーザーに直接付いたロールは読まない）。`add_roles` と `remove_roles` は、それぞれのグループに所属すると付くロールである。realm ロールは名前、client ロールは `client:role` で示し、祖先のグループから受け継ぐ分と、複合ロールの中身（何段でも）を含める。増減を承認する人に見せること。ロールは `digest` に含まれ、追加の前にも追加先のロールを読み直す（1 回の呼び出しの中では同じグループについて 5 秒に 1 回まで）ので、承認の後でロールが付け替えられる（複合ロールの中身が変わる場合も含む）と止まる。ロールの増減を示せない行（パスで引けない現在の所属がある。名前に `/` を含むグループなど）は拒否する。1.3.0 で変わった点: それより前の版はロールマッピングを持つグループをすべて拒否していた。その拒否に頼っていたなら、更新の前にそれらのグループを `KEYCLOAK_PROTECTED_GROUPS` に載せる。
- ロールが無くても、所属そのものがアクセスの条件になっているグループがある（サービスプロバイダが確かめる SAML・OIDC のグループマッパー、認可サービスのグループポリシー）。ロールにかかわらずこのツールで書き換えてはいけないグループは `KEYCLOAK_PROTECTED_GROUPS` に載せる。保護グループのパスは KeyCloak に実在しなければならず、1 つでも見つからない（改名・移動・大文字小文字の違い）ときは、設定を直すまですべての計画を拒否する。
- `digest` は計画のあと何も変わっていないことを示すだけで、人が承認したことの証明ではない。`plan_group_changes` を呼べれば誰でも有効な digest を得られる。承認は `apply_group_changes` の手前に置く（たとえば digest をクライアント側で保持し、呼び出しのたびに人に確かめる）。承認は 1 回限りとして扱う。`reverse` などで所属が計画時の状態に戻ると、古い digest がまた一致する。
- 結果の `reverse` は、実際に起きた変更を戻すための変更案。新しい計画と承認のための提案で、自動では実行しない。所属を戻しても、誤った所属の間に起きたアクセスは取り消せない。

書き込みには `manage-users` が要る。KeyCloak のバージョンによっては、グループとそのロールマッピングの参照に `query-groups` も要る。複合ロールの展開は realm ロールを読む（`view-realm`）。client ロールの名前は client を読む（`view-clients`）。`plan_group_changes` を一度実行して確かめる。

### 設定のスナップショット（任意）

`KEYCLOAK_STATE_DIR` を設定すると、その日最初の `daily_brief` が realm の設定のスナップショットを保存し、毎回の `daily_brief` が前日以前の最新のスナップショットと今の設定を比べる。変わっていれば変わった項目を `[CONFIG]` の警告として出す。全部の一覧は `get_config_changes` で見る。

- 対象: realm の設定（ブルートフォース検知、パスワードと OTP のポリシー、セッションとトークンの寿命、フローの割り当て）、イベントの設定、realm ロールと複合ロールの中身、認証フローとその実行ステップ、必須アクション、クライアント（リダイレクト URI、許可するフロー、フローの上書き、属性、プロトコルマッパー）、クライアントスコープ、既定のクライアントスコープ、コンポーネント、読める場合は ID プロバイダ。グループへのロールの割り当てとクライアントロールはスナップショットに入れず、管理操作のイベントで出す
- 秘密は保存しない。名前に `secret`、`password`、`privateKey`、`apiKey`、`credential`、`token` など（`get_user` と同じ目印）を含むキーの文字列の値は `<redacted>` に置き換えるので、秘密が変わっても変更としては出ない。そうしたキーでも `true`／`false` や数値は設定なので残す。ただしキーそのものが秘密の欄（`...password`、`...secret`）なら何であれ伏せる。よくある名前に対する安全網で、保証ではない。長い値（証明書、公開鍵）はハッシュで保存する
- 全部を読めたときだけ保存する。時間切れのときは比較を見送ったと出し、前の基準をそのまま使う
- グループの所属は設定ではないのでスナップショットに入れない。代わりに、遡る範囲の中でロールの付いたグループ（自分か祖先に付いたロール。複合ロールの中身を含む）に追加された人を、ロール・対象者・追加した管理者とともに出す。読み取り専用の `query-*`／`view-*` 以外の `realm-management` ロール（`realm-admin`、`manage-users` など）が付くグループへの追加は `[PRIVILEGE]` にする。master realm では `<realm>-realm` クライアントの管理ロールと realm ロール `admin` も対象にする。グループは ID で今の状態を読み、ロールは `parentId` でたどるので、イベントの後で名前が変わったり移動したりしても漏れない。グループを読めなかった追加は別に `[CONFIG]` の警告にする。この確認に使う時間は Configuration 節の持ち時間のうち最大 8 秒
- 保存するのは `daily_brief` だけで、その日の最初の 1 回だけ。日中の変更は翌朝にも出る。直近 30 個を残す
- 設定の読み取りには `view-realm` と `view-clients` が要る。ID プロバイダは `view-identity-providers` も要り、無ければその部分は比べずに、比べていないことを出す

### 設定の確認

環境変数を設定したら、MCP クライアントに組み込む前に `--check` で認証が通るか確認する:

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp --check
# HTTP Request: POST https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token "HTTP/1.1 200 OK"
# OK: authenticated to https://keycloak.example.com/admin/realms/my-realm
```

終了コード: `0` 成功、`1` 設定エラー（変数未定義）、`2` 認証エラー。

### IP→拠点ラベル（任意）

出力に表示される IP を、数字のままでなく拠点名付きで読みたいときは `KEYCLOAK_SITES_INI` に INI ファイルのパスを設定する。`get_user_sessions` / `get_events` / `get_login_failures_by_ip` などが自動でタグ付けしてくれ、どの範囲にも入らない IP は `external` と表示される。環境変数を設定しなければ IP はそのまま表示。

フォーマットは [`sites.ini.example`](sites.ini.example) を参照。最小構成はこんな感じ:

```ini
[hq]
name = HQ (Tokyo)
ipv4 = 192.0.2.0/24, 198.51.100.0/24
ipv6 = 2001:db8:1::/48

[vpn]
name = VPN
ipv4 = 10.0.0.0/8, 172.16.0.0/12
```

`[section]` 1 つで 1 拠点。`name` は表示ラベル（省略時はセクション名）。`ipv4` / `ipv6` はカンマ区切りの CIDR で、単一ホストは `/32` や `/128`。記述順に先頭マッチなので、狭い範囲を広い範囲より先に書くこと。

## 使い方

### Claude Code（プラグイン）

このリポジトリはプラグイン 1 個のマーケットプレイスも兼ねているので、Claude Code から
そのまま導入できます。

```
/plugin marketplace add shigechika/keycloak-mcp
/plugin install keycloak-mcp@keycloak-mcp
```

プラグインは `uvx keycloak-mcp` を起動し、[設定](#設定)と同じ環境変数を読みます。
Claude Code を起動する前に export しておいてください。`KEYCLOAK_REALM` は未設定なら
`master`、`KEYCLOAK_SITES_INI` は未設定のままで構いません。

プラグインは `uvx` を起動するため、Claude Code を実行するプロセスの `PATH` に
`uvx` が通っている必要があります。ログインシェルなら通常問題ありませんが、
GUI から起動した場合は通っていないことがあります。プラグインが起動しない場合は
[uv](https://docs.astral.sh/uv/) をシステム全体にインストールしてください。

### Claude Code（手動）

`.mcp.json` に追加:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
      "type": "stdio",
      "command": "keycloak-mcp",
      "env": {
        "KEYCLOAK_URL": "https://keycloak.example.com",
        "KEYCLOAK_REALM": "my-realm",
        "KEYCLOAK_CLIENT_ID": "keycloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": ""
      }
    }
  }
}
```

### Claude Desktop

`claude_desktop_config.json` に追加:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
      "command": "keycloak-mcp",
      "env": {
        "KEYCLOAK_URL": "https://keycloak.example.com",
        "KEYCLOAK_REALM": "my-realm",
        "KEYCLOAK_CLIENT_ID": "keycloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": ""
      }
    }
  }
}
```

### シェルから直接

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp
```

### CLI オプション

```bash
keycloak-mcp --version   # バージョン表示して終了
keycloak-mcp --help      # 使い方と必須環境変数を表示
keycloak-mcp --check     # 環境変数と認証を検証して終了
keycloak-mcp             # MCP STDIO サーバとして起動（デフォルト）
```

オプションなしが通常モード。MCP クライアントはこの形で起動する。

### 日次のスプレー集計（バッチ）

`spray_check` は「いまから遡る移動窓」なので、パトロールには合うが日ごとに保存できない。定期ジョブから暦日 1 日分を同じ判定で集計するには:

```bash
keycloak-mcp spray-report --date 2026-09-17 --tz Asia/Tokyo > 2026-09-17.json
```

- 窓は `--tz`（既定はホストのゾーン）での `[DATE 00:00, DATE+1 00:00)`。`dateFrom` / `dateTo` は KeyCloak サーバのゾーンで解釈されるので、同じゾーンを指定する。取得後にタイムスタンプで両端を切る
- 標準出力には JSON を 1 つだけ出す。エラーは標準エラーに出して非 0 で終わり（2 = 設定、1 = 取得・認証）、そのときは標準出力に何も書かない
- 中身は `spray_check` と同じ形で、ユーザー名の付いたイベントが 1 件でもある外部 IP を `external_ips` に全件（`min_report_users=1`）載せる。加えて `external_totals` は**すべての**外部 IP の LOGIN / LOGIN_ERROR 件数を持つ（ユーザー名の無い失敗しか無く `external_ips` に行が無い IP も含む）・`fetch_complete`・`resolve_complete`・`coverage`（`first_event`・`last_event`・`head_gap_seconds`・`tail_gap_seconds`）・`schema`・`keycloak_mcp_version`・`sites_ini_sha256` を持つ。両方の `*_complete` が true で、どちらの端の欠けも小さい日だけを確定値として扱う。片方の端だけ大きく欠けるのは、たいてい `--tz` が KeyCloak サーバのゾーンと違うとき
- `KEYCLOAK_SITES_INI` から範囲が 1 つも読めないとき（全 IP が外部扱いになる）は `--allow-no-sites` が無い限り実行しない。`KEYCLOAK_KNOWN_EGRESS` に CIDR として読めない値があるときも実行しない
- 上限は専用の値（`--deadline 900`・`--max-events 1000000`・`--max-resolves 2000`）。HTTP ゲートウェイ越しのツール呼び出し向けの `KEYCLOAK_DEADLINE` / `KEYCLOAK_MAX_EVENTS` は使わない
- 出力には送信元 IP とユーザー名が入る。公開するものに含めないこと

## 開発

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp

# uv
uv sync --dev
uv run pytest -v
uv run ruff check .

# pip
python3 -m venv .venv
.venv/bin/pip install -e . && .venv/bin/pip install pytest pytest-cov respx ruff
.venv/bin/pytest -v
.venv/bin/ruff check .
```

### 実データのスモークテスト

`pytest` はフィクスチャに対するロジック検証なので、「ツールが実データを返さなくなった」ことは検出できない。`scripts/smoke_test.py` は**登録されている全ツール**を実際の realm に対して実行し、空・不正・エラー応答を失敗として報告する。

```bash
# KEYCLOAK_URL / KEYCLOAK_CLIENT_ID / KEYCLOAK_CLIENT_SECRET が必要
uv run python scripts/smoke_test.py
uv run python scripts/smoke_test.py --only login_stats --traceback
```

- **読み取り専用**。状態を変更するツール（`reset_password`・`logout_user`・`set_user_enabled`・`reset_passwords_batch`）は名前でスキップし、テストで強制している。レポートに出るのはツール名と状態だけで、応答本文は出さない（realm のデータをログに残さないため）。エラー文もサーバー由来のテキストは伏せる（`--traceback` 使用時のみ手元の端末に全文が出る）。
- ユーザー名・グループ・IP など realm 固有の引数は `scripts/smoke_probes.py` に書かず、**実行時に取得**する。
- CI では安価な半分だけを検証する: probe 仕様の無いツールを追加するとビルドが落ちる（`tests/test_smoke_probes.py`）。ツール追加時に「動作をどう確認するか」を必ず決めさせるため。
- 共有インフラなので既定の同時実行数は 2。
- `scripts/smoke_harness.py` は KeyCloak 固有の知識を持たないエンジン本体。共有する各サーバーで同一に保つ方針なので、この写しに手を入れるのではなく、エンジン側を直してファイルを同期する。

## ライセンス

MIT
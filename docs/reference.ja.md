# リファレンス

## `health_check()`

7つのキーがどの呼び出しでも必ず返ります。

| キー | 意味 |
|---|---|
| `status` | `healthy` / `degraded` / `error` |
| `service` | 常に `keycloak-mcp` |
| `version` | パッケージのバージョン |
| `keycloak_url` | 設定された URL（未設定なら空文字列） |
| `realm` | 設定されたレルム（未設定なら空文字列） |
| `keycloak_version` | 常に `null`（軽量な呼び出しでは取得しない） |
| `auth` | `unknown` / `ok` / `missing-env` / `error` |

`detail` は `degraded` または `error` のときだけ追加され、理由（環境変数の欠落、
または本物の認証失敗の場合は例外の型とバックエンドが返した HTTP ステータス）が
入ります。内部 URL や生の HTTP ペイロードは意図的に含めていません。

意図的に軽量です。Client Credentials トークンを1つ取得するだけ — サービス
アカウントがレルムと話せることを示す最軽量の証明であり、それ以外は何も走査
しません。セッション開始時やツール呼び出しのタイムアウト後に安心して呼べます。

## ツール一覧

| ツール | 用途 |
|---|---|
| `count_users` | レルムの総ユーザー数 |
| `search_users(query, max_results=20)` | ユーザー名・メール・姓名の部分一致検索 |
| `get_user(username)` | 完全一致のユーザー名で詳細を取得 |
| `get_user_sessions(username)` | アクティブなセッション（タイムスタンプはローカル時刻） |
| `logout_user(username)` | **書き込み。** 1ユーザーの全アクティブセッションを終了 |
| `set_user_enabled(username, enabled)` | **書き込み。** 有効/無効の切替。無効化しても既存セッションは終了しない |
| `reset_password(username, password, temporary=False)` | **書き込み。** 1ユーザーのパスワードをリセット |
| `reset_passwords_batch(csv_text, temporary=False)` | **書き込み。** `username,password` の CSV から一括リセット |
| `get_user_credentials(username)` | 設定済みの認証情報の種類。`otp` があれば TOTP/HOTP 設定済み |
| `get_totp_users(max_users=0)` | レルム全体の TOTP 導入率。N+1（ユーザーごとに1呼び出し）。`max_users` または `KEYCLOAK_MAX_USERS` で上限 |
| `list_user_groups(username)` | ユーザーが所属するグループ |
| `list_users_by_group(group_name, max_results=100)` | グループのメンバー |
| `plan_group_changes(changes)` | 任意で有効にするツールで、`KEYCLOAK_GROUP_WRITE_ROOT` を設定したときだけ登録される。グループ移動のバッチ（`username`・`remove`・`add` を完全パスで）を変更せずに確かめる。行ごとの状態、ロールの増減、承認する人に見せる `digest` を返す |
| `apply_group_changes(changes, expected_digest)` | **書き込み。** 任意で有効にするツールで、`KEYCLOAK_GROUP_WRITE_ROOT` を設定したときだけ登録される。承認された計画を実行する。計画を取り直し、新しい digest が一致しなければ何も変えない。一致すればユーザーごとに追加してから削除し、書いたあとに読み戻す。`applied`（`yes`／`no`／`partial`／`unknown`）と、元に戻す案 `reverse` を返す。digest は計画以後に変化が無いことの確認で、承認の証ではない |
| `get_brute_force_status(username)` | ユーザーがブルートフォース検知によりロック中か |
| `get_realm_security_defenses()` | ブルートフォース対策の方針と閾値、パスワードポリシー、ブラウザセキュリティヘッダー |
| `get_config_changes(baseline_date="")` | 保存した日次スナップショットから realm の設定がどう変わったか（`KEYCLOAK_STATE_DIR` が要る。スナップショットは `daily_brief` が保存する） |
| `get_login_failures_by_ip(date_from, date_to, top=20)` | 送信元 IP 別の失敗数ランキング |
| `get_ip_activity(ip_address, event_types, date_from, date_to, max_timeline=200)` | 1 IP の網羅的な調査（構造化 JSON） |
| `spray_check(hours=24, min_users=10, max_success_rate=0.2, min_report_users=3, max_resolves=200, max_user_success_rate=0.2, max_failure_concentration=0.5)` | パスワードスプレー検知。異なるユーザーが `min_users` 人以上で成功率が `max_success_rate` 未満の外部 IP を挙げ、その IP からのログイン成功を突破の候補（証拠の組）として出す。突破の判定は `confidence: high` の行だけで、`low` は共有出口か `KEYCLOAK_KNOWN_EGRESS` への一致を示す。形の決まった JSON で、走査を途中で打ち切ったときは `complete: false` |
| `detect_login_loops(date_from, date_to, threshold=10, window_seconds=60, top=20)` | `window_seconds` 内に `threshold` 回を超えてログインしたユーザー |
| `get_events(event_type, username, client_id, ip_address, date_from, date_to, max_results=50)` | 絞り込みイベント検索。ユーザー名は内部でユーザー ID に解決される |
| `get_login_stats(date_from, date_to)` | 成功/失敗の総数（全件ページング） |
| `get_login_stats_by_hour(date_from, date_to)` | 時間帯別のログイン数（ローカル時刻） |
| `get_login_stats_by_client(date_from, date_to)` | クライアント（SP）別のログイン数 |
| `get_password_update_events(date_from, date_to, max_results=100)` | `UPDATE_PASSWORD` の履歴 |
| `get_admin_events(operation_types, resource_types, resource_path, date_from, date_to, max_results=50, max_repr=500)` | 管理操作による変更。`get_events` には現れない |
| `get_user_attribute_history(username, date_from, date_to, max_results=100, max_repr=500)` | 1ユーザーに絞った管理イベント |
| `get_session_stats()` | クライアント別のアクティブセッション数 |
| `get_client_sessions(client_id, max_results=100)` | 1クライアントのアクティブセッション |
| `list_clients()` | レルムの SAML / OIDC クライアント |
| `get_client(client_id)` | クライアント1件の設定。認証フローのオーバーライド（SP 単位の MFA 切り替え）を含む。`attributes` と `protocolMappers` は出力しないので、クライアントシークレットや SAML の署名鍵はツール出力に出ない。 |
| `get_realm_roles()` | レルムレベルのロール |
| `daily_brief(since_hours=18, ip_failure_threshold=50)` | 朝のサマリー: ログイン統計・ブルートフォース IP・スプレー検知・セッション・パスワード更新・管理イベント・設定の変更 |

書き込みツールが実際に何をするか、`get_ip_activity` の出力の読み方、重い走査が
共有する deadline / 部分結果の仕組みは [セキュリティ調査](investigation.ja.md)
を参照してください。

## `daily_brief`

ログイン統計・`ip_failure_threshold` 件を超える失敗を出した IP（`WARNING` として
フラグ）・スプレー検知（`spray_check` と同じ規則。確度の高いものは突破された
アカウントと証拠を添えて `[SPRAY]`、確度の低いものは本人に確かめるログインとして
`[SPRAY?]`）・アクティブなセッション・パスワード更新・管理イベントを、`since_hours`
（既定18 — 09:00 に実行する場合ほぼ前日午後をカバー）の範囲で1つの Markdown
レポートにまとめます。バックエンド接続に失敗した場合、内訳の欠けた部分的な
レポートではなく、レポート全体が `## CRITICAL — <ExceptionType>` になります。
設定の節には、ロール・ロールの割り当て・認証フロー・クライアントスコープ・
プロトコルマッパー・コンポーネント・realm への管理操作と、`KEYCLOAK_STATE_DIR` を
設定していれば前日以前の最新のスナップショットからの変更を出します（どちらも
`[CONFIG]`）。その日最初の brief がその日のスナップショットを保存します。秘密は
保存する前に伏せます。ロールの付いたグループへの追加も出し、読み取り専用の `query-*`／`view-*` 以外の
`realm-management` ロールが付くグループなら `[PRIVILEGE]` にします。

`get_admin_events` と `get_user_attribute_history` は `max_repr` を受け取り、
KeyCloak の「representation」ペイロード（変更されたオブジェクトの JSON テキスト）
をどこまで含めるかを制御します。正の値はその文字数に切り詰め（既定500）、
`0` は省略、負の値は全文を含めます。

## `get_events` と `get_admin_events` の違い

`get_events` が見るのは*ユーザー*イベントです — ユーザー自身が行ったログイン・
ログアウト・パスワード変更。管理者が行った操作や、サービスアカウントがカスタム
属性を書き込む操作はここには一切現れません。それを見るのが `get_admin_events`
です。`get_user_attribute_history` は `get_admin_events` を1ユーザーに絞った
もので、自動化パイプラインが `provisioning_flag` のような属性を最後に書き込んだ
のがいつかを確認するのに便利です。

## CLI

```bash
keycloak-mcp            # MCP サーバーとして起動（stdio・既定・引数無し）
keycloak-mcp --version  # バージョンを表示して終了
keycloak-mcp --help     # 使い方と必要な環境変数を表示
keycloak-mcp --check    # 環境変数と認証を確認して終了
```

`--check` の終了コード: `0` 成功、`1` 必須の環境変数が欠落、`2` 認証失敗。

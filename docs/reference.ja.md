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
| `keycloak_version` | トークン取得に成功するまでは `null` |
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
| `list_users_by_group(group)` | グループのメンバー |
| `get_brute_force_status(username)` | ユーザーがブルートフォース検知によりロック中か |
| `get_realm_security_defenses()` | ブルートフォース対策の方針と閾値、パスワードポリシー、ブラウザセキュリティヘッダー |
| `get_login_failures_by_ip(date_from, date_to, top=20)` | 送信元 IP 別の失敗数ランキング |
| `get_ip_activity(ip_address, event_types, date_from, date_to, max_timeline=200)` | 1 IP の網羅的な調査（構造化 JSON） |
| `detect_login_loops(date_from, date_to, threshold=10, window_seconds=60, top=20)` | `window_seconds` 内に `threshold` 回を超えてログインしたユーザー |
| `get_events(event_type, username, client_id, ip_address, date_from, date_to)` | 絞り込みイベント検索。ユーザー名は内部でユーザー ID に解決される |
| `get_login_stats(date_from, date_to)` | 成功/失敗の総数（全件ページング） |
| `get_login_stats_by_hour(date_from, date_to)` | 時間帯別のログイン数（ローカル時刻） |
| `get_login_stats_by_client(date_from, date_to)` | クライアント（SP）別のログイン数 |
| `get_password_update_events(date_from, date_to)` | `UPDATE_PASSWORD` の履歴 |
| `get_admin_events(operation_types, resource_types, resource_path, date_from, date_to, max_repr=500)` | 管理操作による変更。`get_events` には現れない |
| `get_user_attribute_history(username, date_from, date_to, max_repr=500)` | 1ユーザーに絞った管理イベント |
| `get_session_stats()` | クライアント別のアクティブセッション数 |
| `get_client_sessions(client_id)` | 1クライアントのアクティブセッション |
| `list_clients()` | レルムの SAML / OIDC クライアント |
| `get_realm_roles()` | レルムレベルのロール |
| `daily_brief(since_hours=18, ip_failure_threshold=50)` | 朝のサマリー: ログイン統計・ブルートフォース IP・セッション・パスワード更新・管理イベント |

書き込みツールが実際に何をするか、`get_ip_activity` の出力の読み方、重い走査が
共有する deadline / 部分結果の仕組みは [セキュリティ調査](investigation.ja.md)
を参照してください。

## `daily_brief`

ログイン統計・`ip_failure_threshold` 件を超える失敗を出した IP（`WARNING` として
フラグ）・アクティブなセッション・パスワード更新・管理イベントを、`since_hours`
（既定18 — 09:00 に実行する場合ほぼ前日午後をカバー）の範囲で1つの Markdown
レポートにまとめます。バックエンド接続に失敗した場合、内訳の欠けた部分的な
レポートではなく、レポート全体が `## CRITICAL — <ExceptionType>` になります。

`get_admin_events` と `get_user_attribute_history` は `max_repr` を受け取り、
KeyCloak の「representation」ペイロード（変更されたオブジェクトの JSON テキスト）
をどこまで含めるかを制御します。正の値はその文字数に切り詰め（既定500）、
`0` は省略、負の値は全文を含めます。

## `get_events` と `get_admin_events` の違い

`get_events` が見るのは*ユーザー*イベントです — ユーザー自身が行ったログイン・
ログアウト・パスワード変更。管理者が行った操作や、サービスアカウントがカスタム
属性を書き込む操作はここには一切現れません。それを見るのが `get_admin_events`
です。`get_user_attribute_history` は `get_admin_events` を1ユーザーに絞った
もので、自動化パイプラインが `temp_password` のような属性を最後に書き込んだ
のがいつかを確認するのに便利です。

## CLI

```bash
keycloak-mcp            # MCP サーバーとして起動（stdio・既定・引数無し）
keycloak-mcp --version  # バージョンを表示して終了
keycloak-mcp --help     # 使い方と必要な環境変数を表示
keycloak-mcp --check    # 環境変数と認証を確認して終了
```

`--check` の終了コード: `0` 成功、`1` 必須の環境変数が欠落、`2` 認証失敗。

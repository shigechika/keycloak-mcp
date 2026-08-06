# keycloak-mcp

[KeyCloak](https://www.keycloak.org/) Admin REST API 用の MCP サーバーです。

2つの用途のために作りました。ブルートフォースの IP や API の不調を1コールで
洗い出す朝の `daily_brief`、そして brief（やアラート）が異常を示したときに、
ある1人のユーザー・1つの IP・1つのクライアントについて全体像をつかむための
調査ツール群です。

## 領域別ツール

| 領域 | ツール |
|---|---|
| ユーザー | `count_users`、`search_users`、`get_user`、`get_user_sessions`、`logout_user`、`set_user_enabled` |
| パスワード | `reset_password`、`reset_passwords_batch` |
| MFA | `get_user_credentials`、`get_totp_users` |
| グループ | `list_user_groups`、`list_users_by_group` |
| セキュリティ | `get_brute_force_status`、`get_realm_security_defenses`、`get_login_failures_by_ip`、`get_ip_activity`、`detect_login_loops` |
| イベント | `get_events`、`get_login_stats`、`get_login_stats_by_hour`、`get_login_stats_by_client`、`get_password_update_events` |
| 管理イベント | `get_admin_events`、`get_user_attribute_history` |
| セッション・クライアント | `get_session_stats`、`get_client_sessions`、`list_clients`、`get_realm_roles` |
| 朝の点検 | `health_check`、`daily_brief` |

**書き込みを行うのは4本だけです。** `reset_password`・`reset_passwords_batch`・
`logout_user`・`set_user_enabled`。それ以外はすべて読み取り専用です。各書き込み
ツールが実際に何をし、どんな場面で使うべきかは
[セキュリティ調査](investigation.ja.md) を参照してください。

## 設計方針

**サービスアカウント認証であること自体が設計の要です。** 本サーバーは Client
Credentials Grant で認証し、人間のパスワードや TOTP を使いません。ユーザー
セッションを一切作らず、`userinfo` エンドポイントも呼びません。これは特に
Infinispan（KeyCloak の分散セッションキャッシュ）がクラスタ構成でない環境で
効いてきます。そうした環境ではセッションベースの認証がノード間で不整合な状態を
生むことがあるからです。サービスアカウントのトークンしか要求しないサーバーは、
呼び出し側の注意深さではなく構造そのものによって、この種の問題を避けます。

**取得を打ち切ったときは、打ち切ったことを明示します。** `KEYCLOAK_DEADLINE` が
重いイベント/TOTP ツールの実行時間を、`KEYCLOAK_MAX_EVENTS` が取得件数を制限します。
いずれかの上限で走査が早期に止まった場合、応答の先頭には明示的な
`⚠️ PARTIAL RESULT` の警告が付き、たまたま取得できた分をそのまま完全な結果として
返すことはありません。完全に見える部分的な結果は、遅い結果よりも、エラーよりも
悪いものです。

**すべてが自分たちのサイトに解決されます。** `get_events`・`get_user_sessions`・
`get_login_failures_by_ip` は、INI ファイルで宣言したサイト名で IP アドレスに
ラベルを付けます。調査結果は生の IP アドレスではなく、自分たちのトポロジーの
言葉で読めます。

## 次に読むもの

- [セットアップ](setup.ja.md) — サービスアカウント・権限・環境変数・IP のサイトラベル付け
- [セキュリティ調査](investigation.ja.md) — ブルートフォース／クレデンシャルスタッフィングの調査手順、書き込みツール、deadline と部分結果
- [リファレンス](reference.ja.md) — 全ツール・`health_check` の契約・CLI・終了コード

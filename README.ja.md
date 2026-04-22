<!-- mcp-name: io.github.shigechika/keycloak-mcp -->

# keycloak-mcp

[English](README.md) | 日本語

[KeyCloak](https://www.keycloak.org/) Admin REST API のための MCP（Model Context Protocol）サーバ。

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

### グループ

| ツール | 説明 |
|------|------|
| `list_user_groups` | ユーザが所属しているグループ |
| `list_users_by_group` | グループのメンバー |

### セキュリティ

| ツール | 説明 |
|------|------|
| `get_brute_force_status` | ブルートフォース検知でロック中かどうか |
| `get_login_failures_by_ip` | 送信元 IP 別のログイン失敗数（`KEYCLOAK_SITES_INI` 設定時は拠点ラベル付き） |
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
| `get_user_attribute_history` | 特定ユーザに対する UPDATE/ACTION イベントを抽出。プロビジョニング処理が `temp_password` のようなカスタム属性をいつ書き込んだかを追うのに便利 |

どちらも `max_repr` で representation ペイロードを制御できる: 正の数 = N 文字で切り詰め（デフォルト 500）、`0` = 省略、負の数 = 全文表示。

### セッション・クライアント

| ツール | 説明 |
|------|------|
| `get_session_stats` | クライアント別のアクティブセッション数 |
| `get_client_sessions` | 1 クライアント（SP）のアクティブセッション |
| `list_clients` | Realm の SAML / OIDC クライアント |
| `get_realm_roles` | Realm ロール |

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
| `KEYCLOAK_URL` | ベース URL（例: `https://sso.example.com`） | *必須* |
| `KEYCLOAK_REALM` | Realm 名 | `master` |
| `KEYCLOAK_CLIENT_ID` | Service Account のクライアント ID | *必須* |
| `KEYCLOAK_CLIENT_SECRET` | クライアントシークレット | *必須* |
| `KEYCLOAK_SITES_INI` | IP→拠点名ラベル用の INI ファイル（後述） | *未設定* |

### KeyCloak 側のクライアント設定

1. KeyCloak 管理コンソールで新しいクライアントを作成。
2. **Client authentication** と **Service account roles** をオンにする。
3. Realm ロールとして `view-users` / `view-events` / `view-clients` を付与。パスワードリセットも使うなら `manage-users` も追加。

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

### Claude Code

`.mcp.json` に追加:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
      "type": "stdio",
      "command": "keycloak-mcp",
      "env": {
        "KEYCLOAK_URL": "https://sso.example.com",
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
        "KEYCLOAK_URL": "https://sso.example.com",
        "KEYCLOAK_CLIENT_ID": "keycloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": ""
      }
    }
  }
}
```

### シェルから直接

```bash
export KEYCLOAK_URL=https://sso.example.com
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

`--check` の終了コード: `0` 成功、`1` 設定エラー、`2` 認証エラー。

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

## ライセンス

MIT

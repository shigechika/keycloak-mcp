<!-- mcp-name: io.github.shigechika/keycloak-mcp -->

# keycloak-mcp

[English](README.md) | 日本語

[KeyCloak](https://www.keycloak.org/) Admin REST API 用の MCP（Model Context Protocol）サーバ。

**Client Credentials Grant**（Service Account）を使用し、ユーザパスワードや TOTP は不要。
Infinispan セーフ：ユーザセッションの作成や userinfo エンドポイントは使用しない。

## 機能

### ユーザ管理

| ツール | 説明 |
|------|------|
| `count_users` | Realm 内の総ユーザ数を取得 |
| `search_users` | ユーザ名・メール・氏名で検索 |
| `get_user` | ユーザ名で詳細情報を取得 |
| `reset_password` | パスワードをリセット |
| `reset_passwords_batch` | CSV から一括パスワードリセット |
| `get_user_sessions` | ユーザのアクティブセッション一覧 |

### グループ管理

| ツール | 説明 |
|------|------|
| `list_user_groups` | ユーザが所属するグループ一覧 |
| `list_users_by_group` | グループのメンバー一覧 |

### セキュリティ監視

| ツール | 説明 |
|------|------|
| `get_brute_force_status` | ブルートフォース検知によるロック状態を確認 |
| `get_login_failures_by_ip` | IP アドレス別ログイン失敗統計 |

### イベント分析

| ツール | 説明 |
|------|------|
| `get_events` | イベント取得（種別・ユーザ・日付でフィルタ） |
| `get_login_stats` | ログイン成功/失敗統計（ページネーション対応） |
| `get_login_stats_by_hour` | 時間帯別ログイン統計（ローカル時刻） |
| `get_login_stats_by_client` | クライアント（SP）別ログイン統計 |
| `get_password_update_events` | パスワード変更イベント履歴 |

### セッション・クライアント

| ツール | 説明 |
|------|------|
| `get_session_stats` | クライアント別アクティブセッション数 |
| `get_client_sessions` | 特定クライアントのアクティブセッション一覧 |
| `list_clients` | SAML/OIDC クライアント一覧 |
| `get_realm_roles` | Realm ロール一覧 |

## インストール

```bash
pip install keycloak-mcp
```

ソースから:

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp
pip install -e .
```

## 設定

以下の環境変数を設定する:

| 変数 | 説明 | デフォルト |
|---|---|---|
| `KEYCLOAK_URL` | KeyCloak ベース URL（例: `https://sso.example.com`） | *必須* |
| `KEYCLOAK_REALM` | Realm 名 | `master` |
| `KEYCLOAK_CLIENT_ID` | Service Account のクライアント ID | *必須* |
| `KEYCLOAK_CLIENT_SECRET` | クライアントシークレット | *必須* |

### KeyCloak クライアント設定

1. KeyCloak 管理コンソールで新しいクライアントを作成
2. **Client authentication** と **Service account roles** を有効化
3. Realm ロールを付与: `view-users`, `view-events`, `view-clients`, `manage-users`（パスワードリセット用）

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

### 直接実行

```bash
export KEYCLOAK_URL=https://sso.example.com
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp
```

## 開発

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -v
.venv/bin/ruff check .
```

## ライセンス

MIT

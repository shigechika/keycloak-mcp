# セットアップ

## インストール

```bash
uv pip install keycloak-mcp
# または
pip install keycloak-mcp
```

ソースから:

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp
uv sync          # または: pip install -e .
```

## KeyCloak クライアントの設定

1. KeyCloak の管理コンソールで新しいクライアントを作成します。
2. **Client authentication** と **Service account roles** を有効にします。
3. サービスアカウントに `view-users`・`view-events`・`view-clients` を付与し、
   `reset_password` や `reset_passwords_batch` を使うつもりがある場合のみ
   `manage-users` も付与します。

!!! tip "読み取り専用で運用する場合"
    このサーバーにパスワードリセットをさせたくなければ、`manage-users` を
    単に付与しなければ済みます。書き込み系の4本（`reset_password`・
    `reset_passwords_batch`・`logout_user`・`set_user_enabled`）はサーバーの
    起動を拒むのではなく KeyCloak API 側で失敗するので、実際のセキュリティ境界は
    この権限付与そのものです。

## 環境変数

| 変数 | 説明 | 既定 |
|---|---|---|
| `KEYCLOAK_URL` | ベース URL（例 `https://keycloak.example.com`） | *必須* |
| `KEYCLOAK_REALM` | レルム名 | `master` |
| `KEYCLOAK_CLIENT_ID` | サービスアカウントのクライアント ID | *必須* |
| `KEYCLOAK_CLIENT_SECRET` | クライアントシークレット | *必須* |
| `KEYCLOAK_SITES_INI` | IP のサイトラベル付け用 INI ファイル | 未設定 |
| `KEYCLOAK_DEFAULT_DATE_FROM_HOURS` | `date_from` 省略時のイベント系ツールの既定ルックバック。`0` で全履歴走査（大規模レルムでハングしうる） | `24` |
| `KEYCLOAK_DEADLINE` | 重いイベント/TOTP ツールの1呼び出しあたりの時間予算（秒）。`0` 以下で無効化 | `45` |
| `KEYCLOAK_MAX_EVENTS` | 1呼び出しで取得するイベント件数の上限。`0` 以下で無効化 | `200000` |
| `KEYCLOAK_MAX_USERS` | `get_totp_users` の `max_users` 引数が `0` のときに走査するユーザー数の既定上限。`0` 以下で無効化 | `5000` |
| `KEYCLOAK_USER_ATTRIBUTE_WHITELIST` | `get_user` が出力してよいカスタム属性キーのカンマ区切りリスト。未設定なら `get_user` は `attributes` を取得も表示もしない。クレデンシャルらしき名前のキーはホワイトリストに入れてもブロックされる（安全弁であり保証ではない） | *未設定* |

## 何かに組み込む前に確認する

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp --check
```

exit `0` なら認証成功、`1` は環境変数の欠落、`2` は認証エラーです。一度これを
走らせておけば、「ツールが何も返さない」が既に答えの出ている問いになります。

## IP のサイトラベル付け（任意）

`KEYCLOAK_SITES_INI` に INI ファイルを指定すると、ツール出力中の IP アドレスに
自分たちのサイト名でタグが付きます。`get_user_sessions`・`get_events`・
`get_login_failures_by_ip` が自動的に読み込み、宣言した範囲外の IP は `external`
と表示されます。変数を未設定にしても IP はそのまま表示されるだけで、どちらでも
壊れません。

```ini
[hq]
name = HQ (Tokyo)
ipv4 = 192.0.2.0/24, 198.51.100.0/24
ipv6 = 2001:db8:1::/48

[vpn]
name = VPN
ipv4 = 10.0.0.0/8, 172.16.0.0/12
```

リポジトリの [`sites.ini.example`](https://github.com/shigechika/keycloak-mcp/blob/main/sites.ini.example)
も参照してください。`[section]` 1つが1サイトです。`name` は表示ラベル（省略時は
セクション名）、`ipv4` / `ipv6` はカンマ区切りの CIDR（単一ホストは `/32` か
`/128`）を取ります。マッチングはファイル内の記載順で最初に一致したものが採用
されるので、広い範囲より前に具体的な範囲を書いてください。

## MCP クライアントへの登録

### Claude Code（プラグイン）

このリポジトリはプラグイン 1 個のマーケットプレイスも兼ねています。

```
/plugin marketplace add shigechika/keycloak-mcp
/plugin install keycloak-mcp@keycloak-mcp
```

プラグインは `uvx keycloak-mcp` を起動し、[環境変数](#環境変数)と同じものを読みます。
Claude Code を起動する前に export しておいてください。

プラグインは `uvx` を起動するため、Claude Code を実行するプロセスの `PATH` に
`uvx` が通っている必要があります。ログインシェルなら通常問題ありませんが、
GUI から起動した場合は通っていないことがあります。プラグインが起動しない場合は
[uv](https://docs.astral.sh/uv/) をシステム全体にインストールしてください。

### Claude Code（手動）

`.mcp.json`:

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

`claude_desktop_config.json` も同じ `env` ブロックを `command` の下に置きます
（`type` フィールドは無し）。完全な例はリポジトリの README を参照してください。

### 直接実行

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp
```

引数無しモードが通常の使い方です。MCP クライアントはこの形で起動します。

## 次に

[セキュリティ調査](investigation.ja.md) でブルートフォースの調査手順と
各書き込みツールの挙動を扱います。

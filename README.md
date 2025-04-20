# falco-nginx-plugin

このプラグインは、Falco のカスタムプラグインとして Nginx のアクセスログをリアルタイムで読み取り、`nginx.uri` というフィールドを Falco ルールで使用できるようにします。

---

## 機能

- `/var/log/nginx/access.log` を `tail -f` 的に読み取り
- 各アクセスログ行から **リクエストURI** を抽出
- Falcoルール内で `nginx.uri contains "/admin"` のような条件が書けます

---

## 前提条件

- Go 1.18 以上
- plugin-sdk-go v0.7.5（固定）
- Falco 0.40.0 以上

---

## ディレクトリ構成

```
falco-nginx-plugin/
├── go.mod
├── pkg/
│   └── nginxlog.go         # プラグイン本体
├── libnginxlog.so          # ビルドで生成される .so ファイル
├── falco.yaml              # Falco プラグイン設定
├── nginx_rules.yaml        # ルール定義ファイル（source: nginx）
```

---

## ビルド手順

```bash
cd falco-nginx-plugin
go mod tidy
go build -buildmode=c-shared -o libnginxlog.so ./pkg
```

---

## Falco 設定（falco.yaml）

```yaml
plugins:
  - name: nginxlog
    library_path: /home/ユーザー名/lab/falco/falco-nginx-plugin/libnginxlog.so
    open_params: "/var/log/nginx/access.log"

load_plugins: [nginxlog]
load_syscall_source: false

stdout_output:
  enabled: true
  priority: debug
```

---

## ルール定義（nginx_rules.yaml）

```yaml
- rule: Detect admin access
  desc: /admin にアクセスしたリクエストを検知
  condition: nginx.uri contains "admin"
  output: "admin accessed"
  priority: WARNING
  source: nginx
```

---

## 実行手順

```bash
sudo falco -c falco.yaml -r nginx_rules.yaml
```

別ターミナルでアクセスログを発生：

```bash
curl http://localhost/admin
```

→ アラート: `admin accessed`

---

## ライセンス

Apache License 2.0

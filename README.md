ConoHa VPS制御ツール
====
ConoHa VPSサービスのサーバ作成や停止、削除のためのツール

## 準備
* ConoHaにログインし、コンソールでAPIユーザを作成する。そのコンソール上の、**テナントID**と**ユーザ名**および設定したパスワードを、**config.ini**に記載する。
* APIユーザを作成後、エンドポイントからIdentity Service、Compute Service、Network Service, DNS Serviceの値を取得し、バージョン名までのパスを**config.ini**に記載する。

```
[api]
CONOHA_IDENTITY_ENDPOINT_BASE = https://identity.tyo1.conoha.io/v2.0/
CONOHA_COMPUTE_ENDPOINT_BASE = https://compute.tyo1.conoha.io/v2/
CONOHA_NETWORK_ENDPOINT_BASE = https://networking.tyo1.conoha.io/v2.0/
CONOHA_DNS_ENDPOINT_BASE = https://dns-service.tyo1.conoha.io/v1/
```
## How to use

### 準備
```bash
pip install -r requirements.txt
```

### VPSサーバのIDとアドレスを取得
```bash
python vps_manage.py -l
```

### VPSサーバのネームタグを指定してIPv4アドレスを取得
```bash
python vps_manage.py --ip <name>
```

### VPSのプラン一覧取得
```bash
python vps_manage.py -c plans
```

### VPSのイメージ一覧取得
```bash
python vps_manage.py -c images
```

### VPSのセキュリティグループ一覧取得
```bash
python vps_manage.py -c security_groups
```

### VPSのセキュリティグループおよびファイアウォールのルール作成
* まずは、config.iniに\[rule\]を記載しておく
```bash
python vps_manage.py --create-rule
```

### VPSサーバの起動、停止、再起動
```bash
python vps_manage.py --start <server_id>
python vps_manage.py --shutdown <server_id>
python vps_manage.py --reboot <server_id>
```

### VPSサーバの作成

* config.iniにSTAG（サーバタグ名）とROOTPASS（管理者パスワード）を指定する場合
```bash
python vps_manage.py --create -s <startup_scriptパス>
```

* サーバタグ名と管理者パスワードを引数指定する場合
```bash
python vps_manage.py --create -s <startup_scriptパス> -t <タグ名> -p <パスワード>
```

※ disable_root_ssh.sh はstartup_scriptのサンプル


### VPSサーバの削除
```bash
python vps_manage.py --delete <server_id>
```


### VPSサーバのプラン変更

* config.iniにSTAG（サーバタグ名）を指定する場合
```bash
python vps_manage.py --change-grade <プラン名（1g, 2g 4g) >
```

* サーバタグ名を引数指定する場合
```bash
python vps_manage.py --change-grade <プラン名（1g, 2g 4g) > -t <タグ名>
```

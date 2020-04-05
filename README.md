ConoHa VPS制御ツール
====
ConoHa VPSサービスのサーバ作成や停止、削除のためのツール

## 準備
ConoHaにログインし、コンソールでAPIユーザを作成する。そのコンソール上の、**テナントID**と**ユーザ名**および設定したパスワードを、**config.ini**に記載する。

## How to use

### 準備
```bash
pip install -r requirements.txt
```

### VPSサーバのIDとアドレスを取得
```bash
python vps_manage.py -l
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
* まずは、config.intに\[rule\]を記載しておく
```bash
python vps_manage.py --rule
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

### VPSサーバの削除
```bash
python vps_manage.py --delete <server_id>
```

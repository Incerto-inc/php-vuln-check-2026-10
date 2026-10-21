# PHP の確認の手順(CVE-2026-109618 / CVE-2026-109619)

2026年10月21日に修正版が出た、PHP の重大な脆弱性2件への対応のための確認の手順です。
**社内のサーバーやパソコンで、どこで PHP が動いていて、更新が要るか**を一覧にします。

- 作成: Incerto合同会社(2026-10-21)
- **読むだけ**です。ファイルの変更・削除、設定の変更はしません。外部への送信もしません
- 結果は画面に出るだけです。そのまま Incerto にお送りいただければ、判断をお手伝いします

## 今回の脆弱性(開発元の告知より)

| 項目 | 内容 |
| --- | --- |
| 中身 | 外部から、ログインなしでサーバー上の不正なプログラムを実行されるおそれ |
| 対象 | 修正版より前のすべての版 |
| 修正版 | **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** |
| 8.1 以前 | 開発元の修正版は出ません。ただし、OS や管理画面の提供元が直しを入れていることがあります(例: Ubuntu 22.04 の php8.1、cPanel の ea-php74〜81)。それ以外は、サポート中の版へ上げる必要があります |
| 確実な対策 | 修正版への更新だけ |

出典: [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) / [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) / [PHP の版の一覧](https://www.php.net/releases/)

## どこで使うか

| 場所 | 確かめ方 |
| --- | --- |
| **レンタルサーバー(共用)の上のサイト** | このコマンドではなく、サーバー会社の管理画面か、WordPress の「ツール → サイトヘルス → 情報 → サーバー」で PHP の版を見てください(コマンドで出る版と、サイトが使う版が違うことがあるため) |
| **社内のサーバー(Linux)・Mac** | `php-check.sh` |
| **社内の Windows のサーバー・パソコン**(XAMPP・IIS など) | `php-check.ps1` |

## 使い方

### Linux・Mac

```bash
bash php-check.sh > php-check-result.txt 2>&1
```

root の権限は要りません(権限があると、より多くの場所を確かめられます)。1分ほどで終わります。

### Windows

PowerShell を開いて、`php-check.ps1` の中身を全部貼り付けて Enter を押します。ファイルのまま動かす場合は:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\php-check.ps1 > php-check-result.txt
```

ドライブ全体は探しません。PHP がふつう入る場所(XAMPP・Laragon・WAMP・IIS・Program Files など)、動いている処理、登録されたサービスだけを見ます。

コピペ用の短いコマンドと読み方は `docs/php-check-guide-2026-10-21.pdf`(A4・3頁)にもまとめています。

## 結果の読み方

| 表示 | 意味 | すること |
| --- | --- | --- |
| `対象です。8.x.y 以降への更新が必要です` / `AFFECTED` | 修正前の版 | 修正版へ更新する |
| `修正済みの版です` / `FIXED` | 修正版以降 | 対応済み |
| `サポートが終わった版です` / `END OF LIFE` | 8.1 以前 | サポート中の版(8.2.35 以降など)へ上げる |
| `OS の部品として入った PHP です` | Ubuntu・Debian・RHEL などの OS が配っている PHP。OS の提供元が、版の番号を変えずに直しを入れる | 番号では判断せず、OS の更新(apt / dnf など)と、OS の提供元のセキュリティ情報を確かめる。※ Sury・Remi・cPanel(ea-php82 以降)・Plesk の PHP もこう表示されますが、これらは開発元と同じ番号なので、表示された版を修正版と比べて判断できます |
| `Apache` に `php_module` / `mod_php` | Apache に組み込んで動かしている | どの動かし方でも更新が必要。開発元の告知では、Apache 組み込みは影響を受けやすい形として挙げられているので、特に急ぐ |
| `session.upload_progress.enabled => On` | 開発元が挙げる緩和の設定が、まだ有効(表示はコマンドライン用の設定の値。Web 側の設定は別のことがある) | 開発元は更新までのつなぎとして Off にすることを挙げていますが、完全な対策ではなく、勧めていない提供元もあります。更新が基本です。変える前に、その仕組みの管理者と相談してください |

## このコマンドで分からないこと

- **Web 側の設定の値**: 表示される設定の値は、コマンドライン用の PHP の設定です。Web(Apache・PHP-FPM)の側は別の設定ファイルのことがあるので、緩和の設定を変えるときは、その仕組みを管理している方が Web 側の設定で確かめてください
- **権限が足りない場所**: root の権限がないと、確かめられない場所や設定があります。気になる場合は、管理者の権限で実行してください
- **OS の部品に直しが入ったか**: OS の部品として入った PHP は、OS の提供元のセキュリティ情報で確かめてください
- **レンタルサーバー上のサイト**: サーバー会社の管理画面か WordPress の「サイトヘルス」で確かめてください
- **入られていないか**: このコマンドは、PHP の場所と版を確かめるものです。不正に入られていないかの調査は別に必要です

## 更新のしかた(主なもの)

| 動かし方 | 更新のしかた |
| --- | --- |
| レンタルサーバー | サーバー会社が更新する。サイトごとに選んでいる版が古い(8.1 以前)なら、管理画面で版を上げる |
| Ubuntu・Debian の部品 | `apt` で OS を更新する(提供元が直しを出してから) |
| RHEL・Rocky・Alma の部品 | `dnf` で OS を更新する(提供元が直しを出してから) |
| 公式の PHP のコンテナ | 修正版の番号のイメージ(例: 8.2.35)が出たことを確かめてから、取り直して作り直す(出る前に取り直しても直りません) |
| cPanel(EasyApache 4) | 10/21 の 25.91 で直っています。更新が当たっているかを確かめる |
| Plesk | 提供元の案内に従って更新する。管理画面の Plesk 自身が使う PHP も対象です |
| Windows(XAMPP・手で入れた PHP) | [windows.php.net](https://windows.php.net/download/) から修正版を入れ直す |

- **更新のあとは、Apache・PHP-FPM などの Web の処理を必ず再起動してください。** 再起動するまで、古い PHP のまま動き続けます
- **製品に入っている PHP**(業務の製品や管理画面に同梱されたもの)は、サーバーの PHP を更新しても直りません。製品の提供元の更新を確かめてください

## 参考情報

- 開発元の告知: [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) / [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- OS の提供元: [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) / [Debian のセキュリティの追跡](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- 管理画面: [cPanel EasyApache 4 の変更の記録](https://docs.cpanel.net/changelogs/easyapache-4-change-log-25/)
- 今回の発見と、関係者が足並みをそろえて公開した経緯: [OpenAI「Coordinated disclosure of critical vulnerabilities」](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities/)

各社の対応は日々変わります。最新の状況は、それぞれの提供元の告知で確かめてください。

## Claude Code で使う場合

`skills/php-vuln-check/` を Claude Code の skill として入れると、「PHP の脆弱性を確認して」と頼むだけで、このコマンドを実行して結果を日本語でまとめます。skill も読むだけで、何も変更しません。

## 動作の確認

GitHub Actions で、次の環境で毎回確かめています(`.github/workflows/test.yml`)。

- Windows: Windows PowerShell 5.1 と PowerShell 7、PHP 8.2、XAMPP と同じ置き方、サポートが終わった PHP 7.4
- Linux: Ubuntu の部品の PHP、公式の PHP のコンテナ(Apache 組み込み)、サポートが終わった PHP 7.4

お問い合わせ: Incerto合同会社 https://www.incerto.tech/

#!/usr/bin/env bash
# PHP の確認(CVE-2026-109618 / CVE-2026-109619、2026-10-21 修正版公開) Incerto合同会社
# 社内のサーバー・PC で、PHP が動いている所と、更新が要るかを確かめます。
# このコマンドは読むだけです。ファイルの変更・削除や、外部への送信はしません。
# 使い方: bash php-check.sh > php-check-result.txt 2>&1
# ※ レンタルサーバー(共用)上のサイトは、ここで出る版とサイトの版が違うことがあります。
#    サイトの版は、サーバー会社の管理画面か WordPress の「ツール → サイトヘルス → 情報 → サーバー」で確かめてください。

# 修正版(これより前は対象)
pkg_owner() {  # OS の部品の一覧に載っていれば、その部品の名前と版を返す
  local f="$1" r
  r=$(readlink -f "$f" 2>/dev/null || echo "$f")
  if command -v dpkg-query >/dev/null 2>&1; then
    local pk; pk=$(dpkg -S "$r" 2>/dev/null | head -1 | cut -d: -f1)
    [ -n "$pk" ] && { dpkg-query -W -f='${Package} ${Version}' "$pk" 2>/dev/null; return 0; }
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -qf "$r" >/dev/null 2>&1 && { rpm -qf "$r" 2>/dev/null | head -1; return 0; }
  fi
  return 1
}
judge() {  # $1 = 版の文字列 / $2 = PHP のファイル(任意)
  local raw="$1" bin="$2" ver mm patch fixed pk
  if [ -n "$bin" ] && pk=$(pkg_owner "$bin"); then
    echo "OS の部品として入った PHP です($pk)。OS の提供元が版の番号を変えずに直しを入れるので、番号では判断できません。OS の更新(apt / dnf など)とセキュリティ情報を確かめてください"; return
  fi
  ver=$(echo "$raw" | grep -o -E '^[0-9]+\.[0-9]+\.[0-9]+')
  [ -z "$ver" ] && { echo "判定できません"; return; }
  mm=${ver%.*}; patch=${ver##*.}
  case "$mm" in
    8.2) fixed=35 ;; 8.3) fixed=36 ;; 8.4) fixed=27 ;; 8.5) fixed=12 ;;
    *) echo "サポートが終わった版です(修正版は出ません)。サポート中の版へ上げる必要があります"; return ;;
  esac
  if [ "$patch" -ge "$fixed" ]; then echo "修正済みの版です"; else echo "対象です。${mm}.${fixed} 以降への更新が必要です"; fi
}

section() { printf '\n--- %s ---\n' "$1"; }
echo "=== PHP の確認 $(date '+%Y-%m-%d %H:%M') / $(hostname) / $(uname -sr) / user=$(id -un) ==="
echo "修正版: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12(これより前は対象。8.1 以前は修正版なし)"

# ---------------------------------------------------------------
section "1. PHP の本体・版・判定"
cands=$(
  {
    type -a -p php php-fpm php-cgi 2>/dev/null
    ls -1d /usr/bin/php* /usr/sbin/php* /usr/local/bin/php* /usr/local/sbin/php* \
      /opt/plesk/php/*/bin/php /opt/cpanel/ea-php*/root/usr/bin/php /opt/remi/php*/root/usr/bin/php \
      /opt/alt/php*/usr/bin/php /usr/local/lsws/lsphp*/bin/php /usr/local/php*/bin/php \
      /opt/homebrew/opt/php*/bin/php /usr/local/opt/php*/bin/php /Applications/MAMP/bin/php/*/bin/php 2>/dev/null
  } | while read -r p; do
    b=$(basename "$p")
    if [[ "$b" =~ ^(php|php[0-9.]+|php-fpm[0-9.]*|php-cgi[0-9.]*)$ ]] && [ -x "$p" ] && [ -f "$p" ]; then
      r=$(readlink -f "$p" 2>/dev/null || echo "$p"); echo "$r"
    fi
  done | sort -u
)
if [ -z "$cands" ]; then
  echo "PHP の本体は見つかりませんでした"
else
  while read -r p; do
    line=$("$p" -v 2>/dev/null | head -1)
    raw=$(echo "$line" | awk '{print $2}')
    echo "$p : ${line:-版を取得できません}"
    [ -n "$raw" ] && echo "    → $(judge "$raw" "$p")"
  done <<< "$cands"
fi

# ---------------------------------------------------------------
section "2. OS の部品として入った PHP(apt / dnf などの版)"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk 'NF==2' | grep -E '^(php[0-9.]*(-cli|-fpm|-common)?|libapache2-mod-php[0-9.]*) ' | head -20
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa 2>/dev/null | grep -E '^php([0-9]+)?(-cli|-fpm|-common)?-[0-9]' | head -20
fi
echo "(ここに出たものは、OS の提供元のセキュリティ情報で直しの有無を確かめます)"

# ---------------------------------------------------------------
section "3. PHP の動かし方(公式の告知では Apache 組み込み = mod_php の影響が最も大きい)"
for a in apache2ctl apachectl httpd; do
  if command -v "$a" >/dev/null 2>&1; then
    m=$("$a" -M 2>/dev/null | grep -i -E 'php[0-9_]*_module')
    echo "Apache: $(command -v "$a") / PHP の組み込み: ${m:-なし}"; break
  fi
done
ps -eo user,args 2>/dev/null | grep -E 'php-fpm: master|php-fpm[0-9.]*: master|lsphp|frankenphp' | grep -v grep | cut -c1-160 | head -10
echo "(php-fpm: master が出れば PHP-FPM で動いています)"
for d in /etc/nginx /etc/httpd /etc/apache2 /usr/local/etc/nginx /usr/local/apache2/conf /usr/local/lsws/conf; do
  [ -d "$d" ] && grep -R -l -E 'fastcgi_pass|proxy:(unix|fcgi).*php|SetHandler.*php|AddHandler.*php|LoadModule +php|lsphp' "$d" 2>/dev/null | head -10
done

# ---------------------------------------------------------------
section "4. 公式が挙げる緩和の設定の今の値(更新までのつなぎ。更新の代わりにはなりません)"
if [ -n "$cands" ]; then
  while read -r p; do
    case "$(basename "$p")" in php|php[0-9.]*) ;; *) continue ;; esac
    echo "[$p]"
    "$p" -i 2>/dev/null | grep -E '^(Loaded Configuration File|session\.upload_progress\.enabled|fatal_error_backtraces) ' | sed 's/^/    /'
  done <<< "$cands"
fi
for f in /etc/php/*/*/php.ini /etc/php.ini /etc/php.d/*.ini /etc/php/*/*/conf.d/*.ini /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf \
         /opt/remi/php*/root/etc/php.ini /usr/local/etc/php/php.ini /usr/local/etc/php/conf.d/*.ini /usr/local/etc/php-fpm.d/*.conf; do
  [ -f "$f" ] && grep -H -E '^[[:space:]]*(php_admin_value\[|php_value\[)?(session\.upload_progress\.enabled|fatal_error_backtraces)' "$f" 2>/dev/null
done
echo "(session.upload_progress.enabled が On なら、更新までの間は Off にするのが公式の緩和の1つです。"
echo " 変える前に、その仕組みを管理している方とご相談ください。Web の処理の再起動が要ります)"

# ---------------------------------------------------------------
section "5. PHP の入ったコンテナ"
if command -v docker >/dev/null 2>&1 && docker ps -q >/dev/null 2>&1; then
  docker ps --format '{{.Names}}' 2>/dev/null | while read -r c; do
    v=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null | grep -E '^PHP_VERSION=' | cut -d= -f2)
    img=$(docker inspect --format '{{.Config.Image}}' "$c" 2>/dev/null)
    [ -n "$v" ] && echo "$c ($img): PHP $v → $(judge "$v")"
  done
  echo "(公式の PHP のイメージをもとにしたコンテナを表示。新しいイメージで作り直すと直ります)"
else
  echo "docker は使われていないか、権限がありません"
fi

# ---------------------------------------------------------------
section "6. PHP で動く主な仕組み(WordPress・phpMyAdmin・EC-CUBE など)"
roots=""
for r in /var/www /srv /usr/share/nginx /usr/share/phpmyadmin /usr/share/zabbix /home "$HOME" /Library/WebServer /Applications/MAMP/htdocs; do
  [ -d "$r" ] && roots="$roots $r"
done
[ -n "$roots" ] && find $roots -maxdepth 6 \( -name node_modules -o -name .git -o -name vendor -o -name cache -o -name uploads \) -prune -o -type f \
  \( -path '*/wp-includes/version.php' -o -path '*/src/Eccube/Common/Constant.php' -o -path '*/lib/moodlelib.php' -o -name occ \
     -o -name LocalSettings.php -o -name artisan -o -iname 'config.inc.php' \) -print 2>/dev/null | sort -u | while read -r f; do
  case "$f" in
    */wp-includes/version.php) echo "WordPress $(grep -E '^\$wp_version' "$f" | sed -E "s/.*'([^']+)'.*/\1/"): $(dirname "$(dirname "$f")")" ;;
    */Constant.php) echo "EC-CUBE: $f" ;;
    */moodlelib.php) echo "Moodle: $f" ;;
    */occ) grep -q -i -E 'nextcloud|owncloud' "$f" 2>/dev/null && echo "Nextcloud/ownCloud: $(dirname "$f")" ;;
    */LocalSettings.php) echo "MediaWiki: $(dirname "$f")" ;;
    */artisan) grep -q -i laravel "$f" 2>/dev/null && echo "Laravel: $(dirname "$f")" ;;
    *) echo "$f" | grep -q -i -E 'phpmyadmin|/pma/' && echo "phpMyAdmin: $(dirname "$f")" ;;
  esac
done
echo "(ここに出た仕組みは、1 の PHP の更新で直ります。仕組み自体の更新とは別です)"

echo
echo "=== 以上です。この結果をそのまま Incerto にお送りください(何も変更していません) ==="

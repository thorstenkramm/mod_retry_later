#!/bin/bash

APACHE_LOG=/var/log/apache2/access.log
DEBUG_LOG=/tmp/retry_later_debug.log
clean_logs() {
  rm $DEBUG_LOG || true
  rm $APACHE_LOG || true
  systemctl reload apache2
}

echo 0 > /var/www/html/test.css
ab -c 5 -n 20 http://localhost/test.css
grep -c "test.css.*429" $APACHE_LOG

clean_logs
cat <<EOF > $CONF_FILE
<IfModule mod_retry_later.c>
    DOSHashTableSize    3097
    DOSPageCount        50
    DOSSiteCount        50
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   10
    DOSDebugLog /tmp/retry_later_debug.log
    DOSClientIPHeader my-ip
    DOSExcludeURIRe \.(jpg|png|gif|css|js|woff|svg)$
    DOSResponseDocument /var/www/html/429.html
</IfModule>
EOF
ab -c 5 -n 20 http://localhost/test.css
grep -c "test.css.*429" $APACHE_LOG

clean_logs
echo "0" > /var/www/html/test.html
ab -c 10 -n 200 http://localhost/test.html
grep -c "test.html.*429" $APACHE_LOG

clean_logs
ab -c 10 -n 200 -H "my-ip: 192.168.1.1" http://localhost/test.html
wc -l /tmp/retry_later_debug.log

clean_logs
echo "my429doc" > /var/www/html/429.html
for I in $(seq 1 200);do
  echo -n "$I: "
  curl -s http://localhost/test.html 2>&1|grep -c "my429doc"
done
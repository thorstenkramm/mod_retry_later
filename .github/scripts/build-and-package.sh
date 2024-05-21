#!/usr/bin/env bash

on_fail() {
  echo ""
  echo "We are very sorry. Something went wrong."
  echo "Command '$previous_command' exited erroneous on line $1."
  echo "Try executing this installer or update with bash debug mode."
  echo "  bash -x $0"
  echo ""
}
debug() {
  previous_command=$this_command
  this_command=$BASH_COMMAND
}
trap 'debug' DEBUG
trap 'on_fail ${LINENO}' ERR

set -e
set -o pipefail

env

VERSION=${GITHUB_REF_NAME}
PKG_NAME=libapache2-mod-retry-later
PKG_ROOT=/pkg

echo "Building DEB for $PKG_NAME version $VERSION ..."

if [ "$(id -u)" -ne 0 ];then
  echo "Script requires root rights. Execute with sudo"
  false
fi

if dpkg -l|grep libapache2-mod-retry-later ;then
    dpkg -P libapache2-mod-retry-later
fi
systemctl stop apache2 || true

CONF_FILE=/etc/apache2/mods-available/retry_later.conf
FILES="/etc/apache2/mods-available/retry_later.load
/etc/apache2/mods-enabled/retry_later.load
/etc/apache2/mods-enabled/retry_later.conf
/usr/lib/apache2/modules/mod_retry_later.so
$CONF_FILE"
clean_up() {
  for FILE in ${FILES};do
    if [ -e ${FILE} ];then
      echo "Deleting $FILE"
      rm -f ${FILE}
    fi
  done
}
apt-get -y install apache2 apache2-dev
apxs -i -a -c mod_retry_later.c
strip /usr/lib/apache2/modules/mod_retry_later.so

cat <<EOF > $CONF_FILE
<IfModule mod_retry_later.c>
    #
    # Refer to https://github.com/thorstenkramm/mod_retry_later for more documentation
    #
    DOSHashTableSize    3097
    DOSPageCount        2
    DOSSiteCount        50
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   10
    # DOSEmailNotify	you@yourdomain.com
    # DOSSystemCommand	"su - someuser -c '/sbin/... %s ...'"
    # DOSLogDir		"/var/lock/mod_retry_later"
    # DOSExcludeURIRe \.(jpg|png|gif|css|js|woff|svg)$
    # DOSResponseDocument /var/www/html/429.html
    # DOSDebugLog /tmp/retry_later_debug.log
    # DOSClientIPHeader my-ip
</IfModule>
EOF

test -e $PKG_ROOT && rm -rf $PKG_ROOT
mkdir -p ${PKG_ROOT}/DEBIAN
mkdir -p ${PKG_ROOT}/etc/apache2/mods-available/
mkdir -p ${PKG_ROOT}/usr/lib/apache2/modules/
mkdir -p ${PKG_ROOT}/usr/share/doc/${PKG_NAME}
cp /etc/apache2/mods-available/retry_later.load ${PKG_ROOT}/etc/apache2/mods-available/
cp /usr/lib/apache2/modules/mod_retry_later.so ${PKG_ROOT}/usr/lib/apache2/modules/
cp $CONF_FILE ${PKG_ROOT}/etc/apache2/mods-available/

chmod 0755 ${PKG_ROOT}/DEBIAN
INSTALLED_SIZE=$[$(du -sb ${PKG_ROOT}/etc|awk '{print $1}') + $(du -sb ${PKG_ROOT}/usr|awk '{print $1}')]

#
# Create a changelog, even dummy
#
cat <<EOF | gzip -n --best -c >${PKG_ROOT}/usr/share/doc/${PKG_NAME}/changelog.gz
rport-guacamole; urgency=low

  * Non-maintainer upload.
EOF
chmod 0644 ${PKG_ROOT}/usr/share/doc/${PKG_NAME}/changelog.gz

case $(uname -m) in
x86_64)
    ARCH='amd64'
    ;;
armv7l)
    ARCH='armhf'
    ;;
aarch64)
    ARCH='arm64'
    ;;
esac
echo "ARCH = ${ARCH}"

cat <<EOF >${PKG_ROOT}/DEBIAN/control
Package: $PKG_NAME
Version: ${VERSION}
Maintainer: Thorsten Kramm <tkramm@dimedis.de>
Depends: libc6, apache2, apache2-bin
Installed-Size: ${INSTALLED_SIZE}
Architecture: ${ARCH}
Section: misc
Priority: optional
Homepage: https://github.com/thorstenkramm/mod_retry_later
Description: Module for rate limiting
 Supports sending proper retry later HTTP 429 status.
EOF

cat <<EOF >${PKG_ROOT}/DEBIAN/conffiles
$CONF_FILE
/etc/apache2/mods-available/retry_later.load
EOF

cat <<EOF >${PKG_ROOT}/usr/share/doc/${PKG_NAME}/copyright
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Source: https://github.com/thorstenkramm/mod_retry_later
Copyright: 2024
License: GPL2

Files: *
Copyright: 2024
License:  GPL2
EOF
chmod 0644 ${PKG_ROOT}/usr/share/doc/${PKG_NAME}/copyright

cat <<EOF >${PKG_ROOT}/DEBIAN/postinst
#!/bin/sh
set -e
a2enmod retry_later
EOF
chmod 0555 ${PKG_ROOT}/DEBIAN/postinst

. /etc/os-release
PKG_FILE=${PKG_ROOT}/${PKG_NAME}_${VERSION_ID}_${ID}_${ARCH}.deb
cd /
dpkg-deb -v --build ${PKG_ROOT}
mv ${PKG_ROOT}.deb ${PKG_FILE}
echo "==============================================================="
echo "🐥 Created /$PKG_FILE"
echo "==============================================================="
clean_up

echo "Performing some tests now ..."
dpkg -l|grep ${PKG_NAME} && dpkg -P ${PKG_NAME}
clean_up
dpkg -i /${PKG_FILE}
apachectl -t -D DUMP_INCLUDES|grep retry_later
systemctl start apache2
systemctl status apache2
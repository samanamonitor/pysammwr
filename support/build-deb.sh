#!/bin/bash

set -xe

. /etc/os-release

TEMPDIR=/usr/src

python3 setup.py build
python3 setup.py bdist

tarball_path=$(find dist -type f -name \*.tar.gz)
tarball=$(basename ${tarball_path})

t=${tarball%.linux-x86_64.tar.gz}
VERSION=${t#*-}
PACKAGE_NAME=$(sed -n -e "s/^Package: \+//p" ${TEMPDIR}/debian/control)

BUILD_DIR=${TEMPDIR}/${PACKAGE_NAME}_${VERSION}-1_amd64
mkdir -p ${BUILD_DIR}/DEBIAN
cp ${TEMPDIR}/debian/control ${BUILD_DIR}/DEBIAN
if [ -f ${TEMPDIR}/debian/postinst ]; then
    install -m 0755 -o root -g root ${TEMPDIR}/debian/postinst ${BUILD_DIR}/DEBIAN/postinst
fi

tar -C ${BUILD_DIR} -xzvf ${tarball_path}

dpkg --build ${BUILD_DIR}

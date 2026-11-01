SUMMARY = "Python modules and various SELinux utilities."
DESCRIPTION = "\
This package contains Python modules sepolgen, sepolicy; And the \
SELinux utilities audit2allow, chcat, semanage ..."
SECTION = "base"
LICENSE = "GPL-2.0-or-later"
LIC_FILES_CHKSUM = "file://${S}/LICENSE;md5=393a5ca445f6965873eca0259a17f833"

require selinux_common.inc

inherit python3targetconfig

SRC_URI += "file://0001-sepolicy-fix-install-path-for-new-pymodule-sepolicy.patch;patchdir=.. \
           "

S = "${UNPACKDIR}/${BP}/python"

DEPENDS = "libsepol libselinux gettext-native python3-setuptools-scm-native python3-pip-native \
           python3-build-native python3-wheel-native"

RDEPENDS:${PN} = "\
        python3-core \
        python3-codecs \
        python3-io \
        python3-ipy \
        python3-stringold \
        python3-syslog \
        python3-unixadmin \
        libselinux-python \
        libsemanage-python \
        setools \
"
RDEPENDS:${PN}-audit2allow = "\
        python3-core \
        libselinux-python \
        ${PN}-sepolgen \
"
RDEPENDS:${PN}-chcat = "\
        python3-core \
        python3-codecs \
        python3-shell \
        python3-stringold \
        python3-unixadmin \
        libselinux-python \
        ${PN} \
"
RDEPENDS:${PN}-semanage = "\
        python3-core \
        python3-ipy \
        python3-compression \
        python3-xml \
        python3-misc \
        libselinux-python \
        audit-python \
        ${PN} \
        ${PN}-sepolgen \
"
PACKAGECONFIG ??= "sepolicy-generate"
PACKAGECONFIG[sepolicy-generate] = ",,,"
RDEPENDS:${PN}-sepolicy = "\
        ${@bb.utils.contains('PACKAGECONFIG', 'sepolicy-generate', 'binutils', '', d)} \
        python3-core \
        python3-codecs \
        python3-distro \
        python3-syslog \
        python3-multiprocessing \
        ${PN} \
"
RDEPENDS:${PN}-sepolgen-ifgen = "\
        python3-core \
        libselinux-python \
"

PACKAGES =+ "\
        ${PN}-audit2allow \
        ${PN}-sepolgen-ifgen \
        ${PN}-chcat \
        ${PN}-semanage \
        ${PN}-sepolgen \
        ${PN}-sepolicy \
"
FILES:${PN}-audit2allow = "\
        ${bindir}/audit2allow \
        ${bindir}/audit2why \
"
FILES:${PN}-chcat = "\
        ${bindir}/chcat \
"
FILES:${PN}-semanage = "\
        ${sbindir}/semanage \
        ${datadir}/bash-completion/completions/semanage \
"
# The ${bindir}/sepolgen is a symlink to ${bindir}/sepolicy
FILES:${PN}-sepolicy = "\
        ${bindir}/sepolgen \
        ${bindir}/sepolicy \
        ${datadir}/bash-completion/completions/sepolicy \
"
FILES:${PN}-sepolgen-ifgen = "\
        ${bindir}/sepolgen-ifgen \
        ${bindir}/sepolgen-ifgen-attr-helper \
"
FILES:${PN}-sepolgen = "\
        ${PYTHON_SITEPACKAGES_DIR}/sepolgen* \
        ${localstatedir}/lib/sepolgen/perm_map \
"

FILES:${PN} += "\
        ${PYTHON_SITEPACKAGES_DIR}/seobject.py* \
        ${PYTHON_SITEPACKAGES_DIR}/sepolicy*.dist-info \
        ${PYTHON_SITEPACKAGES_DIR}/sepolicy/* \
"

do_install() {
    oe_runmake \
        DESTDIR="${D}" \
        PREFIX=${prefix} \
        PYLIBVER='python${PYTHON_BASEVERSION}' \
        PYTHONLIBDIR='${PYTHON_SITEPACKAGES_DIR}' \
        PIP_NO_BUILD_ISOLATION=0 \
        install

    # Remove .pyc files
    find ${D} -name *.pyc -delete
    # Remove RECORD file
    find ${D} -path *.dist-info/RECORD -delete

    # Fix buildpaths issue
    sed -i -e 's,${WORKDIR},,g' \
        ${D}${PYTHON_SITEPACKAGES_DIR}/sepolicy-${PV}.dist-info/direct_url.json

}

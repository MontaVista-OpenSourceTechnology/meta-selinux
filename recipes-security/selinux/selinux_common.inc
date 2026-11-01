HOMEPAGE = "https://github.com/SELinuxProject"

SRC_URI = "git://github.com/SELinuxProject/selinux.git;branch=main;protocol=https"
SRCREV = "2233a23a4d4f1bf29054037babec13f30d038e65"

require conf/selinux_refpolicy_common.inc

S = "${UNPACKDIR}/${BP}/${BPN}"

UPSTREAM_CHECK_GITTAGREGEX = "(?P<pver>\d+(\.\d+)+)"

do_compile() {
    oe_runmake all
}

do_install() {
    oe_runmake install \
        DESTDIR="${D}" \
        PREFIX="${prefix}" \
        INCLUDEDIR="${includedir}" \
        LIBDIR="${libdir}" \
        SHLIBDIR="${base_libdir}"
}

CVE_PRODUCT ?= "selinux_project:selinux"

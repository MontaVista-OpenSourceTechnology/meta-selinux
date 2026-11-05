HOMEPAGE = "https://github.com/SELinuxProject"

SRC_URI = "git://github.com/SELinuxProject/selinux.git;branch=main;protocol=https"
SRCREV = "ca10fc4204ed60540d41d2499127c18ad0643f9e"

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

CVE_STATUS[CVE-2026-59676] = "not-applicable-config: The vulnerable seunshare utility is built by selinux-sandbox."

python __anonymous() {
    if d.getVar("BPN") == "selinux-sandbox":
        d.delVarFlag("CVE_STATUS", "CVE-2026-59676")
}

SUMMARY = "Static analysis tool for SELinux policy source files"
DESCRIPTION = "SELint checks refpolicy style .te, .if and .fc files for \
convention, style, warning and error level issues."
HOMEPAGE = "https://github.com/SELinuxProject/selint"
SECTION = "devel"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=3b83ef96387f14655fc854ddc3c6bd57"

SRC_URI = "git://github.com/SELinuxProject/selint.git;branch=main;protocol=https"
# Bumping this means re-syncing files/selint.conf in the refpolicy recipe.
SRCREV = "fdf0d417bcefc6a82be7349d47bbef14e8d5fbbb"
PV = "1.5.1+git"

UPSTREAM_CHECK_GITTAGREGEX = "(?P<pver>\d+(\.\d+)+)"

# libconfuse and uthash come from meta-oe; the rest are for autoreconf.
DEPENDS = "libconfuse uthash pkgconfig-native autoconf-archive-native \
           bison-native flex-native"

# The testsuite would need the check framework for no benefit here.
EXTRA_OECONF = "--without-check"

CONFFILES:${PN} = "${sysconfdir}/selint.conf"

inherit autotools

BBCLASSEXTEND = "native"

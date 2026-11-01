SUMMARY = "SELinux library and simple utilities"
DESCRIPTION = "libselinux provides an API for SELinux applications to get and set \
process and file security contexts and to obtain security policy \
decisions.  Required for any applications that use the SELinux API."
SECTION = "base"
LICENSE = "LicenseRef-PD"
LIC_FILES_CHKSUM = "file://${S}/LICENSE;md5=84b4d2c6ef954a2d4081e775a270d0d0"

require selinux_common.inc

inherit lib_package pkgconfig

DEPENDS = "libsepol libpcre2"
DEPENDS:append:libc-musl = " fts"

def get_policyconfigarch(d):
    import re
    target = d.getVar('TARGET_ARCH')
    p = re.compile('i.86')
    target = p.sub('i386',target)
    return "ARCH=%s" % (target)

EXTRA_OEMAKE = "${@get_policyconfigarch(d)}"
EXTRA_OEMAKE:append:libc-musl = " FTS_LDLIBS=-lfts"

CFLAGS:append = " -DAGGRESSIVE_FREE_AFTER_REGEX_MATCH"

# LTO fat objects in static library embed original source paths in .gnu.lto_* IR
# sections which are not affected by -ffile-prefix-map, causing buildpaths QA failure
LTO = ""

BBCLASSEXTEND = "native"

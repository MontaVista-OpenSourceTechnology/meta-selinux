require selinux_20200710.inc
require ${BPN}.inc

LIC_FILES_CHKSUM = "file://LICENSE;md5=84b4d2c6ef954a2d4081e775a270d0d0"

SRC_URI[md5sum] = "693680c021feb69a4b258b0370021461"
SRC_URI[sha256sum] = "ea5dcbb4d859e3f999c26a13c630da2f16dff9462e3cc8cb7b458ac157d112e7"

SRC_URI += "\
        file://libselinux-make-O_CLOEXEC-optional.patch \
        file://libselinux-make-SOCK_CLOEXEC-optional.patch \
        file://libselinux-define-FD_CLOEXEC-as-necessary.patch \
        "

SRC_URI_append_libc-musl = " \
        file://0001-libselinux-do-not-define-gettid-for-musl.patch \
        "

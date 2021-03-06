HOMEPAGE = "https://github.com/SELinuxProject"

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

#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
# Runtime (testimage) cases for the SELinux support provided by meta-selinux.
#
# Enable them by adding the module name to TEST_SUITES, e.g.
#
#     TEST_SUITES:append = " selinux"
#
# Every case skips itself (instead of failing) when the image does not provide
# the packages, kernel features, SELinux domain or policy variant it needs, so
# the module is safe to enable for any image.  An image that installs
# packagegroup-core-selinux (as core-image-selinux does) satisfies the package,
# feature and kernel requirements of all of them.
#
# The cases that inspect or change system state need an administrative domain
# (sysadm_t, unconfined_t, secadm_t).  With refpolicy-mcs an ssh login as root
# lands in staff_t, which cannot read the policy store, the audit log or the
# kernel ring buffer, so those cases skip.  A console login as root gets
# sysadm_r:sysadm_t; to get the same over ssh, uncomment the system_r:sshd_t
# line in the policy's contexts/users/root.
#
# The denial, module and AVC cases additionally need a policy that confines
# administrators (the mcs and mls variants).  The targeted and minimum variants
# run admins as unconfined_t on purpose, so those cases skip there.

import re
import time

from oeqa.runtime.case import OERuntimeTestCase
from oeqa.core.decorator.depends import OETestDepends
from oeqa.core.decorator.data import skipIfNotFeature
from oeqa.runtime.decorator.package import OEHasPackage


# Domains that are allowed to administer the SELinux configuration.
ADMIN_DOMAINS = ('sysadm_t', 'unconfined_t', 'secadm_t')

# Policy variants in which refpolicy confines administrators.  The targeted and
# minimum variants deliberately run administrators as unconfined_t, with the
# same access as if SELinux were disabled (see refpolicy-targeted_git.bb), so
# the checks below that rely on an access being denied only apply here.
CONFINING_POLICIES = ('mcs', 'mls')

# Name of the policy module built by SELinuxModuleTest.
TEST_MODULE_NAME = 'oeqa-local'

# Scratch directory for the policy module sources on the target.
TEST_MODULE_DIR = '/tmp/oeqa-selinux'

# Source of the test module.  It grants the administrative domain the access
# refpolicy withholds by default, so loading and removing the module can be
# observed with an existing file instead of needing a reboot or a relabel.
TEST_MODULE_TE = """\
module %(module)s 1.0;

require {
    type %(domain)s;
    type shadow_t;
    class file { getattr open read };
}

allow %(domain)s shadow_t:file { getattr open read };
"""


def parse_sestatus(output):
    """
    Return the key/value pairs of the `sestatus -v` header as a dict.

    `sestatus -v` prints a header block of "Key: value" lines followed by
    indented sections describing processes, booleans and file contexts; only
    the header is of interest here, so parsing stops at the first blank line.
    """
    info = {}
    for line in output.splitlines():
        if not line.strip():
            break
        key, sep, value = line.partition(':')
        if sep and key.strip():
            info[key.strip()] = value.strip()
    return info


class SELinuxTest(OERuntimeTestCase):
    """Helpers shared by the SELinux runtime cases."""

    def run_cmd(self, command, timeout=None):
        status, output = self.target.run(command, timeout=timeout)
        self.logger.debug('%s\n-> %d\n%s' % (command, status, output))
        return status, output

    def run_ok(self, command, timeout=None):
        status, output = self.run_cmd(command, timeout=timeout)
        self.assertEqual(status, 0, "Command '%s' failed with status %d:\n%s"
                         % (command, status, output))
        return output

    def sestatus(self):
        """Return the parsed `sestatus -v` header."""
        return parse_sestatus(self.run_ok('sestatus -v'))

    def process_context(self):
        """Return the SELinux context of the session, or '' if unavailable."""
        status, output = self.run_cmd('cat /proc/self/attr/current')
        if status != 0:
            return ''
        # The file is not NUL terminated for all readers.
        return output.replace('\x00', '').strip()

    def selinux_domain(self):
        """Return the type component of the session's SELinux context."""
        parts = self.process_context().split(':')
        return parts[2] if len(parts) > 2 else ''

    def require_admin(self):
        """
        Skip unless the session runs in a domain that may administer SELinux.

        staff_t and user_t can query some of the configuration, but they cannot
        write the policy store, read the audit log or read the kernel ring
        buffer, so tests that poke at those cannot be meaningful.
        """
        domain = self.selinux_domain()
        if domain not in ADMIN_DOMAINS:
            self.skipTest(
                'This test needs an administrative SELinux domain, but the '
                'session runs as %r.  With refpolicy-mcs an ssh login as root '
                'lands in staff_t because contexts/users/root has no '
                'system_r:sshd_t entry; a console login gets '
                'sysadm_r:sysadm_t.'
                % (domain or self.process_context()))
        return domain

    def require_confining_policy(self):
        """
        Skip unless the loaded policy confines administrative domains.

        The refpolicy-targeted and -minimum variants explicitly give admins
        unconfined_t, so on those images an access such as reading /etc/shadow
        is deliberately allowed and cannot be tested for denial.
        """
        info = self.sestatus()
        policy = info.get('Loaded policy name')
        if policy not in CONFINING_POLICIES:
            self.skipTest('Test expects a confining policy (%s), but %r is '
                          'loaded; targeted and minimum run administrators '
                          'unconfined on purpose'
                          % ('/'.join(CONFINING_POLICIES), policy))

    def write_file(self, path, content):
        self.run_ok('mkdir -p %s' % path.rsplit('/', 1)[0])
        self.run_ok("cat > %s << 'OEQA_EOF'\n%sOEQA_EOF" % (path, content))

    def shadow_read_denied(self):
        """Return True when reading /etc/shadow is blocked by SELinux."""
        status, output = self.run_cmd('cat /etc/shadow')
        return status != 0 and 'Permission denied' in output

    def require_shadow_denial(self):
        """Skip unless reading /etc/shadow is blocked, as this test needs it."""
        if not self.shadow_read_denied():
            self.skipTest('Reading /etc/shadow is allowed, so this test has '
                          'no denied access to work with')

    def memtotal_mb(self):
        """Return the target's total RAM in MB, or None if it cannot tell."""
        status, output = self.run_cmd(
            "awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo")
        if status != 0:
            return None
        try:
            return int(output.strip())
        except ValueError:
            return None


class SELinuxStatusTest(SELinuxTest):
    """The system must report SELinux as enabled and enforcing."""

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('policycoreutils-sestatus')
    @OETestDepends(['ssh.SSHTest.test_ssh'])
    def test_sestatus(self):
        output = self.run_ok('sestatus -v')
        info = parse_sestatus(output)

        self.assertEqual(info.get('SELinux status'), 'enabled',
                         'SELinux is not enabled:\n%s' % output)
        self.assertEqual(info.get('Current mode'), 'enforcing',
                         'SELinux is not enforcing:\n%s' % output)
        self.logger.info('SELinux enabled with policy %r, MLS %r, session '
                         'context %r'
                         % (info.get('Loaded policy name'),
                            info.get('Policy MLS status'),
                            self.process_context()))

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OETestDepends(['selinux.SELinuxStatusTest.test_sestatus'])
    def test_kernel_enforcing(self):
        # sestatus is userspace; /sys/fs/selinux/enforce is what the kernel
        # actually enforces.
        output = self.run_ok('cat /sys/fs/selinux/enforce')
        self.assertEqual(output.strip(), '1',
                         'The kernel is not enforcing SELinux (enforce=%r)'
                         % output.strip())


class SELinuxDenialTest(SELinuxTest):
    """Access that the policy denies must be denied."""

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('policycoreutils-sestatus')
    @OETestDepends(['selinux.SELinuxStatusTest.test_kernel_enforcing'])
    def test_read_shadow_denied(self):
        # /etc/shadow is readable by root alone, so a failure to read it cannot
        # be a plain permission problem: it is the policy withholding
        # shadow_t:file from the confined session domain.  staff_t is confined
        # just as sysadm_t is, so this runs for either.
        self.require_confining_policy()
        context = self.process_context()

        status, output = self.run_cmd('cat /etc/shadow')
        self.assertNotEqual(
            status, 0,
            'Reading /etc/shadow as %s was allowed; the policy no longer '
            'denies it:\n%s' % (context, output))
        self.assertIn(
            'Permission denied', output,
            'Reading /etc/shadow as %s failed for a reason other than an '
            'SELinux denial:\n%s' % (context, output))


class SELinuxToolTest(SELinuxTest):
    """The SELinux userspace tools must work."""

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('libselinux-bin')
    @OETestDepends(['selinux.SELinuxStatusTest.test_kernel_enforcing'])
    def test_getenforce(self):
        self.assertEqual(self.run_ok('getenforce').strip(), 'Enforcing',
                         'getenforce does not report enforcing mode')

        # Writing the value the kernel already has is not a privilege check:
        # sel_write_enforce() only asks for SECURITY__SETENFORCE inside
        # 'if (new_value != old_value)' (security/selinux/selinuxfs.c), so this
        # exercises setenforce and libselinux in any domain.
        self.run_ok('setenforce 1')
        self.assertEqual(self.run_ok('getenforce').strip(), 'Enforcing',
                         'setenforce 1 left the system in the wrong mode')

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('libselinux-bin')
    @OETestDepends(['selinux.SELinuxStatusTest.test_kernel_enforcing'])
    def test_setenforce_roundtrip(self):
        # Leaving enforcing mode is the operation that needs the
        # security:setenforce permission; refpolicy grants it to the admin
        # domains only.
        self.require_admin()

        status, output = self.run_cmd('setenforce 0')
        self.assertEqual(status, 0,
                         'setenforce 0 failed:\n%s' % output)
        try:
            self.assertEqual(self.run_ok('getenforce').strip(), 'Permissive',
                             'setenforce 0 did not switch to permissive mode')
            self.assertEqual(
                self.run_ok('cat /sys/fs/selinux/enforce').strip(), '0',
                'setenforce 0 did not reach the kernel')
        finally:
            # Never leave the target permissive behind us.
            self.run_ok('setenforce 1')

        self.assertEqual(self.run_ok('getenforce').strip(), 'Enforcing',
                         'setenforce 1 did not switch back to enforcing mode')
        self.assertEqual(
            self.run_ok('cat /sys/fs/selinux/enforce').strip(), '1',
            'setenforce 1 did not reach the kernel')

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('libselinux-bin')
    @OETestDepends(['selinux.SELinuxStatusTest.test_kernel_enforcing'])
    def test_matchpathcon(self):
        output = self.run_ok('matchpathcon /etc/shadow')
        self.assertIn('shadow_t', output,
                      'matchpathcon did not map /etc/shadow to shadow_t:\n%s'
                      % output)

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('libselinux-bin')
    @OETestDepends(['selinux.SELinuxToolTest.test_matchpathcon'])
    def test_matchpathcon_verify(self):
        # Needs getattr on shadow_t, which only the admin domains have.
        self.require_admin()
        output = self.run_ok('matchpathcon -V /etc/shadow')
        # Success is exactly "<path> verified."; a mismatch prints
        # "<path> has context ..., should be ...", so anchor the whole line
        # rather than looking for a word that other messages may contain.
        self.assertRegex(output, r'^/etc/shadow verified\.$',
                         'matchpathcon -V did not confirm the label of '
                         '/etc/shadow:\n%s' % output)

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('selinux-python-semanage')
    @OETestDepends(['selinux.SELinuxToolTest.test_matchpathcon'])
    def test_semanage(self):
        self.require_admin()

        # Queries.
        output = self.run_ok('semanage login -l')
        self.assertIn('__default__', output,
                      'semanage login -l did not list the default mapping:\n%s'
                      % output)
        self.run_ok('semanage boolean -l')
        self.run_ok('semanage fcontext -l')

        # Add/list/remove round trip.  -N keeps the running policy untouched;
        # the rule is committed to the local store and listed from there.
        fcontext = TEST_MODULE_DIR + '/alt(/.*)?'
        token = TEST_MODULE_DIR + '/alt'
        try:
            self.run_ok("semanage fcontext -N -a -t tmp_t '%s'" % fcontext)
            output = self.run_ok("semanage fcontext -l | grep -F '%s'" % token)
            self.assertIn(fcontext, output,
                          'Added fcontext rule is missing from the listing:\n%s'
                          % output)
        finally:
            # Ignore failures here so that a failed add does not mask itself
            # with a failed delete.
            self.run_cmd("semanage fcontext -N -d '%s'" % fcontext)

        status, output = self.run_cmd("semanage fcontext -l | grep -F '%s'"
                                     % token)
        self.assertNotEqual(status, 0,
                            'Removed fcontext rule is still listed:\n%s'
                            % output)

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('policycoreutils-semodule')
    @OEHasPackage('checkpolicy')
    @OEHasPackage('semodule-utils-semodule-package')
    @OETestDepends(['selinux.SELinuxToolTest.test_matchpathcon'])
    def test_semodule_load_remove(self):
        self.require_confining_policy()
        domain = self.require_admin()
        self.require_shadow_denial()

        # semodule re-expands the whole policy, which does not fit on a small
        # qemu guest: it gets OOM-killed rather than reporting an error.
        memtotal = self.memtotal_mb()
        if memtotal is not None and memtotal < 512:
            self.skipTest('Loading a policy module needs more memory than this '
                          'target has (%d MB); raise it, e.g. with '
                          'TEST_QEMUPARAMS = "-m 1024"' % memtotal)

        te = '%s/%s.te' % (TEST_MODULE_DIR, TEST_MODULE_NAME)
        mod = '%s/%s.mod' % (TEST_MODULE_DIR, TEST_MODULE_NAME)
        pp = '%s/%s.pp' % (TEST_MODULE_DIR, TEST_MODULE_NAME)

        # checkmodule needs -M when the policy has MLS/MCS enabled.
        mls = self.sestatus().get('Policy MLS status', '').lower() == 'enabled'
        checkmodule = 'checkmodule -m %s-o %s %s' % ('-M ' if mls else '', mod, te)

        self.write_file(te, TEST_MODULE_TE % {'module': TEST_MODULE_NAME,
                                              'domain': domain})
        try:
            self.run_ok(checkmodule)
            self.run_ok('semodule_package -o %s -m %s' % (pp, mod))

            self.run_ok('semodule -i %s' % pp)
            self.assertIn(TEST_MODULE_NAME, self.run_ok('semodule -l'),
                          'Installed module is not listed by semodule -l')

            # The new rule allows the domain to read /etc/shadow.
            status, output = self.run_cmd('cat /etc/shadow')
            self.assertEqual(status, 0,
                             'Reading /etc/shadow is still denied after loading '
                             '%s for %s:\n%s'
                             % (TEST_MODULE_NAME, domain, output))
        finally:
            self.run_cmd('semodule -r %s' % TEST_MODULE_NAME)

        output = self.run_ok('semodule -l')
        self.assertNotIn(TEST_MODULE_NAME, output,
                         'Removed module is still listed by semodule -l:\n%s'
                         % output)
        self.assertTrue(self.shadow_read_denied(),
                        'Reading /etc/shadow is still allowed after removing '
                        '%s' % TEST_MODULE_NAME)


class SELinuxAuditTest(SELinuxTest):
    """The kernel audit subsystem must work and record SELinux denials."""

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OETestDepends(['selinux.SELinuxStatusTest.test_kernel_enforcing'])
    def test_kernel_config(self):
        status, output = self.run_cmd('test -r /proc/config.gz')
        if status != 0:
            self.skipTest('No /proc/config.gz on the target; the kernel needs '
                          'CONFIG_IKCONFIG and CONFIG_IKCONFIG_PROC to make the '
                          'configuration readable at runtime')

        output = self.run_ok("zcat /proc/config.gz | grep -E '^CONFIG_"
                             "(AUDIT|AUDITSYSCALL|SECURITY_SELINUX)=y$'")
        for option in ('CONFIG_AUDIT=y', 'CONFIG_AUDITSYSCALL=y',
                       'CONFIG_SECURITY_SELINUX=y'):
            self.assertIn(option, output,
                          '%s is not set in the running kernel:\n%s'
                          % (option, output))

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('auditd')
    @OETestDepends(['selinux.SELinuxAuditTest.test_kernel_config'])
    def test_auditd_running(self):
        self.require_admin()

        if 'systemd' in self.td.get('VIRTUAL-RUNTIME_init_manager', ''):
            status, output = self.run_cmd('systemctl is-active auditd.service')
            self.assertEqual(status, 0,
                             'auditd.service is not active:\n%s' % output)
        else:
            self.run_ok('pidof auditd')

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('auditd')
    @OETestDepends(['selinux.SELinuxAuditTest.test_auditd_running'])
    def test_auditctl_status(self):
        self.require_admin()
        output = self.run_ok('auditctl -s')

        # 'enabled' is the kernel audit state: 0 = off, 1 = on,
        # 2 = on and locked until reboot.
        match = re.search(r'^enabled\s+(\d+)', output, re.MULTILINE)
        self.assertIsNotNone(match,
                             'auditctl -s reported no state:\n%s' % output)
        self.assertIn(match.group(1), ('1', '2'),
                      'Kernel auditing is disabled:\n%s' % output)

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('auditd')
    @OETestDepends(['selinux.SELinuxDenialTest.test_read_shadow_denied'])
    def test_avc_recorded(self):
        self.require_admin()

        # The denied read of /etc/shadow, asserted by the test this depends on,
        # is the event whose record is looked for below.

        # AVC records reach the audit log when auditd is consuming them and
        # the kernel ring buffer otherwise; accept either, but give auditd a
        # moment to flush the record it just received.
        deadline = time.time() + 15
        while True:
            status, ausearch = self.run_cmd('ausearch -m AVC -ts recent')
            status, dmesg = self.run_cmd('dmesg')
            records = '%s\n%s' % (ausearch, dmesg)
            if re.search(r'avc:\s+denied', records) and 'shadow' in records:
                self.logger.info('AVC record found in the audit log:\n%s'
                                 % ausearch.strip())
                return
            if time.time() >= deadline:
                break
            time.sleep(3)

        self.fail('No AVC record for the denied read of /etc/shadow was found '
                  'in the audit log or the kernel ring buffer.\n'
                  'ausearch:\n%s\ndmesg (tail):\n%s'
                  % (ausearch, '\n'.join(dmesg.splitlines()[-20:])))

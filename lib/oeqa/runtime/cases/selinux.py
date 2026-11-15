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
# Two domains matter here, and the cases pick whichever one lets them observe
# what they assert:
#
#   administrative  Needed to inspect or change system state: the policy store,
#                   the audit log, the kernel ring buffer, setenforce.  The
#                   cases use the session's own domain when it is one, and
#                   otherwise switch with newrole:
#
#                       newrole -r sysadm_r -t sysadm_t -- -c '<command>'
#
#                   The '--' arguments are those of the login shell newrole
#                   execs, hence the -c.  Switching needs a root account PAM can
#                   authenticate without a prompt, i.e. IMAGE_FEATURES
#                   "empty-root-password"; without that the cases skip.
#
#   confined        Needed to assert that an access is denied.  A domain only
#                   counts as confined here if the policy also withholds the
#                   administrative accesses above; the two are the same thing in
#                   practice, since refpolicy grants both to the domains in
#                   ADMIN_DOMAINS and neither to a restricted user domain.
#
# Which domain the ssh session lands in depends on the policy variant, not on
# anything the session can choose:
#
#   refpolicy-targeted, -minimum   unconfined_t.  Their recipes make
#                                  unconfined_u the default SELinux user and
#                                  give administrators unconfined_t on purpose,
#                                  "the same access as if SELinux was not
#                                  enabled".
#
#   refpolicy-standard, -mcs, -mls staff_t.  root's SELinux user lists staff_r
#                                  first and pam_selinux picks the first role,
#                                  so the login is confined even though the user
#                                  is uid 0.  newrole then reaches sysadm_t.
#
# The cases therefore never test for a policy name; they read the domain from
# /proc/self/attr/current and decide from that.  A denial needs a confined
# domain, so on the unconfined variants the cases fall back to logging in as a
# test account mapped to the SELinux user user_u, which pam_selinux puts in
# user_t - the restricted-user domain that the policy does confine.  Note that
# su cannot be used for this: pam_selinux is not in its PAM stack, so it leaves
# the caller's context alone and ssh is the only login here that relabels.

import os.path
import re
import shlex
import time

from oeqa.runtime.case import OERuntimeTestCase
from oeqa.core.decorator.depends import OETestDepends
from oeqa.core.decorator.data import skipIfNotFeature
from oeqa.runtime.decorator.package import OEHasPackage


# Domains that may administer SELinux.  refpolicy grants these the policy
# store, the audit log, the kernel ring buffer and setenforce, and it grants
# nobody else; a session in one of them is also allowed everything the denial
# cases try to observe, so it cannot serve as their confined side.
#
# Being an administrative domain does not mean being unconfined: staff_t is not
# one of these, and sysadm_t and secadm_t are confined for most objects.  In
# particular none of the three may read shadow_t.
ADMIN_DOMAINS = ('sysadm_t', 'unconfined_t', 'secadm_t')

# Domains the policy deliberately leaves unconfined, with the access the caller
# would have with SELinux disabled.  refpolicy-targeted and -minimum make
# unconfined_u the default SELinux user for that reason, so a denial cannot be
# asserted against a session in this domain.
UNCONFINED_DOMAINS = ('unconfined_t',)

# Files the denial cases read, most likely first.  Each has to be readable by
# every user, so that a refusal cannot be the discretionary permissions, and
# carry a label restricted users may not read.  /var/log/messages is 0644
# var_log_t, and refpolicy allows no restricted user domain to read var_log_t.
#
# A dontaudited denial is no good here: /etc/shadow would be the obvious choice
# for "root is denied this", but refpolicy has
# 'dontaudit staff_t shadow_t:file { getattr ioctl lock open read }', so that
# denial is deliberately kept out of the audit log and no AVC record can be
# observed for it.
PROBE_PATHS = ('/var/log/messages', '/var/log/syslog')

# Account logged in as when the session itself is unconfined.  Its SELinux user
# is a restricted one, so pam_selinux puts the session in user_t.
CONFINED_USER = 'oeqa_selinux'
CONFINED_SELINUX_USER = 'user_u'

# Name of the policy module built by
# SELinuxToolTest.test_semodule_load_remove.  checkmodule requires it to match
# the basename of the file it compiles.
TEST_MODULE_NAME = 'oeqa-local'

# Directory on the target used for scratch files and for the output files of
# commands run through newrole.
TEST_MODULE_DIR = '/tmp/oeqa-selinux'

# newrole execs the login shell, so the command has to be given as the shell's
# own arguments: 'newrole ... -- -c <command>', not 'newrole ... -- <command>'.
NEWROLE = 'newrole -r sysadm_r -t sysadm_t -- -c '

# ssh options that keep a loopback login quiet and non-interactive.
SSH_OPTIONS = ('-n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
               '-o LogLevel=ERROR')

# Source of the test module.  It grants the confined domain one access the
# policy withholds, so that loading and removing the module can be observed on
# an existing file instead of needing a reboot or a relabel.  Both the domain
# and the label are taken from the target, so the module follows a relabelled
# image instead of hard-coding a type.
TEST_MODULE_TE = """\
module %(module)s 1.0;

require {
    type %(domain)s;
    type %(type)s;
    class file { getattr open read };
}

allow %(domain)s %(type)s:file { getattr open read };
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


def context_type(context):
    """Return the type component of an SELinux context, or ''."""
    # A login through pam_selinux may print warnings before the context it
    # ends up in, so take the last line that looks like a context rather than
    # the first one.
    for line in reversed(context.replace('\x00', '').splitlines()):
        parts = line.strip().split(':')
        if len(parts) >= 3 and parts[2]:
            return parts[2]
    return ''


class SELinuxTest(OERuntimeTestCase):
    """Helpers shared by the SELinux runtime cases."""

    # Cached results of the probes below; None until a test asks for them.
    # Shared by all the cases, because each probe costs command round trips.
    _admin_domain = None
    _confined_domain = None
    _probe_path = None

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
        return context_type(self.process_context())

    def is_admin_domain(self, domain):
        """Return whether `domain' may administer SELinux."""
        return domain in ADMIN_DOMAINS

    def is_unconfined_domain(self, domain):
        """Return whether the policy leaves `domain' unconfined on purpose."""
        return domain in UNCONFINED_DOMAINS

    #
    # Running commands in an administrative domain.
    #

    def require_admin(self):
        """
        Return the domain administrative commands run in, or skip.

        The session itself may already be administrative; if it is not, the
        commands run through newrole, which needs the root password to be empty
        so that PAM can authenticate without a prompt.
        """
        domain = self.admin_domain()
        if not domain:
            self.skipTest(
                'This test needs an administrative SELinux domain, but the '
                'session runs as %r and newrole cannot assume sysadm_r.  '
                'The command then needs policycoreutils-newrole installed and '
                'a root account PAM authenticates without a prompt, i.e. '
                'IMAGE_FEATURES "empty-root-password"'
                % (self.selinux_domain() or self.process_context()))
        return domain

    def admin_domain(self):
        """Return the domain the administrative commands end up in, or ''."""
        if self.is_admin_domain(self.selinux_domain()):
            return self.selinux_domain()

        cls = type(self)
        if cls._admin_domain is None:
            status, output = self.run_admin('cat /proc/self/attr/current')
            domain = ''
            if status == 0:
                candidate = context_type(output)
                if self.is_admin_domain(candidate):
                    domain = candidate
            cls._admin_domain = domain
            self.logger.info('newrole gives domain %r' % domain)
        return cls._admin_domain

    def _newrole(self, command):
        """
        Build a shell command line running `command' through newrole.

        newrole's child inherits the ssh pipes, but its output is not reliably
        readable from them, and some of the tools used here (auditctl,
        semanage, semodule) print nothing when their stdout is a regular file.
        So the command's output is piped through cat into a file, and the exit
        status of the left-hand side of the pipeline is recorded with
        PIPESTATUS.
        """
        redirect = ('{ %s ; } 2>&1 | cat > %s/out; echo "${PIPESTATUS[0]}" > %s/rc'
                    % (command, TEST_MODULE_DIR, TEST_MODULE_DIR))
        return 'mkdir -p %s; %s%s' % (TEST_MODULE_DIR, NEWROLE,
                                      shlex.quote(redirect))

    def run_admin(self, command, timeout=None):
        """Run `command' in an administrative domain, return (status, output)."""
        if self.is_admin_domain(self.selinux_domain()):
            return self.run_cmd(command, timeout)

        self.run_cmd(self._newrole(command), timeout)
        # The output file may not end in a newline, so emit one before the
        # marker or the marker would be glued onto the last output line.
        status, output = self.run_cmd(
            "cat %s/out 2>/dev/null; echo; echo OEQA-RC; cat %s/rc 2>/dev/null"
            % (TEST_MODULE_DIR, TEST_MODULE_DIR))
        body, _, tail = output.rpartition('\nOEQA-RC\n')
        body = body.replace('\x00', '')
        try:
            rc = int(tail.strip())
        except ValueError:
            # newrole itself did not run, e.g. policycoreutils-newrole is not
            # installed; report no status rather than failing here, so that
            # require_admin() can turn it into a skip.
            self.logger.info('newrole did not run %r; it printed:\n%s'
                             % (command, output))
            return None, ''
        self.logger.debug('newrole: %s\n-> %d\n%s' % (command, rc, body))
        return rc, body

    def run_admin_ok(self, command, timeout=None):
        status, output = self.run_admin(command, timeout=timeout)
        self.assertEqual(status, 0,
                         "Command '%s' failed in the admin domain with status "
                         "%s:\n%s" % (command, status, output))
        return output

    #
    # Running commands in a confined domain.
    #

    def require_confined(self):
        """Return a confined domain to assert a denial in, or skip."""
        domain = self.confined_domain()
        if not domain:
            self.skipTest('This test needs a confined non-administrative '
                          'SELinux domain, but the session runs as %r and no '
                          'confined login could be set up'
                          % (self.selinux_domain()
                             or self.process_context()))
        return domain

    def confined_domain(self):
        """Return the confined domain a denial can be asserted in, or ''."""
        if self.selinux_domain() and not self.is_admin_domain(
                self.selinux_domain()):
            # The session is already a restricted user domain, which is what an
            # ssh login as root gives on the confining policy variants.
            return self.selinux_domain()

        cls = type(self)
        if cls._confined_domain is None:
            cls._confined_domain = self.setup_confined_login()
            self.logger.info('confined login gives domain %r'
                             % cls._confined_domain)
        return cls._confined_domain

    def setup_confined_login(self):
        """
        Log in as a confined user, return its domain or ''.

        Used on the variants that run administrators as unconfined_t, where the
        session has no confined domain to offer.  A login that goes through
        pam_selinux is what relabels the session, and ssh is the only one of
        those available on a minimal image, so the account is reached over
        loopback ssh.
        """
        if not self.admin_domain():
            self.logger.info('no administrative domain, so a confined login '
                             'cannot be set up')
            return ''
        if self.run_cmd('pidof sshd')[0] != 0:
            self.logger.info('sshd is not running, so a confined login cannot '
                             'be made')
            return ''

        if self.run_cmd('id %s' % CONFINED_USER)[0] != 0:
            status, output = self.run_cmd(
                'adduser -D -s /bin/sh %s' % CONFINED_USER)
            if status != 0:
                self.logger.info('cannot create %s:\n%s'
                                 % (CONFINED_USER, output))
                return ''

        # pam_selinux labels the session, but only for an account PAM
        # authenticates without asking.  sshd then accepts the empty password
        # because sshd_config sets PermitEmptyPasswords.
        self.run_cmd('passwd -d %s' % CONFINED_USER)

        if self.run_admin('semanage login -a -s %s %s'
                          % (CONFINED_SELINUX_USER, CONFINED_USER))[0] != 0:
            # -m updates the mapping a previous run left behind.
            self.run_admin('semanage login -m -s %s %s'
                           % (CONFINED_SELINUX_USER, CONFINED_USER))

        status, output = self.run_cmd('%s -l %s 127.0.0.1 -- id -Z'
                                      % (self.ssh(), CONFINED_USER))
        if status != 0:
            self.logger.info('cannot log in as %s:\n%s'
                             % (CONFINED_USER, output))
            return ''
        domain = context_type(output)
        if not domain or self.is_admin_domain(domain):
            # Nothing was gained: the policy left this login unconfined too.
            self.logger.info('%s logs in as %r, which is not confined'
                             % (CONFINED_USER, domain or '?'))
            return ''
        return domain

    def ssh(self):
        """Return the ssh command line used for loopback logins."""
        return 'ssh %s' % SSH_OPTIONS

    def run_confined(self, command, timeout=None):
        """Run `command' in the confined domain, return (status, output)."""
        if self.confined_domain() == self.selinux_domain():
            return self.run_cmd(command, timeout)
        return self.run_cmd('%s -l %s 127.0.0.1 -- %s'
                            % (self.ssh(), CONFINED_USER, shlex.quote(command)),
                            timeout)

    def probe_path(self):
        """
        Return a world-readable file the confined domain may not read, or ''.

        Candidates are tried in turn and the first one that exists, is readable
        by every user and whose label the policy withholds is used.  Anything
        else would make a case assert a policy denial while what it is looking
        at is a permission check that SELinux never sees.
        """
        cls = type(self)
        if cls._probe_path is not None:
            return cls._probe_path

        cls._probe_path = ''
        domain = self.confined_domain()
        if not domain:
            return ''

        for path in PROBE_PATHS:
            # The mode is a property of the file, so read it where the policy
            # raises no obstacle; a confined domain may be denied even the
            # stat, which would say nothing about the file's permissions.
            status, output = self.run_admin('stat -c %%A %s' % path)
            if status != 0:
                continue
            # '-rw-r--r--': index 7 is the read bit for everyone else.
            mode = output.strip()
            if len(mode) < 10 or mode[7] != 'r':
                self.logger.info('%s is not world readable' % path)
                continue
            status, output = self.run_confined('cat %s' % path)
            if status == 0:
                self.logger.info('%r may read %s' % (domain, path))
                continue
            if 'Permission denied' not in output:
                self.logger.info('%r cannot read %s for another reason: %s'
                                 % (domain, path, output.strip()))
                continue
            self.logger.info('%r is denied reading %s' % (domain, path))
            cls._probe_path = path
            break
        return cls._probe_path

    def probe_label(self):
        """Return the type of the probe file's label, or ''."""
        status, output = self.run_admin('stat -c %%C %s' % self.probe_path())
        return context_type(output) if status == 0 else ''

    def probe_read(self):
        """Read the probe file in the confined domain, return (status, output)."""
        return self.run_confined('cat %s' % self.probe_path())

    def require_probe_denial(self):
        """
        Return the confined domain and the probe file's label type, or skip.

        Both are verified rather than assumed: the cases need the policy to
        withhold the file, so that loading a module can be seen lifting that,
        and the module needs the file's actual type.
        """
        domain = self.require_confined()

        path = self.probe_path()
        if not path:
            self.skipTest('None of %s is a world-readable file that the policy '
                          'denies %r, so there is no denial to observe'
                          % (', '.join(PROBE_PATHS), domain))

        type_ = self.probe_label()
        if not type_:
            self.skipTest('Cannot read the SELinux label of %s' % path)

        status, output = self.probe_read()
        self.assertNotEqual(
            status, 0,
            'Reading %s as %s was allowed; the policy no longer denies it:\n%s'
            % (path, domain, output))
        self.assertIn('Permission denied', output,
                      'Reading %s as %s failed for a reason other than an '
                      'SELinux denial:\n%s' % (path, domain, output))
        return domain, type_

    #
    # Miscellaneous helpers.
    #

    def write_file(self, path, content):
        self.run_ok('mkdir -p %s' % os.path.dirname(path))
        self.run_ok("cat > %s << 'OEQA_EOF'\n%sOEQA_EOF" % (path, content))

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
    """A confined root must be denied files that only the policy withholds."""

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('policycoreutils-sestatus')
    @OETestDepends(['selinux.SELinuxStatusTest.test_kernel_enforcing'])
    def test_read_shadow_denied(self):
        # /etc/shadow is 0400 and owned by root, so a session that is uid 0 and
        # still cannot read it was not stopped by the discretionary
        # permissions: it is the policy withholding shadow_t:file.  Both halves
        # of that matter, and neither can be arranged on every variant:
        #
        #   - It has to be the session itself, because a confined login as a
        #     non-root account would be refused by the file mode alone and the
        #     test would then pass without SELinux having decided anything.
        #   - The session has to be confined rather than unconfined, which an
        #     ssh login as root is on refpolicy-standard, -mcs and -mls
        #     (staff_t), but not on refpolicy-targeted and -minimum, where
        #     administrators run as unconfined_t by design and reading the file
        #     is allowed.  Note that being an administrative domain is not the
        #     same test: staff_t is not one and is still confined, while
        #     sysadm_t and secadm_t are ones and are denied shadow_t as well.
        #
        # So this case skips on the variants whose policy has no confined
        # administrator.  The confidential data of a confined *user* is covered
        # by test_avc_recorded, which does not need the session to be root.
        domain = self.selinux_domain()
        if not domain:
            self.skipTest('Cannot determine the SELinux domain of the session')
        if self.is_unconfined_domain(domain):
            self.skipTest('The session runs as unconfined %r: this variant '
                          'gives administrators the access they would have '
                          'with SELinux disabled, so there is no denial to '
                          'assert' % domain)

        status, output = self.run_cmd('id -u')
        self.assertEqual(output.strip(), '0',
                         'The session is not root, so /etc/shadow is denied by '
                         'its file mode rather than by the policy; the denial '
                         'would prove nothing')

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

        status, output = self.run_admin('setenforce 0')
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
            self.run_admin_ok('setenforce 1')

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
        output = self.run_admin_ok('matchpathcon -V /etc/shadow')
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
        output = self.run_admin_ok('semanage login -l')
        self.assertIn('__default__', output,
                      'semanage login -l did not list the default mapping:\n%s'
                      % output)
        self.run_admin_ok('semanage boolean -l')
        self.run_admin_ok('semanage fcontext -l')

        # Add/list/remove round trip.  -N keeps the running policy untouched;
        # the rule is committed to the local store and listed from there.
        fcontext = TEST_MODULE_DIR + '/alt(/.*)?'
        token = TEST_MODULE_DIR + '/alt'
        try:
            self.run_admin_ok("semanage fcontext -N -a -t tmp_t '%s'"
                              % fcontext)
            output = self.run_admin_ok("semanage fcontext -l | grep -F '%s'"
                                       % token)
            self.assertIn(fcontext, output,
                          'Added fcontext rule is missing from the listing:\n%s'
                          % output)
        finally:
            # Ignore failures here so that a failed add does not mask itself
            # with a failed delete.
            self.run_admin("semanage fcontext -N -d '%s'" % fcontext)

        status, output = self.run_admin("semanage fcontext -l | grep -F '%s'"
                                        % token)
        self.assertNotEqual(status, 0,
                            'Removed fcontext rule is still listed:\n%s'
                            % output)

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('policycoreutils-semodule')
    @OEHasPackage('checkpolicy')
    @OEHasPackage('semodule-utils-semodule-package')
    @OETestDepends(['selinux.SELinuxStatusTest.test_kernel_enforcing'])
    def test_semodule_load_remove(self):
        # The module grants the confined domain a read the policy withholds, so
        # both loading and removing it are observable without a reboot.  Which
        # domain that is depends on the variant, but it only has to be a
        # confined one, never the session's as such.
        domain, type_ = self.require_probe_denial()
        path = self.probe_path()

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
                                              'domain': domain,
                                              'type': type_})
        try:
            self.run_ok(checkmodule)
            self.run_ok('semodule_package -o %s -m %s' % (pp, mod))

            self.run_admin_ok('semodule -i %s' % pp, timeout=300)
            self.assertIn(TEST_MODULE_NAME,
                          self.run_admin_ok('semodule -l', timeout=120),
                          'Installed module is not listed by semodule -l')

            status, output = self.probe_read()
            self.assertEqual(status, 0,
                             'Reading %s is still denied after loading %s for '
                             '%s:\n%s' % (path, TEST_MODULE_NAME, domain, output))
        finally:
            self.run_admin('semodule -r %s' % TEST_MODULE_NAME, timeout=300)

        output = self.run_admin_ok('semodule -l', timeout=120)
        self.assertNotIn(TEST_MODULE_NAME, output,
                         'Removed module is still listed by semodule -l:\n%s'
                         % output)
        status, output = self.probe_read()
        self.assertNotEqual(status, 0,
                            'Reading %s is still allowed after removing %s:\n%s'
                            % (path, TEST_MODULE_NAME, output))


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
            status, output = self.run_admin('systemctl is-active auditd.service')
            self.assertEqual(status, 0,
                             'auditd.service is not active:\n%s' % output)
        else:
            self.run_admin_ok('pidof auditd')

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('auditd')
    @OETestDepends(['selinux.SELinuxAuditTest.test_auditd_running'])
    def test_auditctl_status(self):
        self.require_admin()
        output = self.run_admin_ok('auditctl -s')

        # 'enabled' is the kernel audit state: 0 = off, 1 = on,
        # 2 = on and locked until reboot.
        match = re.search(r'^enabled\s+(\d+)', output, re.MULTILINE)
        self.assertIsNotNone(match,
                             'auditctl -s reported no state:\n%s' % output)
        self.assertIn(match.group(1), ('1', '2'),
                      'Kernel auditing is disabled:\n%s' % output)

    @skipIfNotFeature('selinux', 'Test requires selinux in DISTRO_FEATURES')
    @OEHasPackage('auditd')
    @OETestDepends(['selinux.SELinuxAuditTest.test_auditctl_status'])
    def test_avc_recorded(self):
        # The denial is provoked here rather than borrowed from another case,
        # so that the record is written moments before it is looked for and
        # comes from a confined domain on every variant that has one.
        domain, _ = self.require_probe_denial()
        path = self.probe_path()

        source = self.avc_source()
        before = self.avc_records(domain, source)

        status, output = self.probe_read()
        self.assertNotEqual(status, 0,
                            'Reading %s as %s was allowed, so no AVC record '
                            'can be expected:\n%s' % (path, domain, output))

        # Compare record sets rather than asking for records since a timestamp:
        # the audit ids are unique, so the difference is exactly what this
        # denial added, and a rolling '-ts recent' window cannot hide it.
        record = ''
        deadline = time.time() + 30
        while True:
            # Give auditd a moment to flush the record before looking.
            time.sleep(2)
            fresh = self.avc_records(domain, source) - before
            if fresh:
                record = '\n'.join(sorted(fresh))
                self.logger.info('AVC record found in the %s:\n%s'
                                 % (source, record))
                break
            if time.time() >= deadline:
                break

        self.assertTrue(
            record,
            'No AVC record for the denied read of %s as %s appeared in the '
            '%s after 30s.\nRecords for the domain already present:\n%s'
            % (path, domain, source,
               '\n'.join(sorted(self.avc_records(domain, source))[-10:])))

    def avc_source(self):
        """Return where the kernel's audit records can be read from."""
        # Ask in the admin domain: a confined session is not allowed to see
        # whether auditd runs, and mistaking that for 'auditd is absent' sends
        # the search to the ring buffer, which holds no record while auditd is
        # consuming them.
        if self.run_admin('pidof auditd')[0] == 0:
            return 'audit log'
        return 'kernel ring buffer'

    def audit_log(self):
        """Return the file auditd writes to, as configured."""
        # auditd.conf is only readable in an administrative domain.
        output = self.run_admin_ok(
            "sed -n 's/^[[:space:]]*log_file[[:space:]]*=[[:space:]]*//p' "
            '/etc/audit/auditd.conf')
        return output.strip() or '/var/log/audit/audit.log'

    def avc_records(self, domain, source):
        """Return the audit records the kernel wrote for `domain' as a set."""
        # Narrow the selection on the target, since the audit log holds
        # thousands of records; repeat the filter in Python so that the match
        # does not depend on how grep splits the fields.
        marker = ':%s:' % domain
        basename = os.path.basename(self.probe_path())
        if source == 'audit log':
            # Name the log file: ausearch reads its input from stdin when stdin
            # is /dev/null, which is what an ssh command gets, and then reports
            # "no matches" while the log holds the records.
            command = ('ausearch -if %s -m AVC 2>/dev/null | grep "avc:" '
                       '| grep -F %s | grep -F %s || true'
                       % (shlex.quote(self.audit_log()),
                          shlex.quote(marker), shlex.quote(basename)))
        else:
            command = ('dmesg 2>/dev/null | grep "avc:" | grep -F %s '
                       '| grep -F %s || true'
                       % (shlex.quote(marker), shlex.quote(basename)))
        status, output = self.run_admin(command)

        # Match the source context and the file, so that a record left by an
        # earlier run or written for another process cannot satisfy the check.
        return {line for line in output.splitlines()
                if 'avc:' in line and marker in line and basename in line}

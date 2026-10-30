"""Fixed mount initialization; never run the network application as root.

Docker defaults to UID10001. An operator may explicitly opt into root startup
for a fresh root-owned Railway volume. Only /data's directory inode is repaired;
existing files are never chowned, followed, deleted or recursively modified.
"""
import os
import stat
import sys

DATA = '/data'
DATABASE = '/data/world.sqlite3'
UID = GID = 10001
FILES = frozenset({'world.sqlite3', 'world.sqlite3-wal', 'world.sqlite3-shm'})


REASONS = frozenset({
    'database_config', 'startup_identity', 'directory_open', 'directory_stat',
    'directory_owner_type', 'directory_list', 'unexpected_entry', 'entry_open',
    'entry_stat', 'entry_owner_type_mode', 'entry_close', 'directory_chown',
    'directory_requires_init', 'directory_chmod', 'directory_verify',
    'directory_close', 'drop_groups', 'drop_gid', 'drop_uid', 'identity_verify',
    'runtime_prepare', 'application_exec', 'internal_error',
})


class StartupRefusal(RuntimeError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else 'internal_error'
        super().__init__(self.reason)


def checked(reason, operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except Exception:
        raise StartupRefusal(reason) from None


def prepare_data():
    if os.environ.get('GPTOPIA_DB', DATABASE) != DATABASE:
        raise StartupRefusal('database_config')
    if os.geteuid() not in (0, UID):
        raise StartupRefusal('startup_identity')
    fd = checked('directory_open', os.open, DATA, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory = checked('directory_stat', os.fstat, fd)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid not in (0, UID):
            raise StartupRefusal('directory_owner_type')
        # Inspect every preexisting entry before changing directory ownership.
        # Refuse migration/repair of foreign-owned databases; that needs a
        # separately reviewed maintenance action, not a broad startup chown.
        for entry in checked('directory_list', os.listdir, fd):
            if entry not in FILES:
                raise StartupRefusal('unexpected_entry')
            item = checked('entry_open', os.open, entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = checked('entry_stat', os.fstat, item)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or (info.st_uid, info.st_gid) != (UID, GID)
                        or info.st_mode & 0o022):
                    raise StartupRefusal('entry_owner_type_mode')
            finally:
                checked('entry_close', os.close, item)
        if os.geteuid() == 0:
            checked('directory_chown', os.fchown, fd, UID, GID)
        elif (directory.st_uid, directory.st_gid) != (UID, GID):
            raise StartupRefusal('directory_requires_init')
        checked('directory_chmod', os.fchmod, fd, 0o700)
        final = checked('directory_verify', os.fstat, fd)
        if (final.st_uid, final.st_gid) != (UID, GID) or stat.S_IMODE(final.st_mode) != 0o700:
            raise StartupRefusal('directory_verify')
    finally:
        checked('directory_close', os.close, fd)


def drop_privileges():
    if os.geteuid() == 0:
        checked('drop_groups', os.setgroups, [])
        checked('drop_gid', os.setresgid, GID, GID, GID)
        checked('drop_uid', os.setresuid, UID, UID, UID)
    uids = checked('identity_verify', os.getresuid)
    gids = checked('identity_verify', os.getresgid)
    groups = checked('identity_verify', os.getgroups)
    if uids != (UID, UID, UID) or gids != (GID, GID, GID) or not set(groups) <= {GID}:
        raise StartupRefusal('identity_verify')
    return uids[0], gids[0]


def main():
    stage = 'internal_error'
    try:
        prepare_data()
        uid, gid = drop_privileges()
        stage = 'runtime_prepare'
        os.umask(0o077)
        os.chdir('/app')
        os.environ['GPTOPIA_DB'] = DATABASE
        os.environ['HOME'] = '/home/app'
        os.environ['PATH'] = '/usr/local/bin:/usr/bin:/bin'
        # This proves checked real/effective/saved IDs, not HTTP readiness.
        print(f'GPTopia startup identity_verified uid={uid} gid={gid} saved_ids_verified=true startup_boundary_ready=true application_ready=false', file=sys.stderr, flush=True)
        stage = 'application_exec'
        os.execv('/usr/local/bin/node', ['node', 'mcp_adapter/server.mjs'])
    except Exception as exc:
        reason = exc.reason if isinstance(exc, StartupRefusal) else stage
        if reason not in REASONS:
            reason = 'internal_error'
        # Never include exception messages, environment, paths or entry names.
        print(f'GPTopia startup refused reason={reason}', file=sys.stderr, flush=True)
        return 1
    return 1


if __name__ == '__main__':
    sys.exit(main())

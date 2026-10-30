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


def prepare_data():
    if os.environ.get('GPTOPIA_DB', DATABASE) != DATABASE:
        raise RuntimeError('database must use the fixed data location')
    if os.geteuid() not in (0, UID):
        raise RuntimeError('unexpected startup identity')
    fd = os.open(DATA, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory = os.fstat(fd)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid not in (0, UID):
            raise RuntimeError('unexpected data directory owner or type')
        # Inspect every preexisting entry before changing directory ownership.
        # Refuse migration/repair of foreign-owned databases; that needs a
        # separately reviewed maintenance action, not a broad startup chown.
        for entry in os.listdir(fd):
            if entry not in FILES:
                raise RuntimeError('unexpected data directory entry')
            item = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(item)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or (info.st_uid, info.st_gid) != (UID, GID)
                        or info.st_mode & 0o022):
                    raise RuntimeError('unsafe preexisting database ownership or type')
            finally:
                os.close(item)
        if os.geteuid() == 0:
            os.fchown(fd, UID, GID)
        elif (directory.st_uid, directory.st_gid) != (UID, GID):
            raise RuntimeError('data directory requires explicit initialization')
        os.fchmod(fd, 0o700)
        final = os.fstat(fd)
        if (final.st_uid, final.st_gid) != (UID, GID) or stat.S_IMODE(final.st_mode) != 0o700:
            raise RuntimeError('data directory initialization failed')
    finally:
        os.close(fd)


def drop_privileges():
    if os.geteuid() == 0:
        os.setgroups([])
        os.setresgid(GID, GID, GID)
        os.setresuid(UID, UID, UID)
    if (os.getresuid() != (UID, UID, UID) or os.getresgid() != (GID, GID, GID)
            or not set(os.getgroups()) <= {GID}):
        raise RuntimeError('privilege drop did not complete')


def main():
    try:
        prepare_data()
        drop_privileges()
        os.umask(0o077)
        os.chdir('/app')
        os.environ['GPTOPIA_DB'] = DATABASE
        os.environ['HOME'] = '/home/app'
        os.environ['PATH'] = '/usr/local/bin:/usr/bin:/bin'
        os.execv('/usr/local/bin/node', ['node', 'mcp_adapter/server.mjs'])
    except Exception:
        # Do not print environment, credentials, filenames or exception details.
        print('GPTopia startup refused: data or privilege boundary invalid', file=sys.stderr)
        return 1
    return 1


if __name__ == '__main__':
    sys.exit(main())

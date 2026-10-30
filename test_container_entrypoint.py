"""Synthetic syscall tests + real filesystem checks; NOT root execution evidence."""
import os
import stat
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import container_entrypoint as entry


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = Path(self.temp.name) / 'data'
        self.data.mkdir()
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(entry, 'DATA', str(self.data)))
        self.stack.enter_context(patch.object(entry, 'UID', os.getuid()))
        self.stack.enter_context(patch.object(entry, 'GID', os.getgid()))
        self.stack.enter_context(patch.dict(os.environ, {'GPTOPIA_DB': entry.DATABASE}))
    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()
    def test_normal_nonroot_directory(self):
        (self.data/'world.sqlite3').write_text('synthetic')
        entry.prepare_data()
        self.assertEqual(stat.S_IMODE(self.data.stat().st_mode),0o700)
    def test_data_symlink_refused(self):
        self.data.rmdir();self.data.symlink_to(self.temp.name)
        with self.assertRaises(OSError): entry.prepare_data()
    def test_database_symlink_refused_without_mutation(self):
        outside=Path(self.temp.name)/'outside';outside.write_text('unchanged')
        (self.data/'world.sqlite3').symlink_to(outside)
        with self.assertRaises(OSError):entry.prepare_data()
        self.assertEqual(outside.read_text(),'unchanged')
        self.assertEqual(stat.S_IMODE(self.data.stat().st_mode),0o755)
    def test_hardlink_unknown_entry_and_directory_refused(self):
        outside=Path(self.temp.name)/'outside';outside.write_text('unchanged')
        os.link(outside,self.data/'world.sqlite3')
        with self.assertRaises(RuntimeError):entry.prepare_data()
        (self.data/'world.sqlite3').unlink()
        (self.data/'unexpected').write_text('unchanged')
        with self.assertRaises(RuntimeError):entry.prepare_data()
        (self.data/'unexpected').unlink();(self.data/'world.sqlite3').mkdir()
        with self.assertRaises(RuntimeError):entry.prepare_data()
    def test_outside_database_config_refused(self):
        with patch.dict(os.environ,{'GPTOPIA_DB':'/tmp/outside.sqlite3'}):
            with self.assertRaises(RuntimeError):entry.prepare_data()
    def test_group_writable_database_refused(self):
        db=self.data/'world.sqlite3';db.write_text('synthetic');db.chmod(0o666)
        with self.assertRaises(RuntimeError):entry.prepare_data()


class PrivilegedSyscallTests(unittest.TestCase):
    def test_fresh_root_owned_mount_only_directory_chowned(self):
        initial=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0,st_gid=0)
        final=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=10001,st_gid=10001)
        with patch.dict(os.environ,{'GPTOPIA_DB':entry.DATABASE}), patch.object(entry.os,'geteuid',return_value=0), \
             patch.object(entry.os,'open',return_value=42) as opened, patch.object(entry.os,'fstat',side_effect=[initial,final]), \
             patch.object(entry.os,'listdir',return_value=[]),patch.object(entry.os,'fchown') as chown, \
             patch.object(entry.os,'fchmod') as chmod,patch.object(entry.os,'close') as close:
            entry.prepare_data()
            opened.assert_called_once_with('/data',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            chown.assert_called_once_with(42,10001,10001);chmod.assert_called_once_with(42,0o700);close.assert_called_once_with(42)
    def test_existing_root_owned_database_refused_before_chown(self):
        directory=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0,st_gid=0)
        db=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_gid=0,st_nlink=1)
        with patch.object(entry.os,'geteuid',return_value=0), patch.object(entry.os,'open',side_effect=[42,43]), \
             patch.object(entry.os,'fstat',side_effect=[directory,db]),patch.object(entry.os,'listdir',return_value=['world.sqlite3']), \
             patch.object(entry.os,'fchown') as chown,patch.object(entry.os,'close'):
            with self.assertRaises(RuntimeError):entry.prepare_data()
            chown.assert_not_called()
    def test_permanent_drop_order_and_verified_saved_ids(self):
        with patch.object(entry.os,'geteuid',return_value=0),patch.object(entry.os,'setgroups') as groups, \
             patch.object(entry.os,'setresgid') as gid,patch.object(entry.os,'setresuid') as uid, \
             patch.object(entry.os,'getresuid',return_value=(10001,)*3),patch.object(entry.os,'getresgid',return_value=(10001,)*3), \
             patch.object(entry.os,'getgroups',return_value=[]):
            calls=[]
            groups.side_effect=lambda x:calls.append(('groups',x))
            gid.side_effect=lambda *x:calls.append(('gid',x))
            uid.side_effect=lambda *x:calls.append(('uid',x))
            entry.drop_privileges()
            self.assertEqual(calls,[('groups',[]),('gid',(10001,)*3),('uid',(10001,)*3)])
    def test_retained_root_saved_id_refused(self):
        with patch.object(entry.os,'geteuid',return_value=10001),patch.object(entry.os,'getresuid',return_value=(10001,10001,0)):
            with self.assertRaises(RuntimeError):entry.drop_privileges()
    def test_normal_nonroot_identity_needs_no_privileged_calls(self):
        with patch.object(entry.os,'geteuid',return_value=10001),patch.object(entry.os,'getresuid',return_value=(10001,)*3), \
             patch.object(entry.os,'getresgid',return_value=(10001,)*3),patch.object(entry.os,'getgroups',return_value=[10001]), \
             patch.object(entry.os,'setgroups') as groups:
            entry.drop_privileges();groups.assert_not_called()
    def test_drop_error_never_executes_application(self):
        with patch.object(entry,'prepare_data'),patch.object(entry,'drop_privileges',side_effect=PermissionError()),patch.object(entry.os,'execv') as execute:
            self.assertEqual(entry.main(),1);execute.assert_not_called()
    def test_exec_is_fixed_and_only_after_drop(self):
        events=[]
        with patch.object(entry,'prepare_data',side_effect=lambda:events.append('prepare')), \
             patch.object(entry,'drop_privileges',side_effect=lambda:events.append('drop')),patch.object(entry.os,'chdir'),patch.object(entry.os,'umask'), \
             patch.dict(os.environ,{}),patch.object(entry.os,'execv',side_effect=lambda *x:events.append(('exec',x))):
            entry.main()
            self.assertEqual(events,['prepare','drop',('exec',('/usr/local/bin/node',['node','mcp_adapter/server.mjs']))])

if __name__=='__main__':unittest.main()

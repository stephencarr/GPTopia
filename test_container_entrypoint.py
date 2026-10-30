"""Synthetic syscall tests + real filesystem checks; NOT root execution evidence."""
import os
import io
from contextlib import redirect_stderr
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
        with self.assertRaises(entry.StartupRefusal): entry.prepare_data()
    def test_database_symlink_refused_without_mutation(self):
        outside=Path(self.temp.name)/'outside';outside.write_text('unchanged')
        (self.data/'world.sqlite3').symlink_to(outside)
        with self.assertRaises(entry.StartupRefusal):entry.prepare_data()
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
             patch.object(entry,'drop_privileges',side_effect=lambda:(events.append('drop') or (10001,10001))),patch.object(entry.os,'chdir'),patch.object(entry.os,'umask'), \
             patch.dict(os.environ,{}),patch.object(entry.os,'execv',side_effect=lambda *x:events.append(('exec',x))):
            entry.main()
            self.assertEqual(events,['prepare','drop',('exec',('/usr/local/bin/node',['node','mcp_adapter/server.mjs']))])

class FilesystemMetadataTests(unittest.TestCase):
    def test_valid_root_only_directory_is_inspected_not_modified(self):
        info=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0)
        with patch.object(entry.os,'open',return_value=43) as opened,patch.object(entry.os,'fstat',return_value=info), \
             patch.object(entry.os,'close') as close,patch.object(entry.os,'listdir') as listed, \
             patch.object(entry.os,'fchown') as chown,patch.object(entry.os,'fchmod') as chmod:
            entry.validate_filesystem_metadata(42)
            opened.assert_called_once_with('lost+found',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=42)
            close.assert_called_once_with(43);listed.assert_not_called();chown.assert_not_called();chmod.assert_not_called()
    def test_wrong_owner_group_mode_or_type_refused(self):
        cases=[(stat.S_IFDIR|0o700,10001,0),(stat.S_IFDIR|0o700,0,10001),
               (stat.S_IFDIR|0o755,0,0),(stat.S_IFDIR|0o770,0,0),
               (stat.S_IFDIR|0o4700,0,0),(stat.S_IFREG|0o700,0,0)]
        for mode,uid,gid in cases:
            with self.subTest(mode=mode,uid=uid,gid=gid),patch.object(entry.os,'open',return_value=43), \
                 patch.object(entry.os,'fstat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid,st_gid=gid)),patch.object(entry.os,'close'):
                with self.assertRaises(entry.StartupRefusal) as error:entry.validate_filesystem_metadata(42)
                self.assertEqual(error.exception.reason,'filesystem_metadata_unsafe')
    def test_real_symlink_and_file_refused_without_following(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            try:
                metadata=Path(tmp)/'lost+found';metadata.symlink_to('/')
                with self.assertRaises(entry.StartupRefusal) as error:entry.validate_filesystem_metadata(parent)
                self.assertEqual(error.exception.reason,'filesystem_metadata_unsafe')
                metadata.unlink();metadata.write_text('unchanged')
                with self.assertRaises(entry.StartupRefusal):entry.validate_filesystem_metadata(parent)
                self.assertEqual(metadata.read_text(),'unchanged')
            finally:os.close(parent)
    def test_only_exact_metadata_name_is_special_cased(self):
        initial=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0,st_gid=0)
        final=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=10001,st_gid=10001)
        for names in [['lost+found'],['LOST+FOUND'],['lost+found','other']]:
            with self.subTest(names=names),patch.dict(os.environ,{'GPTOPIA_DB':entry.DATABASE}), \
                 patch.object(entry.os,'geteuid',return_value=0),patch.object(entry.os,'open',return_value=42), \
                 patch.object(entry.os,'fstat',side_effect=[initial,final]),patch.object(entry.os,'listdir',return_value=names), \
                 patch.object(entry.os,'fchown') as chown,patch.object(entry.os,'fchmod'),patch.object(entry.os,'close'), \
                 patch.object(entry,'validate_filesystem_metadata') as metadata:
                if names==['lost+found']:
                    entry.prepare_data();metadata.assert_called_once_with(42);chown.assert_called_once_with(42,10001,10001)
                else:
                    with self.assertRaises(entry.StartupRefusal) as error:entry.prepare_data()
                    self.assertEqual(error.exception.reason,'unexpected_entry');chown.assert_not_called()

class DiagnosticTests(unittest.TestCase):
    def test_each_reason_is_bounded_and_never_logs_exception_details(self):
        for reason in entry.REASONS:
            with self.subTest(reason=reason), patch.object(entry,'prepare_data',side_effect=entry.StartupRefusal(reason)), \
                 patch.object(entry.os,'execv') as execute, redirect_stderr(io.StringIO()) as log:
                self.assertEqual(entry.main(),1)
                self.assertEqual(log.getvalue(),f'GPTopia startup refused reason={reason}\n')
                execute.assert_not_called()
    def test_unexpected_exception_never_leaks_sensitive_message(self):
        with patch.object(entry,'prepare_data',side_effect=PermissionError('SECRET /private/file token=secret')), \
             redirect_stderr(io.StringIO()) as log:
            self.assertEqual(entry.main(),1)
            self.assertEqual(log.getvalue(),'GPTopia startup refused reason=internal_error\n')
    def test_injected_reason_is_not_printable(self):
        self.assertEqual(entry.StartupRefusal('SECRET\n/path').reason,'internal_error')
    def test_failed_drop_has_specific_code_and_no_readiness_marker(self):
        for function,reason in [('setgroups','drop_groups'),('setresgid','drop_gid'),('setresuid','drop_uid')]:
            with self.subTest(function=function), patch.object(entry,'prepare_data'), \
                 patch.object(entry.os,'geteuid',return_value=0),patch.object(entry.os,'setgroups'), \
                 patch.object(entry.os,'setresgid'),patch.object(entry.os,'setresuid'), \
                 patch.object(entry.os,function,side_effect=PermissionError('SECRET')), \
                 patch.object(entry.os,'execv') as execute,redirect_stderr(io.StringIO()) as log:
                self.assertEqual(entry.main(),1)
                self.assertEqual(log.getvalue(),f'GPTopia startup refused reason={reason}\n')
                execute.assert_not_called()
    def test_marker_only_after_verified_ids_and_before_exec(self):
        with patch.object(entry,'prepare_data'),patch.object(entry.os,'geteuid',return_value=10001), \
             patch.object(entry.os,'getresuid',return_value=(10001,)*3),patch.object(entry.os,'getresgid',return_value=(10001,)*3), \
             patch.object(entry.os,'getgroups',return_value=[10001]),patch.object(entry.os,'chdir'),patch.object(entry.os,'umask'), \
             patch.dict(os.environ,{}),redirect_stderr(io.StringIO()) as log:
            def execute(*args):
                self.assertEqual(log.getvalue(),'GPTopia startup identity_verified uid=10001 gid=10001 saved_ids_verified=true startup_boundary_ready=true application_ready=false\n')
                raise OSError('SECRET exec error')
            with patch.object(entry.os,'execv',side_effect=execute):
                self.assertEqual(entry.main(),1)
            self.assertTrue(log.getvalue().endswith('GPTopia startup refused reason=application_exec\n'))
            self.assertNotIn('SECRET',log.getvalue())
    def test_saved_root_identity_does_not_emit_marker(self):
        with patch.object(entry,'prepare_data'),patch.object(entry.os,'geteuid',return_value=10001), \
             patch.object(entry.os,'getresuid',return_value=(10001,10001,0)),patch.object(entry.os,'getresgid',return_value=(10001,)*3), \
             patch.object(entry.os,'getgroups',return_value=[]),patch.object(entry.os,'execv') as execute,redirect_stderr(io.StringIO()) as log:
            self.assertEqual(entry.main(),1)
            self.assertEqual(log.getvalue(),'GPTopia startup refused reason=identity_verify\n');execute.assert_not_called()

if __name__=='__main__':unittest.main()

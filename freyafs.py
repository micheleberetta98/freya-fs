import sys
import os
import errno
import stat
import shutil

from fuse import FuseOSError, Operations
from encfilesmanager import EncFilesManager
from encfilesinfo import EncFilesInfo


def is_encrypted_metadata(path=''):
    return path.endswith('.private') or path.endswith('.public')


def join_paths(root, partial):
    return os.path.join(root, partial.lstrip('/'))


def strip_dot_enc(path=''):
    if path.endswith('.enc'):
        return '.'.join(path.split('.')[:-1])

    return path


class FreyaFS(Operations):
    def __init__(self, root, metadata_root=None):
        self.root = root
        self.metadata_root = metadata_root if metadata_root is not None else root

        # File .enc aperti
        self.enc_files = EncFilesManager()
        self.enc_info = {}

    # --------------------------------------------------------------------- Helpers

    def _full_path(self, path):
        return join_paths(self.root, path)

    def _metadata_full_path(self, path):
        return join_paths(self.metadata_root, path)

    def _metadata_names(self, path):
        filename = strip_dot_enc(path)

        public = self._metadata_full_path(f'{filename}.public')
        private = self._metadata_full_path(f'{filename}.private')
        finfo = self._metadata_full_path(f'{filename}.finfo')

        return public, private, finfo

    def _update_enc_file_size(self, full_path):
        self.enc_info[full_path].size = self.enc_files.cur_size(full_path)

    def _is_file(self, path):
        if not os.path.exists(self._full_path(path)):
            return False

        attr = self.getattr(path)
        return attr['st_mode'] & stat.S_IFREG == stat.S_IFREG

    # --------------------------------------------------------------------- Filesystem methods

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    # Attributi di path (file o cartella)
    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)

        if path == '/':
            return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                            'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

        try:
            if full_path not in self.enc_info:
                public_metadata, _, finfo = self._metadata_names(path)
                self.enc_info[full_path] = EncFilesInfo(
                    full_path, public_metadata, finfo)

            return {
                'st_mode': stat.S_IFREG | (st.st_mode & ~stat.S_IFDIR),
                'st_nlink': 1,
                'st_atime': st.st_atime,
                'st_ctime': st.st_ctime,
                'st_gid': st.st_gid,
                'st_mtime': st.st_mtime,
                'st_size': self.enc_info[full_path].size,
                'st_uid': st.st_uid
            }
        except:
            return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                            'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        dirents = ['.', '..']

        if os.path.isdir(full_path):
            real_stuff = os.listdir(full_path)
            virtual_stuff = [
                x for x in real_stuff if not is_encrypted_metadata(x)]
            dirents.extend(virtual_stuff)

        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        os.rmdir(self._full_path(path))
        os.rmdir(self._metadata_full_path(path))

    def mkdir(self, path, mode):
        os.mkdir(self._full_path(path), mode)
        os.mkdir(self._metadata_full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
                                                         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
                                                         'f_frsize', 'f_namemax'))

    def unlink(self, path):
        full_path = self._full_path(path)
        public_metadata, private_metadata, finfo = self._metadata_names(path)

        os.unlink(public_metadata)
        os.unlink(private_metadata)
        if os.path.isfile(finfo):
            os.unlink(finfo)

        if full_path in self.enc_info:
            del self.enc_info[full_path]

        shutil.rmtree(full_path)
        return

    def symlink(self, name, target):
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        full_old_path = self._full_path(old)
        full_new_path = self._full_path(new)

        if self._is_file(old):
            # Rinomino un file
            if self._is_file(new):
                self.unlink(new)

            old_public_metadata, old_private_metadata, old_finfo = self._metadata_names(old)
            new_public_metadata, new_private_metadata, new_finfo = self._metadata_names(new)

            os.rename(old_public_metadata, new_public_metadata)
            os.rename(old_private_metadata, new_private_metadata)
            if os.path.isfile(old_finfo):
                os.rename(old_finfo, new_finfo)

            os.rename(full_old_path, full_new_path)
            
            if full_old_path in self.enc_info:
                self.enc_info[full_old_path].rename(full_new_path, new_public_metadata, new_finfo)
        else:
            # Rinomino una cartella
            old_metadata_path = self._metadata_full_path(old)
            new_metadata_path = self._metadata_full_path(new)            
            os.rename(old_metadata_path, new_metadata_path)
            os.rename(full_old_path, full_new_path)

    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        os.utime(self._full_path(path), times)

        public_metadata, private_metadata, finfo_metadata = self._metadata_names(path)
        os.utime(public_metadata, times)
        os.utime(private_metadata, times)
        os.utime(finfo_metadata, times)

    # --------------------------------------------------------------------- File methods

    def open(self, path, flags):
        full_path = self._full_path(path)

        public_metadata, private_metadata, _ = self._metadata_names(path)
        attr = self.getattr(path)
        self.enc_files.open(full_path, public_metadata, private_metadata, attr['st_mtime'])
        return 0

    def create(self, path, mode, fi=None):
        filename = path.split('/')[-1]

        # I file nascosti sono gestiti principalmente da interfaccia grafica
        # Alla loro creazione, vengono gestiti dal sistema
        # Tramite "touch", però, non viene permessa la loro creazione
        if filename.startswith('.'):
            return os.open(path, os.O_WRONLY | os.O_CREAT, mode)

        full_path = self._full_path(path)
        public_metadata, private_metadata, _ = self._metadata_names(path)
        self.enc_files.create(full_path, public_metadata, private_metadata)
        return 0

    def read(self, path, length, offset, fh):
        full_path = self._full_path(path)
        if full_path in self.enc_files:
            return self.enc_files.read_bytes(full_path, offset, length)

        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        full_path = self._full_path(path)
        if full_path in self.enc_files:
            bytes_written = self.enc_files.write_bytes(full_path, buf, offset)
            self._update_enc_file_size(full_path)
            return bytes_written

        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        if full_path in self.enc_files:
            self.enc_files.truncate_bytes(full_path, length)
            self._update_enc_file_size(full_path)
            return

        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        full_path = self._full_path(path)
        if full_path in self.enc_files:
            self.enc_files.flush(full_path)
            return 0

        return os.fsync(fh)

    def release(self, path, fh):
        full_path = self._full_path(path)
        if full_path in self.enc_files:
            self.enc_files.release(full_path)
            return 0

        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)

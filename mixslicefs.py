import sys
import os
import errno
import stat

from fuse import FUSE, FuseOSError, Operations
from aesmix import MixSlice


def is_encrypted_data(path=''):
    return path.endswith('.enc')


def is_encrypted_metadata(path=''):
    return path.endswith('.private') or path.endswith('.public')


class MixSliceFS(Operations):
    def __init__(self, root):
        self.root = root

    # Helpers

    def _full_path(self, partial):
        partial = partial.lstrip("/")
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods

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

        if is_encrypted_data(full_path):
            st = os.lstat(full_path)
            return {
                'st_mode': stat.S_IFREG | 0o666,
                'st_nlink': 1,
                'st_atime': st.st_atime,
                'st_ctime': st.st_ctime,
                'st_gid': st.st_gid,
                'st_mtime': st.st_mtime,
                'st_size': st.st_size,
                'st_uid': st.st_uid
            }

        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                        'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    # Elenco di file/cartelle in path
    def readdir(self, path, fh):
        full_path = self._full_path(path)
        dirents = ['.', '..']

        if os.path.isdir(full_path):
            real_stuff = os.listdir(full_path)
            virtual_stuff = [
                x
                for x in real_stuff
                if is_encrypted_data(x) or not is_encrypted_metadata(x)
            ]
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

    # Equivale a touch
    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
                                                         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
                                                         'f_frsize', 'f_namemax'))

    # Equivale a rm
    def unlink(self, path):
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods

    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    # Reading a file
    def read(self, path, length, offset, fh):
        if is_encrypted_data(path):
            full_path = self._full_path(path)
            filename = '.'.join(path.split('.')[0:-1])
            public_key = self._full_path(f'{filename}.public')

            reader = MixSlice.load_from_file(full_path, public_key)
            plaintext = reader.decrypt()
            return plaintext[offset:offset + length]

        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    # Writing a file
    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


if __name__ == '__main__':
    root = sys.argv[1]
    mountpoint = sys.argv[2]

    FUSE(MixSliceFS(root), mountpoint, nothreads=True, foreground=True)

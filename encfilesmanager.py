from aesmix import MixSlice


class EncFilesManager():
    def __init__(self, key=None, iv=None):
        self.key = key if key is not None else b'K' * 16
        self.iv = iv if iv is not None else b'I' * 16

        self.open_files = {}
        self.touched_files = {}
        self.public_metafiles = {}
        self.private_metafiles = {}

    def __contains__(self, path):
        return path in self.open_files

    # ------------------------------------------------------ Helpers

    def _decrypt(self, path):
        public_metafiles = self.public_metafiles[path]
        reader = MixSlice.load_from_file(path, public_metafiles)
        return reader.decrypt()

    def _encrypt(self, path):
        plaintext = self.open_files[path]
        public_metafile = self.public_metafiles[path]
        private_metafile = self.private_metafiles[path]

        owner = MixSlice.encrypt(plaintext, self.key, self.iv)
        owner.save_to_files(path, public_metafile, public_metafile)

    # ------------------------------------------------------ Methods

    def open(self, path, public_metafile_path, private_metafile_path):
        print(f'Opening {path}')
        if path in self.open_files:
            print('(i) Already opened')
            return

        self.public_metafiles[path] = public_metafile_path
        self.private_metafiles[path] = private_metafile_path

        self.open_files[path] = self._decrypt(path)
        self.touched_files[path] = False

    def read_bytes(self, path, offset, length):
        print(f'Reading {path}')
        if path not in self.open_files:
            return None

        plaintext = self.open_files[path]
        return plaintext[offset:offset + length]

    def write_bytes(self, path, buf, offset):
        print(f'Writing {path}')
        if path not in self.open_files:
            return 0

        bytes_written = len(buf)

        plaintext = self.open_files[path]
        new_text = plaintext[:offset] + buf + \
            plaintext[offset+bytes_written:]

        self.open_files[path] = new_text
        self.touched_files[path] = True

        return bytes_written

    def truncate_bytes(self, path, length):
        print(f'Truncating {path}')
        if path not in self.open_files:
            return

        plaintext = self.open_files[path]
        self.open_files[path] = plaintext[:length]
        self.touched_files[path] = True

    def flush(self, path):
        print(f'Flushing {path}')
        if path not in self.open_files:
            return

        if self.touched_files[path]:
            self.touched_files[path] = False
            self._encrypt(path)

    def release(self, path):
        print(f'Releasing {path}')
        print()
        if path not in self.open_files:
            return

        del self.open_files[path]
        del self.touched_files[path]
        del self.public_metafiles[path]
        del self.private_metafiles[path]

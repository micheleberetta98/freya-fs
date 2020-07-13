import json
import os
from aesmix import MixSlice


def size_decrypt(path, public_metadata):
    reader = MixSlice.load_from_file(path, public_metadata)
    return len(reader.decrypt())


class EncFilesInfo():
    def __init__(self, path, public_metadata, file_finfo):
        self._path = path
        self._public_metadata = public_metadata
        self._file_finfo = file_finfo
        
        self._size = size_decrypt(path, public_metadata)
        self._update_finfo()

    # ------------------------------------------------------ Helpers

    def _update_finfo(self):
        finfo = {}
        if os.path.isfile(self._file_finfo):
            with open(self._file_finfo) as f:
                finfo = json.load(f)
        
        finfo['size'] = self._size

        with open(self._file_finfo, 'w') as f:
            json.dump(finfo, f)

    # ------------------------------------------------------ Methods

    def rename(self, path, public_metadata, file_finfo):
        self._path = path
        self._public_metadata = public_metadata
        self._file_finfo = file_finfo

        self._size = None

    # ------------------------------------------------------ Size

    @property
    def size(self):
        if self._size is None:
            self._size = size_decrypt(self._path, self._public_metadata)
            self._update_finfo()
        return self._size

    @size.setter
    def size(self, value):
        if self._size == value:
            return
        self._size = value
        self._update_finfo()

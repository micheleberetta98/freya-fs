import threading

class FileByteContent:
    def __init__(self, text):
        self._text = text
        self._lock = threading.Lock()

    def __len__(self):
        with self._lock:
            length = len(self._text)
        return length

    def read_all(self):
        with self._lock:
            return self._text

    def read_bytes(self, offset, length):
        with self._lock:
            text = self._text[offset:offset + length]
        return text

    def write_bytes(self, buf, offset):
        bytes_written = len(buf)
        with self._lock:
            new_text = self._text[:offset] + buf + self._text[offset+bytes_written:]
            self._text = new_text

        return bytes_written

    def truncate(self, length):
        with self._lock:
            self._text = self._text[:length]

import threading

class FileByteContent:
    def __init__(self, text):
        self._text = text
        self._cond = threading.Condition(threading.Lock())
        self._readers = 0

    def _r_acquire(self):
        self._cond.acquire()
        try:
            self._readers += 1
        finally:
            self._cond.release()

    def _r_release(self):
        self._cond.acquire()
        try:
            self._readers -= 1
            if self._readers == 0:
                self._cond.notifyAll()
        finally:
            self._cond.release()

    def _w_acquire(self):
        self._cond.acquire()
        while self._readers > 0:
            self._cond.wait()

    def _w_release(self):
        self._cond.release()

    def __len__(self):
        self._r_acquire()
        length = len(self._text)
        self._r_release()
        return length

    def read_all(self):
        self._r_acquire()
        text = self._text
        self._r_release()
        return text

    def read_bytes(self, offset, length):
        self._r_acquire()
        text = self._text[offset:offset + length]
        self._r_release()
        return text

    def write_bytes(self, buf, offset):
        self._w_acquire()
        bytes_written = len(buf)
        new_text = self._text[:offset] + buf + self._text[offset+bytes_written:]
        self._text = new_text
        self._w_release()
        return bytes_written

    def truncate(self, length):
        self._w_acquire()
        self._text = self._text[:length]
        self._w_release()

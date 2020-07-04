# FreyaFS - a virtual filesystem with Mix&Slice support

This is my bachelor degree final thesis.

### Requirements

#### System requirements

You will need `openssl/crypto`. On Ubuntu you can do:
```
sudo apt install libssl-dev
```

#### Python requirements

You will need `aesmix` and `fusepy` python library:
```
pip install aesmix
pip install fusepy
```

If you want to compile, install `pyinstaller` too with `pip` and launch `pyinstaller main.py --noconsole --onefile`.

### Usage

You'll find the executable under `dist` if you compile.
Just run it with the flag `-h` or `--help` to get all the info you need.
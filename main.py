from argparse import ArgumentParser
from fuse import FUSE, FuseOSError, Operations

from freyafs import FreyaFS

parser = ArgumentParser(
    description="Freya File System - a virtual file system that supports Mix&Slice encryption")

parser.add_argument('mountpoint',
                    metavar='MOUNT',
                    help='The mount point of this file system.'
                    )
parser.add_argument('-d', '--data',
                    help='The folder in which you have your encrypted files.',
                    required=True
                    )
parser.add_argument('-m', '--metadata',
                    help='''The folder in which you have your .private and .public metadata files.
                    The metadata files in this folder must have the same name and path as the corresponding ecnrypted file.                    
                    If not specified, the --data folder will be used.''',
                    default=None
                    )
parser.add_argument('-t', '--multithread',
                    help='Run in multi-threaded mode (default FALSE)',
                    action='store_true',
                    default=False
                    )

args = parser.parse_args()

if __name__ == '__main__':
    data = args.data
    metadata = args.metadata
    mountpoint = args.mountpoint

    FUSE(FreyaFS(data, metadata), mountpoint,
         nothreads=not args.multithread, foreground=True)

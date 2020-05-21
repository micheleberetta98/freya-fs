from argparse import ArgumentParser
from fuse import FUSE, FuseOSError, Operations

from mixslicefs import MixSliceFS

parser = ArgumentParser(
    description="Mix & Slice File System - a virtual file system that supports Mix & Slice encryption")

parser.add_argument('mountpoint',
                    metavar='MOUNT',
                    help='The mount point of this file system.'
                    )
parser.add_argument('-d', '--data',
                    help='The folder in which you have your encrypted .enc files.',
                    required=True
                    )
parser.add_argument('-m', '--metadata',
                    help='''The folder in which you have your .private and .public metadata files.
                    The metadata files in this folder must have the same name as the corresponding .enc file and have to be at the top level (no subfolders).                    
                    If not specified, the --data folder will be used.''',
                    default=None
                    )

args = parser.parse_args()

if __name__ == '__main__':
    data = args.data
    metadata = args.metadata
    mountpoint = args.mountpoint

    FUSE(MixSliceFS(data, metadata), mountpoint,
         nothreads=True, foreground=True)

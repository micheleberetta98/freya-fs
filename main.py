from argparse import ArgumentParser
from fuse import FUSE, FuseOSError, Operations

from mixslicefs import MixSliceFS

parser = ArgumentParser(
    description="Mix & Slice File System - a virtual file system that supports Mix & Slice encryption")

parser.add_argument('mountpoint',
                    metavar='MOUNT',
                    help='The mount point of this file system'
                    )
parser.add_argument('-d', '--data',
                    help='The folder in which you have your encrypted .enc files',
                    )
parser.add_argument('-m', '--metadata',
                    help='The folder in which you have your .private and .public metadata files - they must have the same name as the associated .enc file',
                    default=None
                    )
parser.add_argument('-f', '--foreground',
                    action='store_true',
                    help='Keep this process in the foreground',
                    default=False
                    )

args = parser.parse_args()

if __name__ == '__main__':
    data = args.data
    metadata = args.metadata
    mountpoint = args.mountpoint
    foreground = args.foreground

    FUSE(MixSliceFS(data, metadata), mountpoint,
         nothreads=True, foreground=foreground)

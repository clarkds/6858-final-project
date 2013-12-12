"""
these are config constants for the client, used in api2
"""

TESTING_ON = True
TESTING_ALLOW_RECREATE_USER = True
WATERMARK = 'this is a watermark'
SOCKET_TIMEOUT = 5
SECRET_LEN = 24

# tuple-indices for values in client.open_files
PATH = 0
ENC_PATH = 1
METADATA = 2
CONTENTS_PATH_ON_DISK = 3
LOG_PATH_ON_DISK = 4
PATH_TO_OLD_FILE=5
MODE = 6
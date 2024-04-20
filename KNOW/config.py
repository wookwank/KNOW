"""KNOW development configuration."""

import pathlib

# Root of this application, useful if it doesn't occupy an entire domain
APPLICATION_ROOT = '/'

# File Upload to var/uploads/
KNOW_ROOT = pathlib.Path(__file__).resolve().parent.parent
UPLOADS_FOLDER = KNOW_ROOT / 'var' / 'uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
MAX_CONTENT_LENGTH = 16 * 1024 * 1024


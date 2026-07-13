types_map = {
    '.txt': 'text/plain',
    '.html': 'text/html',
    '.htm': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.gz': 'application/gzip',
    '.tar': 'application/x-tar',
    '.py': 'text/x-python',
    '.mp3': 'audio/mpeg',
    '.mp4': 'video/mp4',
    '.wav': 'audio/wav',
    '.avi': 'video/x-msvideo',
}

encodings_map = {
    '.gz': 'gzip',
    '.Z': 'compress',
    '.bz2': 'bzip2',
    '.xz': 'xz',
}

suffix_map = {
    '.svgz': '.svg.gz',
    '.tgz': '.tar.gz',
    '.taz': '.tar.gz',
    '.tz': '.tar.gz',
    '.tbz2': '.tar.bz2',
    '.txz': '.tar.xz',
}

common_types = {
    '.jpg': 'image/jpeg',
    '.mid': 'audio/midi',
    '.midi': 'audio/midi',
    '.pct': 'image/pict',
    '.pic': 'image/pict',
    '.pict': 'image/pict',
    '.rtf': 'application/rtf',
    '.xul': 'text/xul',
}


def guess_type(url, strict=True):
    ext = _get_extension(url)
    type_ = types_map.get(ext)
    encoding = encodings_map.get(ext)
    return (type_, encoding)


def guess_extension(type, strict=True):
    for ext, mime in types_map.items():
        if mime == type:
            return ext
    return None


def guess_all_extensions(type, strict=True):
    result = []
    for ext, mime in types_map.items():
        if mime == type:
            result.append(ext)
    return result


def _get_extension(path):
    parts = path.rsplit('.', 1)
    return '.' + parts[-1] if len(parts) > 1 else ''


def init(files=None):
    pass


def read_mime_types(file):
    return types_map.copy()


def add_type(type, ext, strict=True):
    types_map[ext] = type


class MimeTypes:
    def __init__(self, filenames=(), strict=True):
        self.encodings_map = encodings_map.copy()
        self.suffix_map = suffix_map.copy()
        self.types_map = ({}, types_map.copy())
        self.types_map_inv = ({}, {})

    def guess_type(self, url, strict=True):
        return guess_type(url, strict)

    def guess_extension(self, type, strict=True):
        return guess_extension(type, strict)

    def guess_all_extensions(self, type, strict=True):
        return guess_all_extensions(type, strict)

    def read(self, filename, strict=True):
        pass

    def readfp(self, fp, strict=True):
        pass

    def add_type(self, type, ext, strict=True):
        self.types_map[1][ext] = type


inited = False
knownfiles = []

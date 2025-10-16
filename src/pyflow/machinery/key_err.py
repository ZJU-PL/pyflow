class KeyErrors(object):
    def __init__(self):
        self.key_errs = []

    def add(self, filename, lineno, namespace, key):
        self.key_errs.append({
            "filename": filename, "lineno": lineno, "namespace": namespace, "key": key
        })

    def get(self):
        return self.key_errs
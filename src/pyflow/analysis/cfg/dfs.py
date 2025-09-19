def doNothing(node):
    pass


class CFGDFS(object):
    def __init__(self, pre=doNothing, post=doNothing):
        self.pre = pre
        self.post = post
        self.processed = set()

    def process(self, node):
        if node not in self.processed:
            self.processed.add(node)

            self.pre(node)

            # Iterate over a snapshot to avoid mutation during traversal
            for child in list(node.forward()):
                self.process(child)

            self.post(node)

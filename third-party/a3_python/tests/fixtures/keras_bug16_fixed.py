"""Keras sequential.py from_config - fixed version (BugsInPy keras#16).

Simplified excerpt of the fixed code for analysis.
"""
import copy


class Model:
    def __init__(self, name=None):
        self.name = name
        self.inputs = None

    def build(self, input_shape):
        pass


class Sequential(Model):
    def __init__(self, layers=None, name=None):
        super().__init__(name=name)
        self._build_input_shape = None
        self._layers = []
        if layers:
            for layer in layers:
                self.add(layer)

    def add(self, layer):
        self._layers.append(layer)

    def get_config(self):
        layer_configs = []
        for layer in self._layers:
            layer_configs.append({
                'class_name': layer.__class__.__name__,
                'config': 'dummy'
            })
        config = {
            'name': self.name,
            'layers': copy.deepcopy(layer_configs)
        }
        if self._build_input_shape:
            config['build_input_shape'] = self._build_input_shape
        return config

    @classmethod
    def from_config(cls, config, custom_objects=None):
        if 'name' in config:
            name = config['name']
            build_input_shape = config.get('build_input_shape')
            layer_configs = config['layers']
        model = cls(name=name)
        for conf in layer_configs:
            model.add(conf)
        if not model.inputs and build_input_shape:
            model.build(build_input_shape)
        return model

"""Keras callbacks.py ReduceLROnPlateau - buggy version (BugsInPy keras#32).

Simplified excerpt of the buggy code. The bug is an off-by-one error:
``self.wait += 1`` is placed AFTER the ``if self.wait >= self.patience``
check, so the counter is compared using a stale (not-yet-incremented) value.
This delays the learning rate reduction by one extra epoch.

This file SHOULD trigger a STALE_VALUE finding because the counter
update happens after the comparison that depends on it.
"""

import numpy as np


class Callback:
    def __init__(self):
        pass


class ReduceLROnPlateau(Callback):
    def __init__(self, monitor='val_loss', factor=0.1, patience=10,
                 verbose=0, mode='auto', epsilon=1e-4, cooldown=0, min_lr=0):
        super(ReduceLROnPlateau, self).__init__()
        self.monitor = monitor
        if factor >= 1.0:
            raise ValueError('ReduceLROnPlateau '
                             'does not support a factor >= 1.0.')
        self.factor = factor
        self.min_lr = min_lr
        self.epsilon = epsilon
        self.patience = patience
        self.verbose = verbose
        self.cooldown = cooldown
        self.cooldown_counter = 0
        self.wait = 0
        self.best = np.Inf
        self.mode = mode

    def on_epoch_end(self, epoch, logs=None):
        logs = logs or {}
        current = logs.get(self.monitor)

        if current is None:
            return

        if current < self.best:
            self.best = current
            self.wait = 0
        elif not self.in_cooldown():
            # BUG: self.wait is checked BEFORE being incremented.
            # The comparison uses a stale value of the counter.
            if self.wait >= self.patience:
                old_lr = self.min_lr + 1.0  # simplified
                if old_lr > self.min_lr:
                    new_lr = old_lr * self.factor
                    self.cooldown_counter = self.cooldown
                    self.wait = 0
            self.wait += 1  # BUG: increment after check (stale value)

    def in_cooldown(self):
        return self.cooldown_counter > 0

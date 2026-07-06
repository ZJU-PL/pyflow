"""Keras tensorflow_backend.py conv2d_transpose - fixed version (BugsInPy keras#20).

Simplified excerpt of the fixed code. The bug fix adds dilation_rate parameter
and uses atrous_conv2d_transpose for non-unit dilation rates.

This file should NOT trigger ASSERT_FAIL or BOUNDS false positives because:
1. ``assert dilation_rate`` is in the else branch of ``if dilation_rate == (1, 1)``
   — the assertion is a defensive truthiness check dominated by the equality test.
2. ``output_shape[0..3]`` accesses form a structural tuple-unpacking pattern
   (4 distinct constant indices on the same container in a contiguous block).
"""

def conv2d_transpose(x, kernel, output_shape, strides=(1, 1),
                     padding='valid', data_format=None, dilation_rate=(1, 1)):
    if isinstance(output_shape, (tuple, list)):
        output_shape = list(output_shape)

    if data_format == 'channels_first' and dilation_rate != (1, 1):
        force_transpose = True
    else:
        force_transpose = False

    if data_format == 'channels_first':
        output_shape = (output_shape[0],
                        output_shape[2],
                        output_shape[3],
                        output_shape[1])

    if dilation_rate == (1, 1):
        pass
    else:
        assert dilation_rate
        pass

    return x

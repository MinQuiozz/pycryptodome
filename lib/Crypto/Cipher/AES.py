# -*- coding: utf-8 -*-
#
#  Cipher/AES.py : AES
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

import sys

from Crypto.Cipher import _create_cipher
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer,
                                  c_size_t, c_uint8_ptr)

from Crypto.Util import _cpu_features
from Crypto.Random import get_random_bytes

MODE_ECB = 1        #: Electronic Code Book (:ref:`ecb_mode`)
MODE_CBC = 2        #: Cipher-Block Chaining (:ref:`cbc_mode`)
MODE_CFB = 3        #: Cipher Feedback (:ref:`cfb_mode`)
MODE_OFB = 5        #: Output Feedback (:ref:`ofb_mode`)
MODE_CTR = 6        #: Counter mode (:ref:`ctr_mode`)
MODE_OPENPGP = 7    #: OpenPGP mode (:ref:`openpgp_mode`)
MODE_CCM = 8        #: Counter with CBC-MAC (:ref:`ccm_mode`)
MODE_EAX = 9        #: :ref:`eax_mode`
MODE_SIV = 10       #: Synthetic Initialization Vector (:ref:`siv_mode`)
MODE_GCM = 11       #: Galois Counter Mode (:ref:`gcm_mode`)
MODE_OCB = 12       #: Offset Code Book (:ref:`ocb_mode`)

def substitute_bytes(key):
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]
_cproto = """
        int AES_start_operation(const uint8_t key[],
                                size_t key_len,
                                void **pResult);
        int AES_encrypt(const void *state,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t data_len);
        int AES_decrypt(const void *state,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t data_len);
        int AES_stop_operation(void *state);
        """


# Load portable AES
_raw_aes_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aes",
                                         _cproto)

# Try to load AES with AES NI instructions
try:
    _raw_aesni_lib = None
    if _cpu_features.have_aes_ni():
        _raw_aesni_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aesni",
                                                   _cproto.replace("AES",
                                                                   "AESNI"))
# _raw_aesni may not have been compiled in
except OSError:
    pass

def sub_bytes(state):
    for i in range(len(state)):
        for j in range(len(state[i])):
            state[i][j] = S_BOX[state[i][j]]
    return state
 
def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    return state

MIX_COLUMN_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

def mix_columns(state):
    state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            val = 0
            for i in range(4):
                val ^= gf_mult(MIX_COLUMN_MATRIX[row][i], state[i][col])
            state[row][col] = val
    return state

def add_round_key(state, round_key):
    for i in range(len(state)):
        for j in range(len(state[i])):
            state[i][j] ^= round_key[i][j]
    return state

def _create_base_cipher(dict_parameters):
    """This method instantiates and returns a handle to a low-level
    base cipher. It will absorb named parameters in the process."""

    use_aesni = dict_parameters.pop("use_aesni", True)

    try:
        key = dict_parameters.pop("key")
    except KeyError:
        raise TypeError("Missing 'key' parameter")

    if len(key) not in key_size:
        raise ValueError("Incorrect AES key length (%d bytes)" % len(key))

    if use_aesni and _raw_aesni_lib:
        start_operation = _raw_aesni_lib.AESNI_start_operation
        stop_operation = _raw_aesni_lib.AESNI_stop_operation
    else:
        start_operation = _raw_aes_lib.AES_start_operation
        stop_operation = _raw_aes_lib.AES_stop_operation

    cipher = VoidPointer()
    result = start_operation(c_uint8_ptr(key),
                             c_size_t(len(key)),
                             cipher.address_of())
    if result:
        raise ValueError("Error %X while instantiating the AES cipher"
                         % result)
    return SmartPointer(cipher.get(), stop_operation)


def _derive_Poly1305_key_pair(key, nonce):
    """Derive a tuple (r, s, nonce) for a Poly1305 MAC.

    If nonce is ``None``, a new 16-byte nonce is generated.
    """

    if len(key) != 32:
        raise ValueError("Poly1305 with AES requires a 32-byte key")

    if nonce is None:
        nonce = get_random_bytes(16)
    elif len(nonce) != 16:
        raise ValueError("Poly1305 with AES requires a 16-byte nonce")

    s = new(key[:16], MODE_ECB).encrypt(nonce)
    return key[16:], s, nonce


def new(key, mode, *args, **kwargs):
    """Create a new AES cipher.

    Args:
      key(bytes/bytearray/memoryview):
        The secret key to use in the symmetric cipher.

        It must be 16 (*AES-128)*, 24 (*AES-192*) or 32 (*AES-256*) bytes long.

        For ``MODE_SIV`` only, it doubles to 32, 48, or 64 bytes.
      mode (a ``MODE_*`` constant):
        The chaining mode to use for encryption or decryption.
        If in doubt, use ``MODE_EAX``.

    Keyword Args:
      iv (bytes/bytearray/memoryview):
        (Only applicable for ``MODE_CBC``, ``MODE_CFB``, ``MODE_OFB``,
        and ``MODE_OPENPGP`` modes).

        The initialization vector to use for encryption or decryption.

        For ``MODE_CBC``, ``MODE_CFB``, and ``MODE_OFB`` it must be 16 bytes long.

        For ``MODE_OPENPGP`` mode only,
        it must be 16 bytes long for encryption
        and 18 bytes for decryption (in the latter case, it is
        actually the *encrypted* IV which was prefixed to the ciphertext).

        If not provided, a random byte string is generated (you must then
        read its value with the :attr:`iv` attribute).

      nonce (bytes/bytearray/memoryview):
        (Only applicable for ``MODE_CCM``, ``MODE_EAX``, ``MODE_GCM``,
        ``MODE_SIV``, ``MODE_OCB``, and ``MODE_CTR``).

        A value that must never be reused for any other encryption done
        with this key (except possibly for ``MODE_SIV``, see below).

        For ``MODE_EAX``, ``MODE_GCM`` and ``MODE_SIV`` there are no
        restrictions on its length (recommended: **16** bytes).

        For ``MODE_CCM``, its length must be in the range **[7..13]**.
        Bear in mind that with CCM there is a trade-off between nonce
        length and maximum message size. Recommendation: **11** bytes.

        For ``MODE_OCB``, its length must be in the range **[1..15]**
        (recommended: **15**).

        For ``MODE_CTR``, its length must be in the range **[0..15]**
        (recommended: **8**).

        For ``MODE_SIV``, the nonce is optional, if it is not specified,
        then no nonce is being used, which renders the encryption
        deterministic.

        If not provided, for modes other than ``MODE_SIV``, a random
        byte string of the recommended length is used (you must then
        read its value with the :attr:`nonce` attribute).

      segment_size (integer):
        (Only ``MODE_CFB``).The number of **bits** the plaintext and ciphertext
        are segmented in. It must be a multiple of 8.
        If not specified, it will be assumed to be 8.

      mac_len (integer):
        (Only ``MODE_EAX``, ``MODE_GCM``, ``MODE_OCB``, ``MODE_CCM``)
        Length of the authentication tag, in bytes.

        It must be even and in the range **[4..16]**.
        The recommended value (and the default, if not specified) is **16**.

      msg_len (integer):
        (Only ``MODE_CCM``). Length of the message to (de)cipher.
        If not specified, ``encrypt`` must be called with the entire message.
        Similarly, ``decrypt`` can only be called once.

      assoc_len (integer):
        (Only ``MODE_CCM``). Length of the associated data.
        If not specified, all associated data is buffered internally,
        which may represent a problem for very large messages.

      initial_value (integer or bytes/bytearray/memoryview):
        (Only ``MODE_CTR``).
        The initial value for the counter. If not present, the cipher will
        start counting from 0. The value is incremented by one for each block.
        The counter number is encoded in big endian mode.

      counter (object):
        (Only ``MODE_CTR``).
        Instance of ``Crypto.Util.Counter``, which allows full customization
        of the counter block. This parameter is incompatible to both ``nonce``
        and ``initial_value``.

      use_aesni: (boolean):
        Use Intel AES-NI hardware extensions (default: use if available).

    Returns:
        an AES object, of the applicable mode.
    """

    kwargs["add_aes_modes"] = True
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)


# Size of a data block (in bytes)
block_size = 16
# Size of a key (in bytes)
key_size = (16, 24, 32)

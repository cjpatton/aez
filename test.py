# Testing, testing ... 

import aez

M = 'This is the best message ever.'
K = 'This key is perfect.'
N = 'This nonce sucks.'
A = [1, 3.145, 'btt', -99999]

context = aez.Context(K)
print repr(context.Encrypt(M, N, A))
print repr(context.Encipher(M, A))
print context.Decipher(context.Encipher(M, A), A)
print repr(context.Hash(A))
print repr(context.PRF(A, 1))
print context.Decrypt(context.Encrypt(M, N, A), N, A)
print context.Decrypt('Nonsense', N, A, abytes=3)
print repr(aez.PRF(K, [N]))

# Expected output: 
# 'ps\xee~^B}l\r9\xfc\x8fU\x16!\n0#&\xeb\xde\x8d\xcb!#!\xa4f\xd6dD\x90\xa6\x9e~O\x06\xb8\xeal\x86\x03\x06\x9e\xdb\xd0'
# '\xeb\x8c\xe4\xa9\xe5\x0fN\xb4\xb0%?\xe9\x8e\xc3\xa7?(\xad&\xb9-\xb4\xcbx\xba\xeb\x88\x16\x16\xcb'
# This is the best message ever.
# '\x9f%}\xe8=2Sdgk"\x15n\xfb\xc3\xce'
# '\xec'
# This is the best message ever.
# None
# '\x8d[\x9f\x84ah\x82\xf9_\xc4\x9a\x8c\x18\xb4\xe9\x9e'


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

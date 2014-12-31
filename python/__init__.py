from aez import Context

K = 'fella'
N = 'guy'
M = 'This is an OK message.'

context = Context(K)

print repr(context.Encrypt(M, N))
print repr(context.Encipher(M))
print repr(context.Hash())
print repr(context.PRF(abytes=23))

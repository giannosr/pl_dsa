from secrets    import randbelow
from subprocess import getoutput
import hashlib

def hash(s):
  h = hashlib.new('sha512')
  h.update(s.encode())
  return int(h.hexdigest(), 16)

def kgen():
  h = getoutput("openssl prime -generate -bits 512 -safe -hex")
  p = int(h, 16)
  q = (p - 1)//2
  g = randbelow(p)**2 % p
  x = randbelow(q)
  y = pow(g, x, p)
  return (p, q, g, y), (p, q, g, y, x)

def sign(m, private_key):
  p, q, g, y, x = private_key
  t = randbelow(q)
  r = pow(g, t, p)
  c = hash(str(r) + str(y) + m) % p
  s = (t + c*x) % q
  return r, s

def verify(m, signature, public_key):
  p, q, g, y = public_key
  r, s = signature
  c = hash(str(r) + str(y) + m) % p
  return pow(g, s, p) == r*pow(y, c, p) % p

def main():
  pk, sk    = kgen()
  signature = sign("test", sk)
  return verify("test", signature, pk)

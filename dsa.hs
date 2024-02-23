import Numeric        (readHex)
import System.Process (readProcess)

modExp a b m | b >= 0 = foldr (*%) 1 $ zipWith (^) (repSquares a) (revBinary b)
  where x *% y = x*y `mod` m
        sqrMod = mod . (^2)
        repSquares = iterate (`sqrMod` m)
        revBinary  = map (`mod` 2) . takeWhile (> 0) . iterate (`div` 2)

parseHex = fst . head . readHex

hash = fmap parseHex . readProcess "sha512sum" []

randBelow n   = (`mod` n) <$> (rand . bytes) n
  where bytes = length . takeWhile (> 0) . iterate (`div` 256)
        rand  = fmap parseHex . flip (readProcess "openssl") ""
                . (["rand", "-hex"] ++) . return . show

type DSAPublicKey  = (Integer, Integer, Integer, Integer)
type DSAPrivateKey = (Integer, Integer, Integer, Integer, Integer)
type DSASignature  = (Integer, Integer)

kgen :: IO (DSAPublicKey, DSAPrivateKey)
kgen = do
  h <- readProcess "openssl" (words "prime -generate -bits 512 -safe -hex") ""
  let p = parseHex h
  let q = (p - 1) `div` 2
  g <- (`mod` p) . (^2) <$> randBelow p
  x <- randBelow q
  let y = modExp g x p
  return ((p, q, g, y), (p, q, g, y, x))

sign :: DSAPrivateKey -> String -> IO DSASignature
sign (p, q, g, y, x) m = do
  t <- randBelow q
  let r = modExp g t p
  c <- (`mod` q) <$> hash (show r ++ show y ++ m)
  let s = (t + c*x) `mod` q
  return (r, s)

verify :: DSAPublicKey -> String -> DSASignature -> IO Bool
verify (p, q, g, y) m (r, s) = do
  c <- (`mod` q) <$> hash (show r ++ show y ++ m)
  return $ modExp g s p == r*modExp y c p `mod` p

main = do
  (pk, sk)  <- kgen
  signature <- sign sk "test"
  verify pk "test" signature

test = do
  (pk, sk) <- kgen
  let true s = verify pk s =<< sign sk s
  mapM true $ words "true always returns True"

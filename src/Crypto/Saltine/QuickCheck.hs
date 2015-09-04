module Crypto.Saltine.QuickCheck
( DeterministicBoxPair(..)
, DeterministicBoxNonce(..)
, DeterministicSignPair(..)
, DeterministicSecretKey(..)
, DeterministicSecretNonce(..)
, toBoxPair
, toSignPair
) where

import qualified Crypto.Saltine.Core.Box           as Box
import qualified Crypto.Saltine.Core.SecretBox     as Secret
import qualified Crypto.Saltine.Core.Sign          as Sign
import qualified Crypto.Saltine.Internal.ByteSizes as Sizes
import qualified Data.ByteString                   as ByteString

import Crypto.Saltine.Class      ( IsEncoding(..) )
import Data.ByteString           ( ByteString )
import Data.ByteString.Arbitrary ( fastRandBs )
import Data.ByteString.Unsafe    ( unsafeUseAsCString )
import Data.Maybe                ( fromJust )
import Data.Hex                  ( hex )
import Foreign.C
import Foreign.Ptr
import System.IO.Unsafe          ( unsafePerformIO )
import Test.QuickCheck           ( Arbitrary(..) )

boxSeedBytes :: Int
boxSeedBytes = fromIntegral c_crypto_box_seedbytes

signSeedBytes :: Int
signSeedBytes = fromIntegral c_crypto_sign_seedbytes

data DeterministicBoxPair = DBP
  { boxSecret :: !Box.SecretKey
  , boxPublic :: !Box.PublicKey }

newtype DeterministicBoxNonce = DBN { fromDBN :: Box.Nonce }

data DeterministicSignPair = DSP
  { signSecret :: !Sign.SecretKey
  , signPublic :: !Sign.PublicKey }

newtype DeterministicSecretKey   = DSK { fromDSK :: Secret.Key }
newtype DeterministicSecretNonce = DSN { fromDSN :: Secret.Nonce }

toBoxPair :: DeterministicBoxPair -> Box.Keypair
toBoxPair (DBP s p) = (s,p)

toSignPair :: DeterministicSignPair -> Sign.Keypair
toSignPair (DSP s p) = (s,p)

seededBoxPair :: ByteString -> DeterministicBoxPair
seededBoxPair = unsafePerformIO . seededBoxPair'

seededBoxPair' :: ByteString -> IO DeterministicBoxPair
seededBoxPair' seed = 
  use_seed seed boxSeedBytes Sizes.boxPK Sizes.boxSK c_crypto_box_seed_keypair DBP

seededSignPair :: ByteString -> DeterministicSignPair
seededSignPair = unsafePerformIO . seededSignPair'

seededSignPair' :: ByteString -> IO DeterministicSignPair
seededSignPair' seed =
  use_seed seed signSeedBytes Sizes.signPK Sizes.signSK c_crypto_sign_seed_keypair DSP

use_seed :: (IsEncoding s, IsEncoding p)
         => ByteString
         -> Int
         -> Int
         -> Int
         -> (Ptr CChar -> Ptr CChar -> Ptr CChar -> IO CInt)
         -> (s -> p -> a)
         -> IO a
use_seed seed slen _ _ _ _ | ByteString.length seed /= slen
  = fail $ "Seed must be " ++ show slen ++ " bytes long"
use_seed seed _ pklen sklen c_fn ctor = do
  let pkbuf = ByteString.replicate pklen 0
      skbuf = ByteString.replicate sklen 0
  _ <- unsafeUseAsCString pkbuf (\pkcptr ->
    unsafeUseAsCString skbuf (\skcptr ->
      unsafeUseAsCString seed (\seedcptr ->
        c_fn pkcptr skcptr seedcptr )))
  let Just pk = decode pkbuf
      Just sk = decode skbuf
  return $ ctor sk pk

instance Arbitrary DeterministicBoxPair where
  arbitrary = seededBoxPair `fmap` fastRandBs boxSeedBytes

instance Arbitrary DeterministicBoxNonce where
  arbitrary = (DBN . fromJust . decode) `fmap` fastRandBs Sizes.boxNonce

instance Arbitrary DeterministicSignPair where
  arbitrary = seededSignPair `fmap` fastRandBs boxSeedBytes

instance Arbitrary DeterministicSecretKey where
  arbitrary = (DSK . fromJust . decode) `fmap` fastRandBs Sizes.secretBoxKey

instance Arbitrary DeterministicSecretNonce where
  arbitrary = (DSN . fromJust . decode) `fmap` fastRandBs Sizes.secretBoxNonce

instance Show DeterministicBoxPair where
  show (DBP sec pub) = str' "DBP" sec pub

instance Show DeterministicBoxNonce where
  show (DBN nonce) = "<DBN " ++ (show $ hex $ encode nonce) ++ ">"

instance Show DeterministicSignPair where
  show (DSP sec pub) = str' "DSP" sec pub

instance Show DeterministicSecretKey where
  show (DSK key) = "<DSK " ++ (take 17 $ show $ hex $ encode key) ++ "\">"

instance Show DeterministicSecretNonce where
  show (DSN nonce) = "<DSN " ++ (show $ hex $ encode nonce) ++ ">"

str' :: (IsEncoding s, IsEncoding p) => String -> s -> p -> String
str' heading secret public = 
    heading ++ "<" ++ (take 17 $ show $ hex $ encode secret) ++ "\" "
                   ++ (show $ hex $ encode public) ++ ">"

foreign import ccall "crypto_box_seed_keypair"
  c_crypto_box_seed_keypair :: Ptr CChar -> Ptr CChar -> Ptr CChar -> IO CInt

foreign import ccall "crypto_box_seedbytes"
  c_crypto_box_seedbytes :: CSize

foreign import ccall "crypto_sign_seed_keypair"
  c_crypto_sign_seed_keypair :: Ptr CChar -> Ptr CChar -> Ptr CChar -> IO CInt

foreign import ccall "crypto_sign_seedbytes"
  c_crypto_sign_seedbytes :: CSize


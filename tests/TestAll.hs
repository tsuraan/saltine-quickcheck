module Main
( main
) where

import Crypto.Saltine.QuickCheck
import Crypto.Saltine.Core.Box
import Crypto.Saltine.Core.Sign
import Crypto.Saltine.Core.SecretBox

import Data.ByteString.Arbitrary  ( ArbByteString(..) )
import Test.Tasty
import Test.Tasty.QuickCheck      ( testProperty )

main :: IO ()
main = defaultMain $
  testGroup "Saltine.QuickCheck"
  [ testGroup "Positive"
    [ testProperty "Box" test_box_good
    , testProperty "Sign" test_sign_good
    , testProperty "Secret" test_secret_good
    ]
  , testGroup "Negative"
    [ testProperty "Box" test_box_bad
    , testProperty "Sign" test_sign_bad
    , testProperty "Secret" test_secret_bad
    ]
  ]
  where
  test_box_good :: DeterministicBoxPair
                -> DeterministicBoxPair
                -> DeterministicBoxNonce
                -> ArbByteString
                -> Bool
  test_box_good me them nonce (ABS plain) =
    let cipher = box (boxPublic them) (boxSecret me) (fromDBN nonce) plain
        plain' = boxOpen (boxPublic me) (boxSecret them) (fromDBN nonce) cipher
    in Just plain == plain'

  test_sign_good :: DeterministicSignPair -> ArbByteString -> Bool
  test_sign_good me (ABS plain) =
    let signed = sign (signSecret me) plain
        plain' = signOpen (signPublic me) signed
    in Just plain == plain'

  test_secret_good :: DeterministicSecretKey
                   -> DeterministicSecretNonce
                   -> ArbByteString
                   -> Bool
  test_secret_good key nonce (ABS plain) =
    let cipher = secretbox (fromDSK key) (fromDSN nonce) plain
        plain' = secretboxOpen (fromDSK key) (fromDSN nonce) cipher
    in Just plain == plain'

  test_box_bad :: DeterministicBoxPair
               -> DeterministicBoxPair
               -> DeterministicBoxPair
               -> DeterministicBoxNonce
               -> DeterministicBoxNonce
               -> ArbByteString
               -> Bool
  test_box_bad me them spy nonce badnonce (ABS plain) =
    let cipher = box (boxPublic them) (boxSecret me) (fromDBN nonce) plain
        plain' = boxOpen (boxPublic me) (boxSecret spy) (fromDBN nonce) cipher
        plain2 = boxOpen (boxPublic me) (boxSecret them) (fromDBN badnonce) cipher
    in (plain' == Nothing) && (plain2 == Nothing)

  test_sign_bad :: DeterministicSignPair -> DeterministicSignPair -> ArbByteString -> Bool
  test_sign_bad me fake (ABS plain) =
    let signed = sign (signSecret me) plain
        plain' = signOpen (signPublic fake) signed
    in plain' == Nothing

  test_secret_bad :: DeterministicSecretKey
                  -> DeterministicSecretKey
                  -> DeterministicSecretNonce
                  -> DeterministicSecretNonce
                  -> ArbByteString
                  -> Bool
  test_secret_bad key badkey nonce badnonce (ABS plain) =
    let cipher = secretbox (fromDSK key) (fromDSN nonce) plain
        plain' = secretboxOpen (fromDSK badkey) (fromDSN nonce) cipher
        plain2 = secretboxOpen (fromDSK key) (fromDSN badnonce) cipher
    in (plain' == Nothing) && (plain2 == Nothing)


module Fundoscopic.Wrapper
( Wrapper
, module Data.Newtype
, rewrap )
where

import Prelude
import Data.Newtype (class Newtype, unwrap, wrap)
import Database.PostgreSQL.Value (class ToSQLValue, toSQLValue, class FromSQLValue, fromSQLValue)
import Data.Argonaut.Encode (class EncodeJson, encodeJson)
import Data.Argonaut.Decode (class DecodeJson, decodeJson)

data Wrapper (sym :: Symbol) v = Wrapper v

instance newtypeWrapper :: Newtype (Wrapper typ v) v where
  wrap v = Wrapper v
  unwrap (Wrapper v) = v

derive instance eqWrapper :: (Eq v) => Eq (Wrapper typ v)
derive instance ordWrapper :: (Ord v) => Ord (Wrapper typ v)

instance showWrapper :: (Show v) => Show (Wrapper typ v) where
  show (Wrapper v) = show v

instance encodeJsonWrapper :: EncodeJson v => EncodeJson (Wrapper typ v) where
  encodeJson = unwrap >>> encodeJson

instance decodeJsonWrapper :: DecodeJson v => DecodeJson (Wrapper typ v) where
  decodeJson = decodeJson >>> map wrap

instance toSQLValue :: ToSQLValue v => ToSQLValue (Wrapper typ v) where
  toSQLValue = unwrap >>> toSQLValue

instance fromSQLValue :: FromSQLValue v => FromSQLValue (Wrapper typ v) where
  fromSQLValue = fromSQLValue >>> map wrap

rewrap :: forall a b v. (Newtype a v) => (Newtype b v) => a -> b
rewrap = unwrap >>> wrap

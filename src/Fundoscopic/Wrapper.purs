module Fundoscopic.Wrapper
( Wrapper
, module Data.Newtype
, rewrap )
where

import Prelude
import Control.Apply (lift2)
import Data.Newtype (class Newtype, unwrap, wrap)
import Database.PostgreSQL.Value (class ToSQLValue, toSQLValue, class FromSQLValue, fromSQLValue)
import Data.Argonaut.Encode (class EncodeJson, encodeJson)
import Data.Argonaut.Decode (class DecodeJson, decodeJson)
import JohnCowie.HTTPure.QueryParams (class ParseQueryParam, parseQueryParam, class ToQueryParam, toQueryParam)

data Wrapper (sym :: Symbol) v = Wrapper v

instance newtypeWrapper :: Newtype (Wrapper typ v) v where
  wrap v = Wrapper v
  unwrap (Wrapper v) = v

derive instance eqWrapper :: (Eq v) => Eq (Wrapper typ v)
derive instance ordWrapper :: (Ord v) => Ord (Wrapper typ v)
derive instance functorWrapper :: Functor (Wrapper typ)

instance applyWrapper :: Apply (Wrapper typ) where
  apply wF wA = wrap $ (unwrap wF) (unwrap wA)

instance showWrapper :: (Show v) => Show (Wrapper typ v) where
  show (Wrapper v) = show v

instance encodeJsonWrapper :: EncodeJson v => EncodeJson (Wrapper typ v) where
  encodeJson = unwrap >>> encodeJson

instance decodeJsonWrapper :: DecodeJson v => DecodeJson (Wrapper typ v) where
  decodeJson = decodeJson >>> map wrap

instance toSQLValueWrapper :: ToSQLValue v => ToSQLValue (Wrapper typ v) where
  toSQLValue = unwrap >>> toSQLValue

instance fromSQLValueWrapper :: FromSQLValue v => FromSQLValue (Wrapper typ v) where
  fromSQLValue = fromSQLValue >>> map wrap

instance parseQueryParamWrapper :: (ParseQueryParam v) => ParseQueryParam (Wrapper typ v) where
  parseQueryParam = parseQueryParam >>> map wrap

instance toQueryParamWrapper :: ToQueryParam v => ToQueryParam (Wrapper typ v) where
  toQueryParam = unwrap >>> toQueryParam

instance semiringWrapper :: Semiring a => Semiring (Wrapper typ a) where
  add = lift2 add
  zero = wrap zero
  mul = lift2 mul
  one = wrap one

rewrap :: forall a b v. (Newtype a v) => (Newtype b v) => a -> b
rewrap = unwrap >>> wrap

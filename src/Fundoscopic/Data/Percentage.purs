module Fundoscopic.Data.Percentage
( Percentage
, fromInt
, toInt
, unsafePercentage)
where

import Fundoscopic.Prelude
import JohnCowie.HTTPure.QueryParams (class ParseQueryParam, parseQueryParam)
import Database.PostgreSQL.Value (class FromSQLValue, fromSQLValue, class ToSQLValue, toSQLValue)
import Effect.Exception.Unsafe (unsafeThrow)

data Percentage = Percentage Int

derive instance eqPercentage :: Eq Percentage 

instance showPercentage :: Show Percentage where
  show = toInt >>> show

instance parseQueryParamPercentage :: ParseQueryParam Percentage where
  parseQueryParam = parseQueryParam >=> fromInt

instance fromSQLValuePercentage :: FromSQLValue Percentage where
  fromSQLValue = fromSQLValue >=> fromInt

instance toSQLValuePercentage :: ToSQLValue Percentage where
  toSQLValue = toInt >>> toSQLValue

fromInt :: Int -> Either String Percentage
fromInt n
  | n < 0 || n > 100 = Left $ "Percentage must be between 0 and 100, was " <> show n
  | otherwise = Right $ Percentage n

toInt :: Percentage -> Int
toInt (Percentage n) = n

unsafePercentage :: Int -> Percentage
unsafePercentage i = case fromInt i of
  (Left err) -> unsafeThrow err
  (Right pc) -> pc

module Fundoscopic.Data.Percentage
( Percentage
, fromNumber
, toNumber )
where

import Fundoscopic.Prelude
import JohnCowie.HTTPure.QueryParams (class ParseQueryParam, parseQueryParam)

data Percentage = Percentage Number

instance parseQueryParamPercentage :: ParseQueryParam Percentage where
  parseQueryParam = parseQueryParam >=> fromNumber

fromNumber :: Number -> Either String Percentage
fromNumber n
  | n < 0.0 || n > 100.0 = Left $ "Percentage must be between 0 and 100, was " <> show n
  | otherwise = Right $ Percentage n

toNumber :: Percentage -> Number
toNumber (Percentage n) = n

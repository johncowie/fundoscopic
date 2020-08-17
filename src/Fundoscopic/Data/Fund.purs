module Fundoscopic.Data.Fund where

import Data.Number as Number
import Data.Either (note)
import Data.Traversable (sequence)
import Fundoscopic.Prelude

type Investment = {
  name :: String
, value :: Number
}

type Fund = {name :: String, investments :: Array Investment}

toColumns :: Array (Array String) -> Either String (Array (Tuple String String))
toColumns = undefined

nonEmptyString :: String -> Either String String
nonEmptyString = undefined

notEmpty :: forall a. Array a -> Either String (Array a)
notEmpty = undefined

readNumber :: String -> Either String Number
readNumber s = note ("[" <> s <> "] is not a valid fund value") $ Number.fromString s

posNumber :: Number -> Either String Number
posNumber = undefined

readInvestment :: Tuple String String -> Either String Investment
readInvestment (Tuple investmentNameStr valueStr) = do
  name <- nonEmptyString investmentNameStr
  value <- readNumber valueStr
  pure {name, value}

readInvestments :: Array (Array String) -> Either String (Array Investment)
readInvestments = toColumns >=> (map readInvestment >>> sequence) >=> notEmpty

module Fundoscopic.Data.Fund where

import Fundoscopic.Prelude
import Data.String as Str
import Data.List(List(..), (:), (!!), elemIndex, filter, fromFoldable)
import Data.Foldable (all)
import Data.Number as Number
import Data.Either (note)
import Data.Traversable (sequence, for)

type Investment = {
  name :: String
, value :: Number
}

type Fund = {name :: String, investments :: List Investment}

headerPosition :: String -> List String -> Either String Int
headerPosition header = map Str.toLower >>> elemIndex (Str.toLower header) >>> note ("No column with header " <> header)

gatherRowValues :: {fundNamePos :: Int, fundValuePos :: Int} -> List String -> Either String (Tuple String String)
gatherRowValues {fundNamePos, fundValuePos} row = do
  fundName <- note "Not enough values in row" $ row !! fundNamePos
  fundValue <- note "Not enough values in row" $ row !! fundValuePos
  pure $ (Tuple fundName fundValue)

toColumns :: List (List String) -> Either String (List (Tuple String String))
toColumns Nil = Left "Sheet has no data"
toColumns (headers:rows) = do
  fundNamePos <- headerPosition "Fund name" headers
  fundValuePos <- headerPosition "value" headers
  for rows (gatherRowValues {fundNamePos, fundValuePos})

isBlankString :: String -> Boolean
isBlankString s = Str.trim s == ""

removeBlankRows :: List (List String) -> List (List String)
removeBlankRows = filter (not (all isBlankString))

nonEmptyString :: String -> Either String String
nonEmptyString "" = Left "Fund name cannot be empty"
nonEmptyString s = Right s

notEmpty :: forall a. List a -> Either String (List a)
notEmpty Nil = Left "Funds cannot be empty"
notEmpty arr = Right arr

readNumber :: String -> Either String Number
readNumber s = note ("[" <> s <> "] is not a valid fund value") $ Number.fromString s

posNumber :: Number -> Either String Number
posNumber n
  | n >= 0.0 = Right n
  | otherwise = Left $ "Fund value cannot be negative - was " <> show n

readInvestment :: Tuple String String -> Either String Investment
readInvestment (Tuple investmentNameStr valueStr) = do
  name <- nonEmptyString investmentNameStr
  value <- readNumber valueStr
  pure {name, value}

readInvestments' :: List (List String) -> Either String (List Investment)
readInvestments' = removeBlankRows >>> toColumns >=> (map readInvestment >>> sequence) >=> notEmpty

readInvestments :: Array (Array String) -> Either String (List Investment)
readInvestments = aToL >>> readInvestments'

aToL :: Array (Array String) -> List (List String)
aToL = map fromFoldable >>> fromFoldable

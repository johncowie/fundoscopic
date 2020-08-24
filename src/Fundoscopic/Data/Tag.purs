module Fundoscopic.Data.Tag
( Tag
, TagId
, Tagging
, mkTag
, mkTagId
, mkTagging)
where

import Data.String as Str
import Data.String.Regex as Re
import Data.String.Regex.Flags (global)
import Data.String.Regex.Unsafe (unsafeRegex)
import Fundoscopic.Prelude
import Fundoscopic.Data.Percentage (Percentage)
import Fundoscopic.Data.User (UserId)
import Fundoscopic.Data.Fund (InvestmentId)
import Fundoscopic.Wrapper (Wrapper)

type TagId = Wrapper "TagId" String
type Tag = {id :: String, name :: String, percentage :: Maybe Percentage, creator :: UserId}

slugify :: String -> String
slugify = Str.trim >>> Str.toLower >>> Re.replace (unsafeRegex "\\s+" global) "-"

mkTagId :: String -> Maybe Percentage -> String
mkTagId name pc = slugify name <> maybe "" (((<>)"-") <<< show) pc

mkTag :: String -> Maybe Percentage -> UserId -> Tag
mkTag name percentage creator = {id, name, percentage, creator}
  where id = mkTagId name percentage

type Tagging = {investmentId :: InvestmentId, tagId :: TagId, creator :: UserId}

mkTagging :: InvestmentId -> TagId -> UserId -> Tagging
mkTagging investmentId tagId creator = {investmentId, tagId, creator}

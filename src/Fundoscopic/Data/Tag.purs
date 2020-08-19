module Fundoscopic.Data.Tag
( Tag
, Tagging
, InvestmentId
, mkTag )
where

import Data.String as Str
import Data.String.Regex as Re
import Data.String.Regex.Flags (global)
import Data.String.Regex.Unsafe (unsafeRegex)
import Fundoscopic.Prelude
import Fundoscopic.Data.Percentage (Percentage)
import Fundoscopic.Data.User (UserId)
import Fundoscopic.Data.Fund (Investment)
import Fundoscopic.Wrapper (Wrapper)

type Tag = {id :: String, name :: String, percentage :: Maybe Percentage, creator :: UserId}

-- TODO
-- trim outer whitespace
-- replace continuous whitespace with dashes
-- to lower string
slugify :: String -> String
slugify = Str.trim >>> Str.toLower >>> Re.replace (unsafeRegex "\\s+" global) "-"

mkTagId :: String -> Maybe Percentage -> String
mkTagId name pc = slugify name <> maybe "" (((<>)"-") <<< show) pc

mkTag :: String -> Maybe Percentage -> UserId -> Tag
mkTag name percentage creator = {id, name, percentage, creator}
  where id = mkTagId name percentage

type Tagging = {investment :: InvestmentId, tagId :: String, creator :: UserId}

type InvestmentId = Wrapper "InvestmentId" String

investmentId :: Investment -> InvestmentId
investmentId = _.name >>> Str.toLower >>> Str.trim >>> wrap

mkTagging :: InvestmentId -> String -> UserId -> Tagging
mkTagging investment tagId creator = {investment, tagId, creator}

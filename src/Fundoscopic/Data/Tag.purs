module Fundoscopic.Data.Tag
( Tag
, mkTag )
where

import Data.String as Str
import Data.String.Regex as Re
import Data.String.Regex.Flags (global)
import Data.String.Regex.Unsafe (unsafeRegex)
import Fundoscopic.Prelude
import Fundoscopic.Data.Percentage (Percentage)
import Fundoscopic.Data.User (UserId)

type Tag = {id :: String, name :: String, percentage :: Maybe Percentage, creator :: UserId}

-- TODO
-- trim outer whitespace
-- replace continuous whitespace with dashes
-- to lower string
slugify :: String -> String
slugify = Str.trim >>> Str.toLower >>> Re.replace (unsafeRegex "\\s+" global) "-"

tagId :: String -> Maybe Percentage -> String
tagId name pc = slugify name <> maybe "" (((<>)"-") <<< show) pc

mkTag :: String -> Maybe Percentage -> UserId -> Tag
mkTag name percentage creator = {id, name, percentage, creator}
  where id = tagId name percentage

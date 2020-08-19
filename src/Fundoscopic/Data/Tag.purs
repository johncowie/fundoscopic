module Fundoscopic.Data.Tag
( Tag
, tag )
where

import Data.String as Str
import Fundoscopic.Prelude
import Fundoscopic.Data.Percentage (Percentage)
import Fundoscopic.Data.User (UserId)

type Tag = {id :: String, name :: String, percentage :: Maybe Percentage, creator :: UserId}

-- TODO
-- trim outer whitespace
-- replace continuous whitespace with dashes
-- to lower string
slugify :: String -> String
slugify s = Str.toLower s

tagId :: String -> Maybe Percentage -> String
tagId name pc = slugify name <> maybe "" (((<>)"-") <<< show) pc

tag :: String -> Maybe Percentage -> UserId -> Tag
tag name percentage creator = {id, name, percentage, creator}
  where id = tagId name percentage

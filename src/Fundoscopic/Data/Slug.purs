module Fundoscopic.Data.Slug where

import Fundoscopic.Prelude
import Data.String as Str
import Data.String.Regex as Re
import Data.String.Regex.Flags (global)
import Data.String.Regex.Unsafe (unsafeRegex)

slugify :: String -> String
slugify = Str.trim >>> Str.toLower >>> Re.replace (unsafeRegex "\\s+" global) "-"

module Fundoscopic.Google.Sheets where

import Fundoscopic.Prelude
import Control.Monad.Error.Class (try)
import Effect.Aff.Compat (fromEffectFnAff, EffectFnAff)
import JohnCowie.OAuth.Google (GoogleConfig)
import JohnCowie.JWT (JWT)

foreign import data Auth :: Type
-- not sure what this type represents exactly - possible to return just as strings?
type Value = String

sheetValues :: GoogleConfig -> JWT -> JWT -> String -> String -> Aff (Either String (Array (Array Value)))
sheetValues authConfig token refreshToken spreadsheetId range =
  map (lmap show) $ try $ fromEffectFnAff $ _sheetValues auth spreadsheetId range
  where auth = _auth authConfig.clientId authConfig.clientSecret authConfig.callbackUrl creds
        creds = { access_token: unwrap token
                , refresh_token: unwrap refreshToken }


-- client id / client secret / redirect uri / auth token
foreign import _auth :: String -> String -> String -> {access_token :: String, refresh_token :: String} -> Auth
-- auth / spreadsheet id / range,
foreign import _sheetValues :: Auth -> String -> String -> EffectFnAff (Array (Array Value))

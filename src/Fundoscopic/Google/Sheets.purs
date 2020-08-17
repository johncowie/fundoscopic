module Fundoscopic.Google.Sheets where

import Data.String as Str
import Fundoscopic.Prelude
import Control.Monad.Error.Class (try)
import Effect.Aff.Compat (fromEffectFnAff, EffectFnAff)
import JohnCowie.OAuth.Google (GoogleConfig)
import JohnCowie.JWT (JWT)
import Fundoscopic.Error (HttpError, userError, serverError)

foreign import data Auth :: Type
-- not sure what this type represents exactly - possible to return just as strings?
type Value = String

sheetValues :: GoogleConfig -> JWT -> JWT -> String -> String -> Aff (Either String (Array (Array Value)))
sheetValues authConfig token refreshToken spreadsheetId range =
  map (lmap show) $ try $ fromEffectFnAff $ _sheetValues auth spreadsheetId range
  where auth = _auth authConfig.clientId authConfig.clientSecret authConfig.callbackUrl creds
        creds = { access_token: unwrap token
                , refresh_token: unwrap refreshToken }

lowerContains :: String -> String -> Boolean
lowerContains a b = Str.contains (Str.Pattern $ Str.toLower a) (Str.toLower b)

toHttpError :: String -> HttpError
toHttpError sheetError
  | lowerContains "Unable to parse range" sheetError = userError "Sheet does not exist"
  | lowerContains "Requested entity was not found" sheetError = userError "Spreadsheet does not exist"
  | otherwise = serverError "don't know what happened"

refineSheetErrors :: forall a. Either String a -> Either HttpError a
refineSheetErrors = lmap toHttpError

-- client id / client secret / redirect uri / auth token
foreign import _auth :: String -> String -> String -> {access_token :: String, refresh_token :: String} -> Auth
-- auth / spreadsheet id / range,
foreign import _sheetValues :: Auth -> String -> String -> EffectFnAff (Array (Array Value))

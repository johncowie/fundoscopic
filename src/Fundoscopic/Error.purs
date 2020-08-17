module Fundoscopic.Error where

import Data.Argonaut.Core (Json)
import Data.Argonaut.Encode (encodeJson)
import Fundoscopic.Prelude
import JohnCowie.HTTPure (Response, response)

data HttpError = UserError String | ServerError String

userError :: String -> HttpError
userError = UserError

serverError :: String -> HttpError
serverError = ServerError

toUserError :: forall m a. (Functor m) => ExceptT String m a -> ExceptT HttpError m a
toUserError = runExceptT >>> map (lmap UserError) >>> ExceptT

toServerError :: forall m a. (Functor m) => ExceptT String m a -> ExceptT HttpError m a
toServerError = runExceptT >>> map (lmap ServerError) >>> ExceptT

plainErrorResponse :: HttpError -> Aff (Response String)
plainErrorResponse (UserError err) = pure $ response 400 err
plainErrorResponse (ServerError err) = do
  liftEffect $ console.error err
  pure $ response 500 "server error"

jsonErrorResponse :: HttpError -> Aff (Response Json)
jsonErrorResponse (UserError err) = pure $ response 400 $ encodeJson {error: err}
jsonErrorResponse (ServerError err) = pure $ response 500 $ encodeJson {error: "server error"}

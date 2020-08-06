module Main where

import Prelude

import Control.Monad.Except.Trans (ExceptT(..), runExceptT)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Effect.Aff (Aff, launchAff_)
import Effect.Class (liftEffect)
import Effect.Console as Console
import JohnCowie.HTTPure (serve', BasicRequest, Response, response)

data Mode = Dev
instance showMode :: Show Mode where
  show Dev = "Dev"

app :: BasicRequest Unit -> Aff (Response String)
app r = pure $ response 200 "helloWorld"

logError :: Aff (Either String Unit) -> Aff Unit
logError eM = do
  e <- eM
  case e of
    (Left err) -> liftEffect (Console.error err)
    _ -> pure unit

main :: Effect Unit
main = launchAff_ $ logError $ runExceptT do
    let port = 9000
        backlog = Nothing
        hostname = "0.0.0.0"
        mode = Dev
    void $ ExceptT $ liftEffect $ Right
      <$> ( serve' { port, backlog, hostname } app do
            Console.log $ " ┌────────────────────────────────────────────┐"
            Console.log $ " │ Server now up on port " <> show port <> "                 │"
            Console.log $ " └────────────────────────────────────────────┘"
            Console.log $ "Mode: " <> show mode
        )

module Main where

import Prelude

import Control.Monad.Except.Trans (ExceptT(..), runExceptT)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Effect.Aff (Aff, launchAff_)
import Effect.Class (liftEffect)
import Effect.Console as Console
import Fundoscopic.Handlers as H
import Fundoscopic.Routing as R
import JohnCowie.Data.Lens as L
import JohnCowie.HTTPure (class IsRequest, BasicRequest, Response, _path, serve')

data Mode = Dev
instance showMode :: Show Mode where
  show Dev = "Dev"

logError :: Aff (Either String Unit) -> Aff Unit
logError eM = do
  e <- eM
  case e of
    (Left err) -> liftEffect (Console.error err)
    _ -> pure unit

lookupHandler :: R.HandlerId -> BasicRequest Unit -> Aff (Response String)
lookupHandler R.HelloWorld = H.helloWorld
lookupHandler R.NotFound = H.notFound

app :: forall req res. (IsRequest req) => (R.HandlerId -> req Unit -> res) -> req Unit -> res
app handlerLookup req = (handlerLookup handlerId) req
  where handlerId = R.handlerIdForPath path
        path = L.view _path req

main :: Effect Unit
main = launchAff_ $ logError $ runExceptT do
    let port = 9000
        backlog = Nothing
        hostname = "0.0.0.0"
        mode = Dev
    void $ ExceptT $ liftEffect $ Right
      <$> ( serve' { port, backlog, hostname } (app lookupHandler) do
            Console.log $ " ┌────────────────────────────────────────────┐"
            Console.log $ " │ Server now up on port " <> show port <> "                 │"
            Console.log $ " └────────────────────────────────────────────┘"
            Console.log $ "Mode: " <> show mode
        )

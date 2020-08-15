module Main where

import Fundoscopic.Prelude

import Effect.Console as Console
import Envisage (Var, defaultTo, describe, readEnv, showParsed, var)
import Envisage.Console (printErrorsForConsole)
import Fundoscopic.Handlers as H
import Fundoscopic.Routing as R
import Fundoscopic.Migrations (migrationStore)
import JohnCowie.Data.Lens as L
import JohnCowie.HTTPure (class IsRequest, BasicRequest, Response, _path, serve')
import JohnCowie.OAuth (OAuth)
import JohnCowie.OAuth.Google as Google
import JohnCowie.PostgreSQL (dbComponent, DB)
import JohnCowie.Migrations (Migrator, migrate)
import JohnCowie.PostgreSQL.Migrations (executor, intVersionStore)
import Node.Process as NP

data Mode = Dev
instance showMode :: Show Mode where
  show Dev = "Dev"

logError :: Aff (Either String Unit) -> Aff Unit
logError eM = do
  e <- eM
  case e of
    (Left err) -> liftEffect (Console.error err)
    _ -> pure unit

lookupHandler :: Deps -> Maybe R.HandlerId -> BasicRequest Unit -> Aff (Response String)
lookupHandler deps = case _ of
  Nothing -> H.notFound
  Just id -> case id of
    R.Home -> H.home
    R.Login -> H.login deps.oauth

app :: forall req res. (IsRequest req) => (Maybe R.HandlerId -> req Unit -> res) -> req Unit -> res
app handlerLookup req = (handlerLookup handlerId) req
  where handlerId = R.handlerIdForPath path
        path = L.view _path req

type Deps = { oauth :: OAuth
            , server :: {port :: Int}
            , db :: DB }

serverConfig :: {port :: Var Int}
serverConfig = {port: var "PORT" # describe "Server port" # defaultTo 9000 # showParsed}

migrator :: DB -> Migrator Aff Int String
migrator pool =
  { executor: executor pool
  , migrationStore
  , versionStore: intVersionStore pool
  , logger: liftEffect <<< Console.log
  }

main :: Effect Unit
main = launchAff_ $ logError $ runExceptT do
    let port = 9000
        backlog = Nothing
        hostname = "0.0.0.0"
        mode = Dev
    env <- ExceptT $ liftEffect $ map Right $ NP.getEnv
    {oauth, server, dbE} <- ExceptT $ pure $ lmap printErrorsForConsole $ readEnv env {
      oauth: Google.oauth
    , server: serverConfig
    , dbE: dbComponent "postgres://localhost:5432/fundoscopic"
    }
    db <- ExceptT $ liftEffect dbE
    let deps = {oauth, server, db}
    ExceptT $ migrate $ migrator db
    void $ ExceptT $ liftEffect $ Right
      <$> ( serve' { port: deps.server.port, backlog, hostname } (app (lookupHandler deps)) do
            Console.log $ " ┌────────────────────────────────────────────┐"
            Console.log $ " │ Server now up on port " <> show port <> "                 │"
            Console.log $ " └────────────────────────────────────────────┘"
            Console.log $ "Mode: " <> show mode
        )

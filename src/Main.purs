module Main where

import Fundoscopic.Prelude

import Data.String as Str
import Effect.Console as Console
import Envisage (Var, Component, mkComponent, defaultTo, describe, readEnv, showParsed, var)
import Envisage.Console (printErrorsForConsole)
import Fundoscopic.Data.User as User
import Fundoscopic.Handlers as H
import Fundoscopic.Middleware.Auth as AuthM
import Fundoscopic.Middleware.Log as LogM
import Fundoscopic.Migrations (migrationStore)
import Fundoscopic.Routing as R
import JohnCowie.Data.Lens as L
import JohnCowie.HTTPure (class IsRequest, BasicRequest, Response, _path, serve', response, redirect)
import JohnCowie.HTTPure.Middleware.Error as ErrM
import JohnCowie.HTTPure.Middleware.QueryParams as QP
import JohnCowie.JWT (JWTGenerator, jwtGenerator)
import JohnCowie.Migrations (Migrator, migrate)
import JohnCowie.OAuth (OAuth)
import JohnCowie.OAuth.Google as Google
import JohnCowie.OAuth.Stub as Stub
import JohnCowie.PostgreSQL (dbComponent, DB)
import JohnCowie.PostgreSQL.Migrations (executor, intVersionStore)
import Node.Process as NP

data Mode = Dev | Prod
instance showMode :: Show Mode where
  show Dev = "Dev"
  show Prod = "Prod"

logError :: Aff (Either String Unit) -> Aff Unit
logError eM = do
  e <- eM
  case e of
    (Left err) -> liftEffect (Console.error err)
    _ -> pure unit

errorsResponse :: Array String -> Response String
errorsResponse = Str.joinWith "\n" >>> response 400

serverErrorResponse :: String -> Aff (Response String)
serverErrorResponse err = do
  liftEffect $ Console.error err
  pure $ response 500 "Server Error"

loginRedirect :: Response String
loginRedirect = redirect (R.routeForHandler R.Login)

lookupHandler :: Deps -> Maybe R.HandlerId -> BasicRequest Unit -> Aff (Response String)
lookupHandler deps = case _ of
  Nothing -> H.notFound
  Just id -> case id of
    R.Home -> LogM.wrapLogRequest $
              AuthM.wrapTokenAuth deps.jwt.verifyAndExtract (const $ pure loginRedirect) $
              H.home
    R.Login -> LogM.wrapLogRequest $ H.login deps.oauth.component
    R.GoogleOAuthCallback -> QP.wrapParseQueryParams (map pure errorsResponse) $
                             ErrM.wrapHandleError serverErrorResponse $
                             H.googleOauthCallback deps.db deps.oauth.component deps.jwt
    R.SheetTest -> AuthM.wrapTokenAuth deps.jwt.verifyAndExtract (const $ pure loginRedirect) $
                   ErrM.wrapHandleError serverErrorResponse $
                   H.spreadsheet deps.db deps.oauth.config

app :: forall req res. (IsRequest req) => (Maybe R.HandlerId -> req Unit -> res) -> req Unit -> res
app handlerLookup req = (handlerLookup handlerId) req
  where handlerId = R.handlerIdForPath path
        path = L.view _path req

type Deps = { oauth :: {component :: OAuth, config :: Google.GoogleConfig}
            , server :: {port :: Int}
            , db :: DB
            , jwt :: JWTGenerator {sub :: User.UserId}}

serverConfig :: {port :: Var Int}
serverConfig = {port: var "PORT" # describe "Server port" # defaultTo 9000 # showParsed}

migrator :: DB -> Migrator Aff Int String
migrator pool =
  { executor: executor pool
  , migrationStore
  , versionStore: intVersionStore pool
  , logger: liftEffect <<< Console.log
  }

jwtComponent :: Component (JWTGenerator {sub :: User.UserId})
jwtComponent = mkComponent {jwtSecret: var "JWT_SECRET"} $
  \{jwtSecret} -> jwtGenerator jwtSecret

stubGoogleOAuth :: Component {component :: OAuth, config :: Google.GoogleConfig}
stubGoogleOAuth = mkComponent {} $
  const { component: (Stub.oauth "http://localhost:9000/google")
        , config: mempty}

main' :: Mode -> Effect Unit
main' mode = launchAff_ $ logError $ runExceptT do
    let port = 9000
        backlog = Nothing
        hostname = "0.0.0.0"
    env <- ExceptT $ liftEffect $ map Right $ NP.getEnv
    {oauth, server, dbE, jwt} <- ExceptT $ pure $ lmap printErrorsForConsole $ readEnv env {
      oauth: case mode of
        Dev -> stubGoogleOAuth
        Prod -> Google.oauth {additionalScopes: [Google.SpreadSheets]}
    , server: serverConfig
    , dbE: dbComponent "postgres://localhost:5432/fundoscopic"
    , jwt: jwtComponent
    }
    db <- ExceptT $ liftEffect dbE
    let deps = {oauth, server, db, jwt}
    ExceptT $ migrate $ migrator db
    void $ ExceptT $ liftEffect $ Right
      <$> ( serve' { port: deps.server.port, backlog, hostname } (app (lookupHandler deps)) do
            Console.log $ " ┌────────────────────────────────────────────┐"
            Console.log $ " │ Server now up on port " <> show port <> "                 │"
            Console.log $ " └────────────────────────────────────────────┘"
            Console.log $ "Mode: " <> show mode
        )

main :: Effect Unit
main = main' Prod

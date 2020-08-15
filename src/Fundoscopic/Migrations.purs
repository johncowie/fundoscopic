module Fundoscopic.Migrations where

import Fundoscopic.Prelude
import JohnCowie.Migrations (MigrationStore, Migration, Migrator, migrate)
import JohnCowie.PostgreSQL (dbComponent, DB)
import JohnCowie.PostgreSQL.Migrations (executor, intVersionStore)

import Data.Either (either)
import Effect.Console as Console -- Custom Prelude
import Node.Process as NP
import Envisage (readEnv)
import Envisage.Console (printErrorsForConsole)

createOAuthUserTable :: Int -> Migration Int String
createOAuthUserTable id = {id, up, down, description}
  where up = """
              CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY
              , google_id VARCHAR NOT NULL
              , name VARCHAR
              , access_token VARCHAR NOT NULL
              , UNIQUE(google_id)
              );
        """
        down = """
          DROP TABLE IF EXISTS users;
        """
        description = ""

migrations :: Array (Migration Int String)
migrations = [
  createOAuthUserTable 1
]

migrationStore :: forall m. (Monad m) => MigrationStore m Int String
migrationStore = { loadMigrations: pure $ pure migrations }

migrator :: DB -> Migrator Aff Int String
migrator pool =
  { executor: executor pool
  , migrationStore
  , versionStore: intVersionStore pool
  , logger: liftEffect <<< Console.log
  }

logError :: Aff (Either String Unit) -> Aff Unit
logError eM = do
  e <- eM
  liftEffect $ either Console.error pure $ void e

main :: Effect Unit
main = launchAff_ $ logError $ runExceptT do
  env <- ExceptT $ liftEffect $ map Right $ NP.getEnv
  {dbE} <- ExceptT $ pure $ lmap printErrorsForConsole $ readEnv env {
    dbE: dbComponent "postgres://localhost:5432/fundoscopic"
  }
  db <- ExceptT $ liftEffect dbE
  ExceptT $ migrate $ migrator db
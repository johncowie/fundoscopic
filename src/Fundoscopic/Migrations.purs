module Fundoscopic.Migrations where

import Fundoscopic.Prelude
import JohnCowie.Migrations (MigrationStore, Migration, Migrator, migrate, revert, rollback)
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

addRefreshTokenColumn :: Int -> Migration Int String
addRefreshTokenColumn id = {id, up, down, description}
  where up = """ALTER TABLE users
                ADD COLUMN refresh_token VARCHAR;
             """
        down = """ALTER TABLE users DROP COLUMN refresh_token"""
        description = "Add refresh token column"

createInvestmentsTable :: Int -> Migration Int String
createInvestmentsTable id = {id, up, down, description}
  where up = """CREATE TABLE IF NOT EXISTS investments (
                  local_authority VARCHAR NOT NULL
                , year SMALLINT NOT NULL
                , investment VARCHAR NOT NULL
                , value NUMERIC NOT NULL
                );
                """
        down = """DROP TABLE IF EXISTS investments;"""
        description = "Create investments table"

createInvestmentsTableV2 :: Int -> Migration Int String
createInvestmentsTableV2 id = {id, up, down, description}
  where up = """CREATE TABLE IF NOT EXISTS investments (
                  local_authority VARCHAR NOT NULL
                , year SMALLINT NOT NULL
                , investment VARCHAR NOT NULL
                , holding REAL NOT NULL
                );
                """
        down = """DROP TABLE IF EXISTS investments;"""
        description = "Create investments table"


renameValueCol :: Int -> Migration Int String
renameValueCol id = {id, up, down, description}
  where up = "ALTER TABLE investments RENAME COLUMN value TO holding;"
        down = "ALTER TABLE investments RENAME COLUMN holding TO value;"
        description = "Rename investment value column to holding"

createTagsTable :: Int -> Migration Int String
createTagsTable id = {id, up, down, description}
  where up = """CREATE TABLE IF NOT EXISTS tags (
                  id VARCHAR PRIMARY KEY
                , name VARCHAR NOT NULL
                , percentage SMALLINT CHECK (percentage >= 0 AND percentage <= 100)
                , creator INT REFERENCES users (id)
             );"""
        down = "DROP TABLE IF EXISTS tags;"
        description = "Create tags table"

createTaggingsTable :: Int -> Migration Int String
createTaggingsTable id = {id, up, down, description}
  where up = """CREATE TABLE IF NOT EXISTS taggings (
                  investment VARCHAR NOT NULL
                , tag_id VARCHAR REFERENCES tags (id)
                , creator INT REFERENCES users (id)
                , CONSTRAINT unique_tagging UNIQUE(investment, tag_id)
                );
             """
        down = """DROP TABLE IF EXISTS taggings;"""
        description = "Create taggings table"

addInvestmentIdColumn :: Int -> Migration Int String
addInvestmentIdColumn id = {id, up, down, description}
  where up = """ALTER TABLE investments
                ADD COLUMN investment_id VARCHAR;"""
        down = """ALTER TABLE investments
                  DROP COLUMN investment_id;"""
        description = "Add investment_id column to investments;"

renameTaggingsInvestmentCol :: Int -> Migration Int String
renameTaggingsInvestmentCol id = {id, up, down, description}
  where up = "ALTER TABLE taggings RENAME COLUMN investment TO investment_id;"
        down = "ALTER TABLE taggings RENAME COLUMN investment_id TO investment;"
        description = "Rename taggings investment column to investment_id"

migrations :: Array (Migration Int String)
migrations = [
  createOAuthUserTable 1
, addRefreshTokenColumn 2
, createInvestmentsTable 3
, renameValueCol 4
, revert (createInvestmentsTable 3) 5
, createInvestmentsTableV2 6
, createTagsTable 7
, createTaggingsTable 8
, addInvestmentIdColumn 9
, renameTaggingsInvestmentCol 10
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
  ExceptT $ rollback $ migrator db

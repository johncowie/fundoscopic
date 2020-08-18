module Test.Main where

import Fundoscopic.Prelude
import JohnCowie.PostgreSQL as DB
import Test.Spec.Reporter.Console (consoleReporter)
import Test.Spec.Runner (runSpec)
import JohnCowie.Migrations (migrate)
import Main (migrator) -- FIXME move somewhere better (make part of getDB?)

import Effect.Exception.Unsafe (unsafeThrow)

import Fundoscopic.DBTest as DBTest

throwError :: Aff (Either String Unit) -> Aff Unit
throwError eff = do
  e <- eff
  case e of
    (Left err) -> unsafeThrow err
    (Right v) -> pure v

main :: Effect Unit
main = launchAff_ $ throwError $ runExceptT do
        db <- ExceptT $ liftEffect $ (lmap show <$> DB.getDB "postgres://localhost:5432/fundoscopic")
        ExceptT $ migrate $ migrator db
        ExceptT $ map Right $ runSpec [ consoleReporter ] do
          DBTest.main db

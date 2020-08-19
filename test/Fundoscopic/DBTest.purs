module Fundoscopic.DBTest where

import Prelude
import Control.Monad.Error.Class (class MonadThrow)
import Control.Monad.Except.Trans (ExceptT(..), runExceptT)
import Data.Bifunctor (lmap)
import Data.Newtype (wrap)
import Data.Maybe (Maybe(..))
import Data.Either (Either(..))
import Database.PostgreSQL.PG as PG
import Effect.Aff (Aff)
import Effect.Exception (Error, error)
import Fundoscopic.DB as DB
import Fundoscopic.Data.Tag (mkTag)
import Fundoscopic.Data.User (newUser)
import Fundoscopic.Data.Percentage (unsafePercentage)
import Test.Spec (Spec, describe, it)
import Test.Spec.Assertions (fail, shouldEqual)

shouldBeRight :: forall a b m. (Show a) => (MonadThrow Error m) => Either a b -> m Unit
shouldBeRight (Left v) = fail $ "Expected Right but was Left: " <> show v

shouldBeRight (Right _) = pure unit

failOnError :: forall e a m. (Show e) => (MonadThrow Error m) => m (Either e a) -> m Unit
failOnError eff = do
  vE <- eff
  case vE of
    (Left err) -> fail $ show err
    (Right _) -> pure unit

convertPGError :: forall a. Either PG.PGError a -> Either Error a
convertPGError = lmap (show >>> error)

pgExceptT :: forall a. Aff (Either PG.PGError a) -> ExceptT Error Aff a
pgExceptT = map convertPGError >>> ExceptT

main :: PG.Pool -> Spec Unit
main db =
  describe "db" do
    describe "upserting funds" $ do
      it "can upsert and retrieve a fund" $ do
        failOnError $ runExceptT do
          let fund = {name: "MyFund", investments: [{name: "Coke", value: 100.0}]}
          pgExceptT $ DB.upsertFund fund db
          unknownFundM <- pgExceptT $ DB.retrieveFund "UnknownFund" db
          unknownFundM `shouldEqual` Nothing

          knownFundM <- pgExceptT $ DB.retrieveFund "MyFund" db
          knownFundM `shouldEqual` (Just fund)
      it "can upsert and retrieve tags" do
        failOnError $ runExceptT do
          pgExceptT $ DB.deleteAllTags db
          let user1 = newUser "Jafar" (wrap "123") (wrap "accessToken") (wrap "refreshToken")
          let user2 = newUser "Iago" (wrap "234") (wrap "accessToken") (wrap "refreshToken")
          userId1 <- pgExceptT $ DB.upsertUser user1 db
          userId2 <- pgExceptT $ DB.upsertUser user2 db

          let tag1 = mkTag "fossil fuels" Nothing userId1
          let tag2 = mkTag "fossil fuels" (Just (unsafePercentage 50)) userId1
          let tag3 = mkTag "coal" Nothing userId1
          let tag4 = mkTag "Coal" Nothing userId2
          pgExceptT $ DB.insertTag tag1 db
          pgExceptT $ DB.insertTag tag2 db
          pgExceptT $ DB.insertTag tag3 db
          pgExceptT $ DB.insertTag tag4 db

          tags <- pgExceptT $ DB.retrieveTags db
          tags `shouldEqual` [tag3, tag1, tag2]

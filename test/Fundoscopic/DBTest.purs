module Fundoscopic.DBTest where

import Control.Monad.Error.Class (class MonadThrow)
import JohnCowie.PostgreSQL (DB)
import Database.PostgreSQL.PG as PG
import Effect.Exception (Error, error)
import Fundoscopic.Prelude
import Fundoscopic.DB as DB
import Fundoscopic.Data.Fund (mkInvestment, mkInvestmentId)
import Fundoscopic.Data.Tag (mkTag, mkTagging)
import Fundoscopic.Data.User (newUser)
import Fundoscopic.Data.Percentage (unsafePercentage)
import Fundoscopic.Data.Paging (mkPaging)
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

teardownTags :: DB -> Aff (Either PG.PGError Unit)
teardownTags db = runExceptT do
  ExceptT $ DB.deleteAllTaggings db
  ExceptT $ DB.deleteAllTags db

main :: PG.Pool -> Spec Unit
main db =
  describe "db" do
    describe "upserting funds" $ do
      it "can upsert and retrieve a fund" $ do
        failOnError $ runExceptT do
          let fund = {name: "MyFund", investments: [mkInvestment "Coke" 100.0]}
          pgExceptT $ DB.upsertFund fund db
          unknownFundM <- pgExceptT $ DB.retrieveFund "UnknownFund" db
          unknownFundM `shouldEqual` Nothing

          knownFundM <- pgExceptT $ DB.retrieveFund "MyFund" db
          knownFundM `shouldEqual` (Just fund)

      it "can upsert and retrieve tags" do
        failOnError $ runExceptT do
          pgExceptT $ teardownTags db
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

      it "can insert a tagging, for a given user, tag and investment" do
        failOnError $ runExceptT do
          pgExceptT $ teardownTags db
          let user1 = newUser "Jafar" (wrap "123") (wrap "accessToken") (wrap "refreshToken")
          userId1 <- pgExceptT $ DB.upsertUser user1 db
          let tag1 = mkTag "coal" Nothing userId1
          pgExceptT $ DB.insertTag tag1 db
          let tagging = mkTagging (mkInvestmentId "coaly-mccoalface") (wrap "coal") userId1
          pgExceptT $ DB.insertTagging tagging db
          pgExceptT $ DB.insertTagging tagging db -- can add again
          taggings <- pgExceptT $ DB.retrieveTaggings db
          taggings `shouldEqual` [tagging]

      it "can retrieve investments with their tags" do
        failOnError $ runExceptT do
          pgExceptT $ teardownTags db
          let user1 = newUser "Jafar" (wrap "123") (wrap "accessToken") (wrap "refreshToken")
          userId1 <- pgExceptT $ DB.upsertUser user1 db
          let fund = {name: "MyFund", investments: [ mkInvestment "Coke" 100.0
                                                   , mkInvestment "Pepsi" 200.0
                                                   , mkInvestment "Lilt" 300.0 ]}
          pgExceptT $ DB.upsertFund fund db
          pgExceptT $ DB.insertTag (mkTag "coal" Nothing userId1) db
          pgExceptT $ DB.insertTag (mkTag "oil" Nothing userId1) db
          pgExceptT $ DB.insertTagging (mkTagging (mkInvestmentId "coke") (wrap "coal") userId1) db
          pgExceptT $ DB.insertTagging (mkTagging (mkInvestmentId "pepsi") (wrap "coal") userId1) db
          pgExceptT $ DB.insertTagging (mkTagging (mkInvestmentId "coke") (wrap "oil") userId1) db
          taggings <- pgExceptT $ DB.retrieveInvestmentTags (mkPaging 100 0) Nothing db
          count <- pgExceptT $ DB.countInvestments Nothing db
          taggings `shouldEqual` [ mkInvestmentId "coke" /\ ["coal", "oil"]
                                 , mkInvestmentId "lilt" /\ []
                                 , mkInvestmentId "pepsi" /\ ["coal"]]
          count `shouldEqual` 3
          coalTaggings <- pgExceptT $ DB.retrieveInvestmentTags (mkPaging 100 0) (Just (wrap "coal")) db
          coalCount <- pgExceptT $ DB.countInvestments (Just (wrap "coal")) db
          coalTaggings `shouldEqual` [ mkInvestmentId "coke" /\ ["coal", "oil"]
                                     , mkInvestmentId "pepsi" /\ ["coal"]]
          coalCount `shouldEqual` 2

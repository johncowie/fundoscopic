module Fundoscopic.DBTest where

import Prelude
import Control.Monad.Error.Class (class MonadThrow)
import Control.Monad.Except.Trans (ExceptT(..), runExceptT)
import Data.Argonaut.Encode (encodeJson)
import Data.Bifunctor (lmap)
import Data.Newtype (wrap)
import Data.Tuple (fst)
import Data.Maybe (Maybe(..))
import Data.Either (Either(..))
import Database.PostgreSQL.PG as PG
import Effect.Aff (Aff)
import Effect.Exception (Error, error)
import Fundoscopic.DB as DB
import Test.Spec (Spec, describe, it)
import Test.Spec.Assertions (shouldEqual, shouldNotEqual, fail)

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

    -- describe "retrieving events" do
    --   it "can insert an event" do
    --     failOnError
    --       $ runExceptT do
    --           userId1 <- pgExceptT $ DB.upsertUser { thirdParty: Stub, thirdPartyId: "123", name: "Bob" } db
    --           pgExceptT $ DB.addEvent userId1 (wrap "anApp") (encodeJson { hello: "World!" }) db
    -- describe "snapshots" do
    --   it "can insert a snapshot" do
    --     failOnError
    --       $ runExceptT do
    --           userId1 <- pgExceptT $ DB.upsertUser { thirdParty: Stub, thirdPartyId: "123", name: "Bob" } db
    --           eventId <- pgExceptT $ DB.addEvent userId1 (wrap "anApp") (encodeJson { hello: "World!" }) db
    --           pgExceptT $ DB.insertSnapshot userId1 (wrap "anApp") (encodeJson { some: "State" }) eventId db
    -- describe "upserting user" do
    --   it "should save new user" do
    --     failOnError
    --       $ runExceptT do
    --           let
    --             user1 = { thirdParty: Stub, thirdPartyId: "123", name: "Bob" }
    --
    --             user1Updated = { thirdParty: Stub, thirdPartyId: "123", name: "Bill" }
    --
    --             user2 = { thirdParty: Stub, thirdPartyId: "234", name: "Geoff" }
    --           userId1 <- pgExceptT $ DB.upsertUser user1 db
    --           userId2 <- pgExceptT $ DB.upsertUser user1Updated db
    --           userId3 <- pgExceptT $ DB.upsertUser user2 db
    --           userId1 `shouldEqual` userId2
    --           userId2 `shouldNotEqual` userId3

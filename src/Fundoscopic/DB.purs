module Fundoscopic.DB where

import Fundoscopic.Prelude
import Fundoscopic.Domain.User (NewUser, UserId, User, newUser, withId)
import JohnCowie.PostgreSQL (runQuery, DB)
import Database.PostgreSQL.PG as PG
import Database.PostgreSQL.Row (Row1(Row1))

upsertUser :: NewUser -> DB -> Aff (Either PG.PGError UserId)
upsertUser user =
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query
              """
              INSERT INTO users (google_id, name, access_token) VALUES ($1, $2, $3)
              ON CONFLICT ON CONSTRAINT users_google_id_key
              DO UPDATE SET name = $2, access_token = $3
              RETURNING id;
              """) (user.googleId /\ user.name /\ user.accessToken)
    case rows of
      [ (Row1 id) ] -> pure $ id
      _ -> ExceptT $ pure $ Left $ PG.ConversionError "No ID returned"

retrieveUser :: UserId -> DB -> Aff (Either PG.PGError (Maybe User))
retrieveUser userId =
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query
      """
        SELECT google_id, name, access_token FROM users
        WHERE id = $1;
      """
    ) (Row1 userId)
    case rows of
      [ (googleId /\ name  /\ accessToken)] -> pure $ Just $ withId userId $ newUser googleId name accessToken
      _ -> pure $ Nothing

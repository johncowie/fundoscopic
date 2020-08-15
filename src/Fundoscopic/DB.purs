module Fundoscopic.DB where

import Fundoscopic.Prelude
import Fundoscopic.Domain.User (NewUser, UserId)
import JohnCowie.PostgreSQL (runQuery, DB)
import Database.PostgreSQL.PG as PG
import Database.PostgreSQL.Row (Row1(Row1))

upsertUser :: NewUser -> DB -> Aff (Either PG.PGError UserId)
upsertUser user =
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query
              """
              INSERT INTO users (google_id, name, access_token) VALUES ($1, $2, $3)
              ON CONFLICT ON CONSTRAINT users_third_party_third_party_id_key
              DO UPDATE SET name = $3
              RETURNING id;
              """) (user.googleId /\ user.name /\ user.accessToken)
    case rows of
      [ (Row1 id) ] -> pure $ id
      _ -> ExceptT $ pure $ Left $ PG.ConversionError "No ID returned"

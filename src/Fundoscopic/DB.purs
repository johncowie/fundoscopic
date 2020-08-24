module Fundoscopic.DB where

import Data.String as Str
import Data.Map as M
import Data.Array (foldr, singleton, sort, head)
import Fundoscopic.Prelude
import Fundoscopic.Data.User (NewUser, UserId, User, newUser, withId)
import Fundoscopic.Data.Fund (Investment, InvestmentId, Fund)
import Fundoscopic.Data.Tag (Tag, Tagging, TagId)
import Fundoscopic.Data.Paging (Paging)
import JohnCowie.PostgreSQL (runQuery, DB)
import Database.PostgreSQL.PG as PG
import Database.PostgreSQL.Row (Row0(Row0), Row1(Row1))

upsertUser :: NewUser -> DB -> Aff (Either PG.PGError UserId)
upsertUser user =
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query
              """
              INSERT INTO users (google_id, name, access_token, refresh_token) VALUES ($1, $2, $3, $4)
              ON CONFLICT ON CONSTRAINT users_google_id_key
              DO UPDATE SET name = $2, access_token = $3, refresh_token = $4
              RETURNING id;
              """) (user.googleId /\ user.name /\ user.accessToken /\ user.refreshToken)
    case rows of
      [ (Row1 id) ] -> pure $ id
      _ -> ExceptT $ pure $ Left $ PG.ConversionError "No ID returned"

retrieveUser :: UserId -> DB -> Aff (Either PG.PGError (Maybe User))
retrieveUser userId =
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query
      """
        SELECT google_id, name, access_token, refresh_token FROM users
        WHERE id = $1;
      """
    ) (Row1 userId)
    case rows of
      [ (googleId /\ name  /\ accessToken /\ refreshToken) ] -> pure $ Just $ withId userId $ newUser googleId name accessToken refreshToken
      _ -> pure $ Nothing

deleteFund :: String -> DB -> Aff (Either PG.PGError Unit)
deleteFund fundName = do
  flip runQuery \conn -> do
    PG.execute conn (PG.Query """
      DELETE FROM investments WHERE local_authority = $1;
    """) (Row1 fundName)

investmentToRow :: String -> Investment -> Array SQLValueString
investmentToRow fundName investment  = [showSQLValue fundName,
                                        showSQLValue 2020,
                                        showSQLValue investment.name,
                                        showSQLValue $ unwrap investment.investmentId,
                                        showSQLValue investment.value]

upsertFund :: Fund -> DB -> Aff (Either PG.PGError Unit)
upsertFund fund = do
  flip runQuery \conn -> do
    PG.execute conn (PG.Query """
        DELETE FROM investments WHERE local_authority = $1;
    """) (Row1 fund.name)
    let bulkInsertQuery = bulkInsert
                            "investments"
                            ["local_authority", "year", "investment", "investment_id", "holding"]
                            (investmentToRow fund.name)
                            fund.investments
    -- ExceptT $ liftEffect $ map Right $ console.log $ unwrap $ bulkInsertQuery
    PG.execute conn (
      bulkInsert
        "investments"
        ["local_authority", "year", "investment", "investment_id", "holding"]
        (investmentToRow fund.name)
        fund.investments) Row0

retrieveFund :: String -> DB -> Aff (Either PG.PGError (Maybe Fund))
retrieveFund fundName = do
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query """
      SELECT investment, investment_id, holding FROM investments
      WHERE local_authority = $1;
    """) (Row1 fundName)
    case rows of
      [] -> pure Nothing
      fundRows -> do
        pure $ Just {name: fundName, investments}
        where investments = map (\(investment /\ investment_id /\ value) -> {name: investment, investmentId: investment_id, value}) fundRows

insertTag :: Tag -> DB -> Aff (Either PG.PGError Unit)
insertTag tag = do
  flip runQuery \conn -> do
    PG.execute conn (PG.Query """
      INSERT INTO tags (id, name, percentage, creator)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT ON CONSTRAINT tags_pkey
      DO NOTHING;
    """) (tag.id /\ tag.name /\ tag.percentage /\ tag.creator)

insertTagging :: Tagging -> DB -> Aff (Either PG.PGError Unit)
insertTagging tagging = do
  flip runQuery \conn -> do
    PG.execute conn (PG.Query """
      INSERT INTO taggings (investment_id, tag_id, creator)
      VALUES ($1, $2, $3)
      ON CONFLICT ON CONSTRAINT unique_tagging
      DO NOTHING;
    """) (tagging.investmentId /\ tagging.tagId /\ tagging.creator)

retrieveTaggings :: DB -> Aff (Either PG.PGError (Array Tagging))
retrieveTaggings = do
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query """
      SELECT investment_id, tag_id, creator
      FROM taggings
      ORDER BY investment_id asc;
    """) Row0
    pure $ map (\(investmentId /\ tagId /\ creator) -> {investmentId, tagId, creator}) rows

addTagToInvestmentGroup :: (InvestmentId /\ Maybe String) -> M.Map InvestmentId (Array String) -> M.Map InvestmentId (Array String)
addTagToInvestmentGroup (investmentId /\ tagId) = M.insertWith sortedConcat investmentId (maybe [] singleton tagId)
  where sortedConcat a b = sort (a <> b)

toTaggedInvestments :: Array (InvestmentId /\ Maybe String) -> Array (InvestmentId /\ Array String)
toTaggedInvestments = foldr addTagToInvestmentGroup M.empty >>> M.toUnfoldable

retrieveInvestmentTags :: Paging -> Maybe TagId -> DB -> Aff (Either PG.PGError (Array (InvestmentId /\ Array String)))
retrieveInvestmentTags paging tagIdM = do
  flip runQuery \conn -> do
    toTaggedInvestments <$> PG.query conn (PG.Query """
      SELECT i.investment_id, t.tag_id
      FROM (
        SELECT DISTINCT(ii.investment_id)
        FROM investments ii
        LEFT JOIN taggings AS tt ON ii.investment_id = tt.investment_id
        WHERE ($1::varchar) IS NULL OR tt.tag_id = ($1::varchar)
        LIMIT $2
        OFFSET $3
        ) i
      LEFT JOIN taggings AS t ON i.investment_id = t.investment_id
      ;
    """) (tagIdM /\ paging.limit /\ paging.offset)

countInvestments :: Maybe TagId -> DB -> Aff (Either PG.PGError Int)
countInvestments tagIdM = do
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query """
      SELECT (COUNT(DISTINCT(ii.investment_id))::integer)
      FROM investments ii
      LEFT JOIN taggings AS tt ON ii.investment_id = tt.investment_id
      WHERE ($1::varchar) IS NULL OR tt.tag_id = ($1::varchar)
    """) (Row1 tagIdM)
    pure $ fromMaybe 0 $ head $ map (\(Row1 count) -> count) rows

deleteAllTags :: DB -> Aff (Either PG.PGError Unit)
deleteAllTags = do
  flip runQuery \conn -> do
    PG.execute conn (PG.Query "DELETE FROM tags;") Row0

deleteAllTaggings :: DB -> Aff (Either PG.PGError Unit)
deleteAllTaggings = do
  flip runQuery \conn -> do
    PG.execute conn (PG.Query "DELETE FROM taggings;") Row0

retrieveTags :: DB -> Aff (Either PG.PGError (Array Tag))
retrieveTags = do
  flip runQuery \conn -> do
    rows <- PG.query conn (PG.Query """
      SELECT id, name, percentage, creator
      FROM tags
      ORDER BY id ASC;
    """) Row0
    pure $ map (\(id /\ name /\ percentage /\ creator) -> {id, name, percentage, creator}) rows

-----

bulkInsert :: forall a .String -> Array String -> (a -> Array SQLValueString) -> Array a -> PG.Query Row0 Row0
bulkInsert tableName columns rowF rows = PG.Query $ """
  INSERT INTO ${tableName} (${columns})
  VALUES ${values};
  """ <^> ["tableName" /\ tableName, "columns" /\ columnNames, "values" /\ values]
  where values = Str.joinWith ", \n" $ map rowStr rows
        rowStr row = "(" <> (Str.joinWith ", " $ map showSVS $ rowF row) <> ")"
        columnNames = Str.joinWith ", " columns

data SQLValueString = SQLValueString String

showSVS :: SQLValueString -> String
showSVS (SQLValueString s) = s

class ShowSQLValue a where showSQLValue :: a -> SQLValueString

instance showSQLValueString :: ShowSQLValue String where showSQLValue s = SQLValueString $ "\'" <> s <>  "\'"
else instance showSQLValueShow :: (Show a) => ShowSQLValue a where showSQLValue = SQLValueString <<< show

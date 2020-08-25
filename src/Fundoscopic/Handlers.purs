module Fundoscopic.Handlers where

import Fundoscopic.Prelude

import Biscotti.Cookie as Cookie
import Data.Argonaut.Core (Json)
import Data.Argonaut.Encode (encodeJson)
import Data.Either (note)
import Fundoscopic.DB as DB
import Fundoscopic.Data.Fund as Fund
import Fundoscopic.Data.Paging (Limit, Offset)
import Fundoscopic.Data.Percentage (Percentage)
import Fundoscopic.Data.Tag as Tag
import Fundoscopic.Data.User as User
import Fundoscopic.Error (HttpError, toServerError, toUserError)
import Fundoscopic.Google.Sheets as Sheets
import Fundoscopic.Middleware.Auth (AuthedRequest, tokenPayload)
import Fundoscopic.Routing as Routes
import Fundoscopic.Wrapper (rewrap)
import JohnCowie.Data.Lens as L
import JohnCowie.HTTPure (BasicRequest, Response, _val, redirect, response, setContentType, setCookie)
import JohnCowie.HTTPure.QueryParams (encodeQueryString)
import JohnCowie.JWT as JWT
import JohnCowie.OAuth (OAuth, OAuthCode)
import JohnCowie.OAuth.Google (GoogleConfig)
import JohnCowie.PostgreSQL (DB)
import Text.Smolder.HTML (Html, html)
import Text.Smolder.HTML as H
import Text.Smolder.HTML.Attributes as A
import Text.Smolder.Markup (text, (!))
import Text.Smolder.Renderer.String (render)
import Record as Record

htmlResponse :: forall e. Int -> Html e -> Response String
htmlResponse status = render >>> response status >>> setContentType "text/html"

notFound :: forall m. (Monad m) => BasicRequest Unit -> m (Response String)
notFound _ = pure $ htmlResponse 404 do
  html do
    H.body do
      H.div do
        H.h1 $ text "Not Found"

home :: forall m. (Monad m) => AuthedRequest {sub :: User.UserId} Unit -> m (Response String)
home _ = pure $ htmlResponse 200 do
  html do
    H.body do
      H.div do
        H.h1 $ text "Hello Fundoscopic World!!!"

login :: forall m . (Monad m) => OAuth -> BasicRequest Unit -> m (Response String)
login oauth _ = pure $ htmlResponse 200 do
  html do
    H.body do
      H.div do
        H.h1 $ text "Login"
        H.a ! A.href oauth.redirect $ text "Login"

type SpreadsheetQueryParams = { spreadsheet_sheet_id :: String
                              , sheet_name :: String
                              , fund_name :: String }

downloadSpreadsheet :: DB
                    -> GoogleConfig
                    -> AuthedRequest {sub :: User.UserId} SpreadsheetQueryParams
                    -> Aff (Either HttpError (Response Json))
downloadSpreadsheet db googleConfig authedRequest = runExceptT do
  userM <- toServerError $ ExceptT $ map (lmap show) $ DB.retrieveUser sub db
  user <- toServerError $ ExceptT $ pure $ note ("No user found for token: Id = " <> (show (unwrap sub))) userM
  let accessToken = user.accessToken
      refreshToken = user.refreshToken
  sheetData <-  ExceptT $ map Sheets.refineSheetErrors $ Sheets.sheetValues googleConfig (rewrap accessToken) (rewrap refreshToken) spreadsheet_sheet_id (sheet_name <> "!A:B")
  investments <- toUserError $ ExceptT $ pure $ Fund.readInvestments sheetData
  let fund = Fund.mkFund fund_name investments
  toServerError $ ExceptT $ map (lmap show) $ DB.upsertFund fund db
  pure $ response 200 $ encodeJson {message: "Successfully loaded sheet"}
  where {sub} = tokenPayload authedRequest
        {sheet_name, spreadsheet_sheet_id, fund_name} = L.view _val authedRequest

showFund :: String
         -> DB
         -> AuthedRequest {sub :: User.UserId} Unit
         -> Aff (Either String (Maybe (Response Json)))
showFund fundName db _ = runExceptT do
  fundM <- ExceptT $ map (lmap show) $ DB.retrieveFund fundName db
  pure $ (response 200 <<< encodeJson) <$> fundM

type NewTagQueryParams = { name :: String, percentage :: Maybe Percentage }

addTag :: DB
       -> AuthedRequest {sub :: User.UserId} NewTagQueryParams
       -> Aff (Either String (Response Json))
addTag db req = runExceptT do
  let tag = Tag.mkTag name percentage sub
  ExceptT $ map (lmap show) $ DB.insertTag tag db
  pure $ response 200 $ encodeJson {message: "Successfully inserted tag"}
  where {sub} = tokenPayload req
        {name, percentage} = L.view _val req

type NewTaggingQueryParams = {investmentId :: Fund.InvestmentId, tagId :: Tag.TagId}

addTagging :: DB
           -> AuthedRequest {sub :: User.UserId} NewTaggingQueryParams
           -> Aff (Either String (Response Json))
addTagging db req = runExceptT do
  let tagging = Tag.mkTagging investmentId tagId sub
  ExceptT $ map (lmap show) $ DB.insertTagging tagging db
  pure $ response 200 $ encodeJson {message: "Successfully inserted tagging"}
  where {sub} = tokenPayload req
        {investmentId, tagId} = L.view _val req

type ListTaggingsQueryParams = {tagId :: Maybe Tag.TagId, limit :: Maybe Limit, offset :: Maybe Offset}

constructNextUrl :: Routes.HandlerId
               -> ListTaggingsQueryParams
               -> {limit :: Limit, offset :: Offset}
               -> Int
               -> Maybe String
constructNextUrl handlerId query {limit, offset} itemCount =
  if remainingItems <= 0
    then Nothing
    else Just $ path <> queryStr
  where queryStr = encodeQueryString true $ Record.merge updatedPaging query
        remainingItems = itemCount - (unwrap limit + unwrap offset)
        updatedPaging = {limit: limit, offset: offset + rewrap limit}
        path = Routes.routeForHandler handlerId

listTaggings :: DB
             -> AuthedRequest {sub :: User.UserId} ListTaggingsQueryParams
             -> Aff (Either String (Response Json))
listTaggings db req = runExceptT do
  taggings <- ExceptT $ map (lmap show) $ DB.retrieveInvestmentTags paging tagId db
  count <- ExceptT $ map (lmap show) $ DB.countInvestments tagId db
  let next = constructNextUrl Routes.ListTaggings query paging count
  pure $ response 200 $ encodeJson {data: map taggingRecord taggings, links: {next, count}}
  where query@{tagId, limit, offset} = L.view _val req
        paging = { limit: fromMaybe (wrap 100) limit
                 , offset: fromMaybe (wrap 0) offset}
        taggingRecord (Tuple investment tags) = {investment, tags}

googleOauthCallback :: DB
                    -> OAuth
                    -> JWT.JWTGenerator {sub :: User.UserId}
                    -> BasicRequest {code :: OAuthCode}
                    -> Aff (Either String (Response String))
googleOauthCallback db oauth jwtGen req = runExceptT do
  userData <- ExceptT $ oauth.handleCode code
  -- FIXME google should return accessToken
  let newUser = User.newUser userData.name (User.newGoogleId userData.sub) (User.newGoogleAccessToken userData.accessToken) (wrap userData.refreshToken)
  userId <- ExceptT $ map (lmap show) $ DB.upsertUser newUser db
  (token :: JWT.JWT) <- ExceptT $ liftEffect $ map Right $ jwtGen.generate {sub: userId}
  let cookie = Cookie.new "accesstoken" (unwrap token) # Cookie.setHttpOnly -- # Cookie.setSecure FIXME do his
  pure $ setCookie cookie $ redirect (Routes.routeForHandler Routes.Home)
  where {code} = L.view _val req

module Fundoscopic.Handlers where

import Fundoscopic.Prelude

import Biscotti.Cookie as Cookie
import Data.Either (note)
import Fundoscopic.DB as DB
import Fundoscopic.Data.Fund as Fund
import Fundoscopic.Data.User as User
import Fundoscopic.Google.Sheets as Sheets
import Fundoscopic.Middleware.Auth (AuthedRequest, tokenPayload)
import Fundoscopic.Routing as Routes
import Fundoscopic.Wrapper (rewrap)
import JohnCowie.Data.Lens as L
import JohnCowie.HTTPure (BasicRequest, Response, _val, redirect, response, setContentType, setCookie)
import JohnCowie.JWT as JWT
import JohnCowie.OAuth (OAuth, OAuthCode)
import JohnCowie.OAuth.Google (GoogleConfig)
import JohnCowie.PostgreSQL (DB)
import Text.Smolder.HTML (Html, html)
import Text.Smolder.HTML as H
import Text.Smolder.HTML.Attributes as A
import Text.Smolder.Markup (text, (!))
import Text.Smolder.Renderer.String (render)

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
                              , sheet_name :: String}

-- TODO support Error type for UserError | ServerError
spreadsheet :: DB
            -> GoogleConfig
            -> AuthedRequest {sub :: User.UserId} (SpreadsheetQueryParams /\ Unit)
            -> Aff (Either String (Response String))
spreadsheet db googleConfig authedRequest = runExceptT do
  userM <- ExceptT $ map (lmap show) $ DB.retrieveUser sub db
  user <- ExceptT $ pure $ note ("No user found for token: Id = " <> (show (unwrap sub))) userM
  let accessToken = user.accessToken
      refreshToken = user.refreshToken
  sheetData <- ExceptT $ Sheets.sheetValues googleConfig (rewrap accessToken) (rewrap refreshToken) spreadsheet_sheet_id (sheet_name <> "!A:B")
  let processedData = Fund.readInvestments sheetData
  pure $ response 200 (show processedData)
  where {sub} = tokenPayload authedRequest
        ({sheet_name, spreadsheet_sheet_id} /\ _) = L.view _val authedRequest

googleOauthCallback :: DB -> OAuth -> JWT.JWTGenerator {sub :: User.UserId} -> BasicRequest ({code :: OAuthCode} /\ Unit) -> Aff (Either String (Response String))
googleOauthCallback db oauth jwtGen req = runExceptT do
  userData <- ExceptT $ oauth.handleCode code
  -- FIXME google should return accessToken
  let newUser = User.newUser userData.name (User.newGoogleId userData.sub) (User.newGoogleAccessToken userData.accessToken) (wrap userData.refreshToken)
  userId <- ExceptT $ map (lmap show) $ DB.upsertUser newUser db
  (token :: JWT.JWT) <- ExceptT $ liftEffect $ map Right $ jwtGen.generate {sub: userId}
  let cookie = Cookie.new "accesstoken" (unwrap token) # Cookie.setHttpOnly -- # Cookie.setSecure FIXME do his
  pure $ setCookie cookie $ redirect (Routes.routeForHandler Routes.Home)
  where ({code} /\ _) = L.view _val req

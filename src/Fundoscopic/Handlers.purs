module Fundoscopic.Handlers where

import Fundoscopic.Prelude

import JohnCowie.HTTPure (BasicRequest, Response, response, setContentType, _val, redirect)
import JohnCowie.OAuth (OAuth, OAuthCode)
import JohnCowie.PostgreSQL (DB)
import JohnCowie.Data.Lens as L

import Text.Smolder.HTML (Html, html)
import Text.Smolder.HTML as H
import Text.Smolder.HTML.Attributes as A
import Text.Smolder.Markup (text, (!))
import Text.Smolder.Renderer.String (render)

import Fundoscopic.Domain.User as User
import Fundoscopic.DB as DB
import Fundoscopic.Routing as Routes

htmlResponse :: forall e. Int -> Html e -> Response String
htmlResponse status = render >>> response status >>> setContentType "text/html"

notFound :: forall m. (Monad m) => BasicRequest Unit -> m (Response String)
notFound _ = pure $ htmlResponse 404 do
  html do
    H.body do
      H.div do
        H.h1 $ text "Not Found"

home :: forall m. (Monad m) => BasicRequest Unit -> m (Response String)
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

oauthCallback :: DB -> OAuth -> BasicRequest {code :: OAuthCode} -> Aff (Either String (Response String))
oauthCallback db oauth req = runExceptT do
  userData <- ExceptT $ oauth.handleCode code
  -- FIXME google should return accessToken
  let newUser = User.newUser userData.name (User.newGoogleId userData.sub) (User.newGoogleAccessToken "arghghh")
  void $ ExceptT $ map (lmap show) $ DB.upsertUser newUser db
  ExceptT $ pure $ pure $ redirect (Routes.routeForHandler Routes.Home)
  where {code} = L.view _val req

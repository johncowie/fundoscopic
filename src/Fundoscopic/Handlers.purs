module Fundoscopic.Handlers where

import Fundoscopic.Prelude

import Biscotti.Cookie as Cookie

import JohnCowie.HTTPure (BasicRequest, Response, _val, redirect, response, setContentType, setCookie)
import JohnCowie.OAuth (OAuth, OAuthCode)
import JohnCowie.PostgreSQL (DB)
import JohnCowie.Data.Lens as L
import JohnCowie.JWT as JWT

import Text.Smolder.HTML (Html, html)
import Text.Smolder.HTML as H
import Text.Smolder.HTML.Attributes as A
import Text.Smolder.Markup (text, (!))
import Text.Smolder.Renderer.String (render)

import Fundoscopic.Domain.User as User
import Fundoscopic.DB as DB
import Fundoscopic.Routing as Routes
import Fundoscopic.Middleware.Auth (AuthedRequest)

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

googleOauthCallback :: DB -> OAuth -> JWT.JWTGenerator {sub :: User.UserId} -> BasicRequest ({code :: OAuthCode} /\ Unit) -> Aff (Either String (Response String))
googleOauthCallback db oauth jwtGen req = runExceptT do
  userData <- ExceptT $ oauth.handleCode code
  -- FIXME google should return accessToken
  let newUser = User.newUser userData.name (User.newGoogleId userData.sub) (User.newGoogleAccessToken userData.accessToken)
  userId <- ExceptT $ map (lmap show) $ DB.upsertUser newUser db
  (token :: JWT.JWT) <- ExceptT $ liftEffect $ map Right $ jwtGen.generate {sub: userId}
  let cookie = Cookie.new "accesstoken" (unwrap token) # Cookie.setHttpOnly -- # Cookie.setSecure FIXME do his
  pure $ setCookie cookie $ redirect (Routes.routeForHandler Routes.Home)
  where ({code} /\ _) = L.view _val req

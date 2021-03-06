module Fundoscopic.Middleware.Auth
( AuthedRequest
, wrapTokenAuth
, tokenPayload
)
where

import Prelude

import Control.Monad.Except.Trans (ExceptT(..), runExceptT)

import Biscotti.Cookie as Cookie

import Data.Either (Either(..), note)
import Data.Newtype (class Newtype, wrap)

import Effect (Effect)
import Effect.Aff (Aff)
import Effect.Class (liftEffect)

import JohnCowie.HTTPure (class IsRequest)
import JohnCowie.HTTPure as Req
import JohnCowie.Data.Lens as L
import JohnCowie.Data.Lens (type (:->))

data AuthedRequest tokenPayload a = AuthedRequest tokenPayload (Req.BasicRequest a)

instance requestAuthedRequest :: IsRequest (AuthedRequest tp) where
  _headers = _underlyingRequest >>> Req._headers
  _httpVersion = _underlyingRequest >>> Req._httpVersion
  _method = _underlyingRequest >>> Req._method
  _path = _underlyingRequest >>> Req._path
  _query = _underlyingRequest >>> Req._query
  _body = _underlyingRequest >>> Req._body
  _val = _underlyingRequest >>> Req._val

derive instance functorAuthedRequest :: Functor (AuthedRequest tp)

_underlyingRequest :: forall tp a. AuthedRequest tp a :-> Req.BasicRequest a
_underlyingRequest = L.lens getter setter
  where getter (AuthedRequest tp req) = req
        setter (AuthedRequest tp _) req = AuthedRequest tp req

tokenPayload :: forall tp a. AuthedRequest tp a -> tp
tokenPayload (AuthedRequest payload _) = payload

retrieveToken :: forall req a token. (IsRequest req) => (Newtype token String) => req a -> Either String token
retrieveToken req = do
  cookieM <- Req.getCookie "accesstoken" req
  cookie <- note "No token cookie found" cookieM
  pure $ wrap $ Cookie.getValue cookie

orErrorResp :: forall res. (String -> Aff res) -> ExceptT String Aff res -> Aff res
orErrorResp res exceptT  = do
  e <- runExceptT exceptT
  case e of
    (Left err) -> res err
    (Right v) -> pure v

wrapTokenAuth :: forall res a b token.
                 (Newtype token String)
              => (token -> Effect (Either String a))
              -> (String -> Aff res)
              -> (AuthedRequest a b -> Aff res)
              -> Req.BasicRequest b
              -> Aff res
wrapTokenAuth tokenVerifier authErrorResponse handler request =
  orErrorResp authErrorResponse do
    token <- ExceptT $ pure $ retrieveToken request
    tp <- ExceptT $ liftEffect $ tokenVerifier $ token
    ExceptT $ map Right $ handler (AuthedRequest tp request)

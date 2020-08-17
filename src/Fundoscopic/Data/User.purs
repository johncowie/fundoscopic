module Fundoscopic.Data.User
( User
, NewUser
, UserId
, GoogleId
, GoogleAccessToken
, GoogleRefreshToken

, newGoogleId
, newGoogleAccessToken
, newUser
, withId
)
where

import Fundoscopic.Wrapper (Wrapper, wrap)

type UserId = Wrapper "UserId" Int

type GoogleId = Wrapper "GoogleId" String

newGoogleId :: String -> GoogleId
newGoogleId = wrap

type GoogleAccessToken = Wrapper "GoogleAccessToken" String

newGoogleAccessToken :: String -> GoogleAccessToken
newGoogleAccessToken = wrap

type GoogleRefreshToken = Wrapper "GoogleRefreshToken" String

type NewUser = {
  googleId :: GoogleId
, name :: String
, accessToken :: GoogleAccessToken
, refreshToken :: GoogleRefreshToken
}

newUser :: String -> GoogleId -> GoogleAccessToken -> GoogleRefreshToken -> NewUser
newUser name googleId accessToken refreshToken = {name, googleId, accessToken, refreshToken}

type User = {
  id :: UserId
, googleId :: GoogleId
, name :: String
, accessToken :: GoogleAccessToken
, refreshToken :: GoogleRefreshToken
}

withId :: UserId -> NewUser -> User
withId id {googleId, name, accessToken, refreshToken} = {id, googleId, name, accessToken, refreshToken}

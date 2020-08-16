module Fundoscopic.Domain.User
( User
, NewUser
, UserId
, GoogleId
, GoogleAccessToken

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

type NewUser = {
  googleId :: GoogleId
, name :: String
, accessToken :: GoogleAccessToken
}

newUser :: String -> GoogleId -> GoogleAccessToken -> NewUser
newUser name googleId accessToken = {name, googleId, accessToken}

type User = {
  id :: UserId
, googleId :: GoogleId
, name :: String
, accessToken :: GoogleAccessToken
}

withId :: UserId -> NewUser -> User
withId id {googleId, name, accessToken} = {id, googleId, name, accessToken}

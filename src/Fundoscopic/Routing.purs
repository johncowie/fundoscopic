module Fundoscopic.Routing
( HandlerId(..)
, handlerIdForPath
, routeForHandler )
where

{- Pass handler data around, have function for registering routes (checks that they are ISOMorphic)

-}

import Fundoscopic.Prelude
-- import Data.Map as M
import Data.String as Str

-- type Routes = BiMap HandlerId (Array String)

data HandlerId = Home | Login

handlerIdForPath :: Array String -> Maybe HandlerId
handlerIdForPath ["login"] = Just Login
handlerIdForPath [] = Just Home
handlerIdForPath _ = Nothing

routeForHandler :: HandlerId -> String
routeForHandler Login = joinPath ["login"]
routeForHandler Home = joinPath []

joinPath :: Array String -> String
joinPath arr = "/" <> Str.joinWith "/" arr

-- TODO maybe use map for routes, can then validate for duplicates, how would you then use these as keys
--  maybe another map of handlers and assert they are the same, or some function for constructing handler with phantom type

-- data HandlerKey routes
--
-- handlerKey' :: forall proxy. proxy {a :: Int, b :: Int} -> SProxy -> String
-- handlerKey'

-- lookupPathForHandler :: Routes -> HandlerId -> Array String
-- lookupPathForHandler = undefined
--
-- lookupPathStrForHandler :: Routes -> HandlerId -> String
-- lookupPathStrForHandler = undefined
--
-- lookupHandlerForPath :: Array String -> Maybe HandlerId
-- lookupHandlerForPath = undefined
--
-- data BiMap a b = BiMap (M.Map a b) (M.Map b a)
--
-- addEntry :: a -> Array (String) -> Routes a -> Routes a
-- addEntry = undefined
--
-- addEntryTuple :: (Tuple a b) -> BiMap a b -> Either String (BiMap a b)
-- addEntryTuple = undefined
--
-- compileRoutes :: Array (Tuple a (Array String)) ->

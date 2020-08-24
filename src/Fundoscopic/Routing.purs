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
import HTTPure (Method(..))

-- type Routes = BiMap HandlerId (Array String)

data HandlerId = Home
               | Login
               | GoogleOAuthCallback
               | DownloadSpreadsheet
               | ShowFund String
               | AddTag
               | AddTagging
               | ListTaggings

handlerIdForPath :: Method -> Array String -> Maybe HandlerId
handlerIdForPath Get ["login"] = Just Login
handlerIdForPath Get ["google"] = Just GoogleOAuthCallback
handlerIdForPath _ ["sheet"] = Just DownloadSpreadsheet -- FIXME restrict to Post
handlerIdForPath _ ["tag"] = Just AddTag -- FIXME restrict to Post
handlerIdForPath Post ["tagging"] = Just AddTagging
handlerIdForPath Get ["tagging"] = Just ListTaggings
handlerIdForPath Get ["fund", fundName] = Just $ ShowFund fundName
handlerIdForPath Get [] = Just Home
handlerIdForPath _ _ = Nothing

routeForHandler :: HandlerId -> String
routeForHandler Login = joinPath ["login"]
routeForHandler GoogleOAuthCallback = joinPath ["google"]
routeForHandler DownloadSpreadsheet  = joinPath ["sheet"]
routeForHandler AddTag = joinPath ["tag"]
routeForHandler AddTagging = joinPath ["tagging"]
routeForHandler ListTaggings = joinPath ["tagging"]
routeForHandler (ShowFund fundName) = joinPath ["fund", fundName]
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

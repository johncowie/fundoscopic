module Fundoscopic.Routing where

data HandlerId = HelloWorld | NotFound | Login

handlerIdForPath :: Array String -> HandlerId
handlerIdForPath ["login"] = Login
handlerIdForPath [] = HelloWorld
handlerIdForPath _ = NotFound

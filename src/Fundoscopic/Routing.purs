module Fundoscopic.Routing where

data HandlerId = HelloWorld | NotFound

handlerIdForPath :: Array String -> HandlerId
handlerIdForPath [] = HelloWorld
handlerIdForPath _ = NotFound

module Fundoscopic.Middleware.Log where

import Fundoscopic.Prelude
import JohnCowie.HTTPure(BasicRequest)
import Effect.Console as Console

wrapLogRequest :: forall res a. (Show a) => (BasicRequest a -> Aff res) -> BasicRequest a -> Aff res
wrapLogRequest handler req = do
  liftEffect $ Console.log $ show $ unwrap req
  handler req

module Fundoscopic.Prelude
( module Prelude
, module Data.Bifunctor
, module Data.Either
, module Data.Maybe
, module Data.Tuple
, module Control.Monad.Except.Trans
, module Effect
, module Effect.Aff
, module Effect.Class
)
where

import Prelude

import Data.Bifunctor (lmap)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Data.Tuple (Tuple(..))

import Control.Monad.Except.Trans (ExceptT(..), runExceptT)

import Effect (Effect)
import Effect.Aff (Aff, launchAff_)
import Effect.Class (liftEffect)

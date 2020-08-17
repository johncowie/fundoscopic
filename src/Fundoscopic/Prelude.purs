module Fundoscopic.Prelude
( module Prelude
, module Data.Bifunctor
, module Data.Either
, module Data.Maybe
, module Data.List
, module Data.Traversable
, module Data.Tuple
, module Data.Tuple.Nested
, module Data.Newtype
, module Data.TemplateString
, module Control.Monad.Except.Trans
, module Effect
, module Effect.Aff
, module Effect.Class

, undefined
, console
)
where

import Prelude

import Data.Bifunctor (lmap)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Data.List (List(..), (:))
import Data.Traversable (class Traversable)
import Data.Tuple (Tuple(..))
import Data.Tuple.Nested (type (/\), (/\))
import Data.Newtype (wrap, unwrap)

import Data.TemplateString ((<^>))

import Control.Monad.Except.Trans (ExceptT(..), runExceptT)

import Effect (Effect)
import Effect.Aff (Aff, launchAff_)
import Effect.Class (liftEffect)
import Effect.Console as Console

import Effect.Exception.Unsafe (unsafeThrow)

undefined :: forall x a. x -> a
undefined _ = unsafeThrow "undefined"

console :: {log :: String -> Effect Unit, error :: String -> Effect Unit}
console = {log: Console.log, error: Console.error}

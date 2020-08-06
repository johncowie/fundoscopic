module Env where

import Prelude
import Data.Maybe (Maybe(..), fromMaybe)
import Data.Either (Either(..))
import Data.Symbol (class IsSymbol, SProxy(..))
import Prim.Row (class Cons, class Lacks) as Row
import Type.RowList (class ListToRow)
import Type.Equality (class TypeEquals, to)
import Prim.RowList (class RowToList, kind RowList, Cons, Nil)
import Type.Data.RowList (RLProxy(..))
import Data.Int as Int
import Data.String as Str
import Data.Bifunctor (lmap)

import Foreign.Object (Object, lookup)

import Record as Record

import Node.Process (getEnv)
import Chalk as Chalk
import Effect (Effect)
import Effect.Console as Console

type Env = Object String

data Var t = Var { varName :: String
                 , parser :: String -> Either String t
                 , description :: Maybe String
                 , default :: Maybe t
                 , showDefault :: t -> Maybe String
                 }

type VarInfo = { varName :: String
               , description :: Maybe String
               , default :: Maybe String
               }

data EnvError = MissingError VarInfo
              | ParseError VarInfo String
              | EnvErrors (Array EnvError)

instance semigroupEnvError :: Semigroup EnvError where
  append (EnvErrors aErrors) (EnvErrors bErrors) = EnvErrors $ aErrors <> bErrors
  append (EnvErrors errors) err = EnvErrors $ errors <> [err]
  append err (EnvErrors errors) = EnvErrors $ [err] <> errors
  append errA errB = EnvErrors [errA, errB]

printErrorForConsole :: EnvError -> String
printErrorForConsole (EnvErrors errors) = Str.joinWith "\n" $ map printErrorForConsole errors
printErrorForConsole (MissingError {varName, description}) =
  Chalk.red $ "Missing: " <> Chalk.yellow varName <> " - " <> fromMaybe "<no-description>" description
printErrorForConsole (ParseError {varName, description} err) =
  Chalk.red $ "ParseError: " <> Chalk.yellow varName <> " - " <> err

class ParseValue v where
  parseValue :: String -> Either String v

instance parseValueInt :: ParseValue Int where
  parseValue s = case Int.fromString s of
    (Just i) -> Right i
    Nothing -> Left "Invalid int"

instance parseValueString :: ParseValue String where
  parseValue = Right

class MaybeShow t where
  maybeShow :: t -> Maybe String

instance maybeShowShow :: Show t => MaybeShow t where
  maybeShow = show >>> Just
else instance maybeShowOther :: MaybeShow a where
  maybeShow s = Nothing

var :: forall t. (MaybeShow t) => (ParseValue t) => String -> Var t
var varName = Var {varName, parser: parseValue, description: Nothing, default: Nothing, showDefault: maybeShow}

describe :: forall t. String -> Var t -> Var t
describe desc (Var r) = Var $ r {description = Just desc}

defaultTo :: forall t. t -> Var t -> Var t
defaultTo def (Var r) = Var $ r {default = Just def}

varInfo :: forall t. Var t -> VarInfo
varInfo (Var {varName, default, description, showDefault})
  = {varName, description, default: default >>= showDefault}

-- TODO support maybe (need another type class for this)
-- TODO add description to error?
readValueFromEnv :: forall t. Var t -> Object String -> Either EnvError t
readValueFromEnv v@(Var {varName, parser, default}) env = do
  case lookup varName env of
    (Just str) -> lmap (ParseError (varInfo v)) $ parser str
    Nothing -> case default of
      (Just def) -> Right def
      Nothing -> Left $ MissingError (varInfo v)

class Compiler (el :: RowList) (rl :: RowList) (e :: # Type) (r :: # Type) | el -> rl, e -> r where
  compileParser :: forall proxy. proxy el -> proxy rl -> (Record e) -> Object String -> Either EnvError (Record r)

instance compilerCons ::
  ( IsSymbol l
  , Row.Lacks l rt
  , Row.Lacks l pt
  , ListToRow rlt rt
  , ListToRow plt pt
  , Row.Cons l (Var t) pt p
  , Row.Cons l t rt r
  , Compiler plt rlt pt rt
  ) => Compiler (Cons l (Var t) plt) (Cons l t rlt) p r where
    compileParser _ _ vars env = insert value tail
      where name = (SProxy :: SProxy l)
            (var :: Var t) = Record.get name vars
            value = readValueFromEnv var env
            varsTail = Record.delete name vars
            tail = compileParser (RLProxy :: RLProxy plt) (RLProxy :: RLProxy rlt) varsTail env

            insert (Left valueErr) (Left tailErrs) = Left $ valueErr <> tailErrs
            insert valE tailE = Record.insert name <$> valE <*> tailE

instance compilerNil :: (TypeEquals {} (Record r), TypeEquals {} (Record p)) => Compiler Nil Nil p r where
  compileParser _ _ _ _ = pure $ to {}

class ReadEnv (e :: # Type) (r :: # Type) where
  readEnv :: (Record e) -> Object String -> Either EnvError (Record r)

instance readEnvImpl ::
  ( RowToList e el
  , RowToList r rl
  , Compiler el rl e r
  , ListToRow rl r
  , ListToRow el l
  ) => ReadEnv e r where
    readEnv = compileParser (RLProxy :: RLProxy el) (RLProxy :: RLProxy rl)

exampleParser2 :: Object String -> Either EnvError {a :: Int, c :: Int, b :: String}
exampleParser2 = readEnv { a: var "BILL" # describe "Bill is an int" # defaultTo 7
                         , b: var "BEN" # describe "Ben is a string"
                         , c: var "BOB_BOB" # describe "Bob bob is the feckin best" }

-- TODO function for merging parsers
-- TODO how to document parsers?
-- TODO more specific error type with VAR info
-- TODO can support nested?

main :: Effect Unit
main = do
  env <- getEnv
  case exampleParser2 env of
    (Left err) -> Console.error (printErrorForConsole err)
    (Right val) -> Console.log (show val)

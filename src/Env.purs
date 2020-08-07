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
import Effect.Exception.Unsafe (unsafeThrow)

type Env = Object String

data Var t = Var { varName :: String
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

var :: forall t. (MaybeShow t) => (ReadValue t) => String -> Var t
var varName = Var {varName, description: Nothing, default: Nothing, showDefault: maybeShow}

describe :: forall t. String -> Var t -> Var t
describe desc (Var r) = Var $ r {description = Just desc}

defaultTo :: forall t. t -> Var t -> Var t
defaultTo def (Var r) = Var $ r {default = Just def}

varInfo :: forall t. Var t -> VarInfo
varInfo (Var {varName, default, description, showDefault})
  = {varName, description, default: default >>= showDefault}

class ReadValue t where
  readValue :: VarInfo -> Maybe t -> Maybe String -> Either EnvError t

instance readValueMaybe :: (ParseValue t) => ReadValue (Maybe t) where
  readValue info default (Just str) = map Just $ lmap (ParseError info) $ parseValue str
  readValue info default Nothing =
    case default of
      (Just def) -> Right def
      Nothing -> Right Nothing
else instance readValueAll :: (ParseValue t) => ReadValue t where
  readValue info default (Just str) = lmap (ParseError info) $ parseValue str
  readValue info default Nothing =
    case default of
      (Just def) -> Right def
      Nothing -> Left $ MissingError info

readValueFromEnv :: forall t. (ReadValue t) => Var t -> Object String -> Either EnvError t
readValueFromEnv v@(Var {varName, default}) env = readValue (varInfo v) default $ lookup varName env

-- TODO rename this typeclass
class Compiler (el :: RowList) (rl :: RowList) (e :: # Type) (r :: # Type) where
  compileParser :: forall proxy. proxy el -> proxy rl -> (Record e) -> Object String -> Either EnvError (Record r)

instance compilerResultsNil :: (TypeEquals {} (Record r)) => Compiler pl Nil p r where
  compileParser _ _ _ _ = pure $ to {}
else instance compilerCons ::
  ( IsSymbol l
  , ReadValue t
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
else instance compilerConsSubVars ::
  ( IsSymbol l
  , Row.Lacks l rt
  , Row.Lacks l pt
  , ListToRow rlt rt
  , ListToRow plt pt
  , RowToList v vlt
  , RowToList t tlt
  , ListToRow vlt v
  , ListToRow tlt t
  , ReadEnv v t
  , Row.Cons l (Record v) pt p
  , Row.Cons l (Record t) rt r
  , Compiler plt rlt pt rt
  , Compiler vlt tlt v t
  ) => Compiler (Cons l (Record v) plt) (Cons l (Record t) rlt) p r where
    compileParser _ _ vars env = insert value tail
      where name = (SProxy :: SProxy l)
            (subVars :: Record v) = Record.get name vars
            value = readEnv subVars env  -- replace with readEnv?
            varsTail = Record.delete name vars
            tail = compileParser (RLProxy :: RLProxy plt) (RLProxy :: RLProxy rlt) varsTail env

            insert (Left valueErr) (Left tailErrs) = Left $ valueErr <> tailErrs
            insert valE tailE = Record.insert name <$> valE <*> tailE

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

-- TODO type class with instances for var and record, so that sub record can also be processed
-- TODO  maybe just need another instance of Compiler where instead of Var t value, it's  a ReadEnv value?

exampleEnv :: { a :: Var Int
              , b :: Var String
              , c :: {c1 :: Var Int, c2 :: Var Int}
              , d :: Var (Maybe String)}
exampleEnv = { a: var "BILL" # describe "Bill is an int" # defaultTo 7
             , b: var "BEN" # describe "Ben is a string"
             , c: {c1: var "C1", c2: var "C2"}
             , d: var "MAYBE" # describe "Value is optional"}

-- TODO Should you be able to read a subset of values?  means the result type declaration is required when using..
exampleParser :: Object String -> Either EnvError {a :: Int, b :: String, c :: {c1 :: Int, c2 :: Int}}
exampleParser = readEnv exampleEnv

blah :: {a :: Int, b :: String}
blah = Record.merge {a: 1} {b: ""}

-- TODO function for merging parsers  (basically Record.Merge)
-- TODO how to document parsers?
-- TODO can support nested?
-- TODO support parser override? (supply parser to readMaybeValue)

main :: Effect Unit
main = do
  env <- getEnv
  case exampleParser env of
    (Left err) -> Console.error (printErrorForConsole err)
    (Right val) -> Console.log (show val)

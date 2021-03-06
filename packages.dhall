{-
Welcome to your new Dhall package-set!

Below are instructions for how to edit this file for most use
cases, so that you don't need to know Dhall to use it.

## Warning: Don't Move This Top-Level Comment!

Due to how `dhall format` currently works, this comment's
instructions cannot appear near corresponding sections below
because `dhall format` will delete the comment. However,
it will not delete a top-level comment like this one.

## Use Cases

Most will want to do one or both of these options:
1. Override/Patch a package's dependency
2. Add a package not already in the default package set

This file will continue to work whether you use one or both options.
Instructions for each option are explained below.

### Overriding/Patching a package

Purpose:
- Change a package's dependency to a newer/older release than the
    default package set's release
- Use your own modified version of some dependency that may
    include new API, changed API, removed API by
    using your custom git repo of the library rather than
    the package set's repo

Syntax:
Replace the overrides' "{=}" (an empty record) with the following idea
The "//" or "⫽" means "merge these two records and
  when they have the same value, use the one on the right:"
-------------------------------
let overrides =
  { packageName =
      upstream.packageName // { updateEntity1 = "new value", updateEntity2 = "new value" }
  , packageName =
      upstream.packageName // { version = "v4.0.0" }
  , packageName =
      upstream.packageName // { repo = "https://www.example.com/path/to/new/repo.git" }
  }
-------------------------------

Example:
-------------------------------
let overrides =
  { halogen =
      upstream.halogen // { version = "master" }
  , halogen-vdom =
      upstream.halogen-vdom // { version = "v4.0.0" }
  }
-------------------------------

### Additions

Purpose:
- Add packages that aren't already included in the default package set

Syntax:
Replace the additions' "{=}" (an empty record) with the following idea:
-------------------------------
let additions =
  { package-name =
       { dependencies =
           [ "dependency1"
           , "dependency2"
           ]
       , repo =
           "https://example.com/path/to/git/repo.git"
       , version =
           "tag ('v4.0.0') or branch ('master')"
       }
  , package-name =
       { dependencies =
           [ "dependency1"
           , "dependency2"
           ]
       , repo =
           "https://example.com/path/to/git/repo.git"
       , version =
           "tag ('v4.0.0') or branch ('master')"
       }
  , etc.
  }
-------------------------------

Example:
-------------------------------
let additions =
  { benchotron =
      { dependencies =
          [ "arrays"
          , "exists"
          , "profunctor"
          , "strings"
          , "quickcheck"
          , "lcg"
          , "transformers"
          , "foldable-traversable"
          , "exceptions"
          , "node-fs"
          , "node-buffer"
          , "node-readline"
          , "datetime"
          , "now"
          ]
      , repo =
          "https://github.com/hdgarrood/purescript-benchotron.git"
      , version =
          "v7.0.0"
      }
  }
-------------------------------
-}


let upstream =
      https://github.com/purescript/package-sets/releases/download/psc-0.13.8-20200724/packages.dhall sha256:bb941d30820a49345a0e88937094d2b9983d939c9fd3a46969b85ce44953d7d9

let additions =
      { postgresql-client =
          { dependencies =
            [ "bytestrings"
            , "exceptions"
            , "newtype"
            , "effect"
            , "console"
            , "either"
            , "foreign-generic"
            , "arrays"
            , "maybe"
            , "argonaut"
            , "foreign-object"
            , "aff"
            , "foldable-traversable"
            , "prelude"
            , "bifunctors"
            , "assert"
            , "test-unit"
            , "transformers"
            , "decimals"
            , "js-date"
            , "psci-support"
            , "tuples"
            , "foreign"
            , "lists"
            , "nullable"
            ]
          , repo =
              "https://github.com/rightfold/purescript-postgresql-client.git"
          , version = "v3.0.2"
          }
      , template-strings =
          { dependencies = [ "tuples", "functions" ]
          , repo = "https://github.com/purescripters/purescript-template-strings"
          , version = "v5.1.0"
          }
      , envisage =
          { dependencies =
            [ "console"
            , "effect"
            , "integers"
            , "node-process"
            , "numbers"
            , "prelude"
            , "psci-support"
            , "record"
            , "strings"
            , "transformers"
            ]
          , repo = "https://github.com/johncowie/purescript-envisage.git"
          , version = "v0.0.5"
       }
      , johncowie-bricker =
          { dependencies =
            [ "aff"
            , "console"
            , "crypto"
            , "effect"
            , "node-child-process"
            , "node-fs"
            , "node-process"
            , "psci-support"
            ]
            , repo = "https://github.com/johncowie/purescript-johncowie-bricker.git"
            , version = "v0.0.1"
          }
      , johncowie-stuff =
          { dependencies =
            [ "affjax"
            , "b64"
            , "biscotti-cookie"
            , "console"
            , "crypto"
            , "effect"
            , "envisage"
            , "form-urlencoded"
            , "http-methods"
            , "httpure"
            , "parsing"
            , "postgresql-client"
            , "psci-support"
            , "uri"
            ]
            , repo = "https://github.com/johncowie/purescript-johncowie-stuff.git"
            , version = "v0.0.9"
          }
      }


let overrides =
      { johncowie-stuff = ../purescript-johncowie-stuff/spago.dhall as Location
      }

in  upstream // additions // overrides

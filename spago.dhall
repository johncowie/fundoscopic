{-
Welcome to a Spago project!
You can edit this file as you like.
-}
{ name = "my-project"
, dependencies =
  [ "biscotti-cookie"
  , "console"
  , "effect"
  , "envisage"
  , "httpure"
  , "johncowie-bricker"
  , "johncowie-stuff"
  , "node-process"
  , "prelude"
  , "psci-support"
  , "record"
  , "smolder"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs", "test/**/*.purs" ]
}

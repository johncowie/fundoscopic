{-
Welcome to a Spago project!
You can edit this file as you like.
-}
{ name = "my-project"
, dependencies =
  [ "biscotti-cookie"
  , "console"
  , "effect"
  , "httpure"
  , "johncowie-httpure"
  , "prelude"
  , "psci-support"
  , "smolder"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs", "test/**/*.purs" ]
}

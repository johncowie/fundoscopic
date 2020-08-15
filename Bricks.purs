module Bricks where

import Prelude
import Bricker (chainTasks, cmd, compileTasks)
import Data.Either (Either(..))
import Data.String (toLower)
import Effect (Effect)
import Effect.Aff (launchAff_)

lowercaseId :: String -> Either String String
lowercaseId s = Right (toLower s)

main :: Effect Unit
main =
  launchAff_
    $ compileTasks lowercaseId do
        chainTasks "build" [ "clean", "build-html", "build-js", "deploy" ]
        cmd "setup-deploy-branch" """
          git branch -D server-dist || echo "no branch" &&
          git checkout --orphan server-dist &&
          git reset --hard && git commit --allow-empty -m "Init" &&
          git checkout master &&
          rm -rf server-dist &&
          git worktree add server-dist server-dist
        """
        cmd "clean-server" "rm -f server-dist/*.js"
        cmd "build-server" "spago bundle-app --main Main --to server-dist/server.js"
        cmd "bundle-server" "npx noderify server-dist/server.js -o server-dist/server.bundle.js"
        {- mkdir server-dist && git worktree add -b server-dist /server-dist
              to get this working
              plus for heroku add a package.json and Procfile
               -}
        cmd "deploy-server" """cd server-dist && git add . && git commit --allow-empty -m "New build" && git push -f heroku server-dist:master"""
        chainTasks "release-server" [ "clean-server", "build-server", "bundle-server", "deploy-server" ]

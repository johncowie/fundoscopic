module Fundoscopic.Data.Paging where

import Fundoscopic.Prelude
import Fundoscopic.Wrapper (Wrapper)

type Limit = Wrapper "Limit" Int
type Offset = Wrapper "Offset" Int

type Paging = {limit :: Limit, offset :: Offset}

mkPaging :: Int -> Int -> Paging
mkPaging limit offset = {limit: wrap limit, offset: wrap offset}

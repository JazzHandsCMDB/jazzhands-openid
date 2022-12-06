--
-- Copyright (c) 2021-2022 Todd Kover
-- All rights reserved.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

--
-- This is what was used to create everything from scratch the very 
-- first time.
--

\set ON_ERROR_STOP
\pset pager off

\ir create_scaffolding.sql

SAVEPOINT scaffolding;

set role jazzhands_openid;
set search_path=jazzhands_openid;
\ir create/ddl.sql

SAVEPOINT ddl;

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

\set ON_ERROR_STOP

SELECT schema_support.begin_maintenance();

-- rollback to prepostgrest;
set role=none;

----------------------------------------------------------------------------
---
--- Setup views and things
---
----------------------------------------------------------------------------

\ir database/create_all.sql

----------------------------------------------------------------------------
---
--- Setup properties and whatnot for views and things to work
---
----------------------------------------------------------------------------

set role=jazzhands;
set search_path=jazzhands;

\ir prep.sql

----------------------------------------------------------------------------
---
--- Setup minter database user and grants
---
----------------------------------------------------------------------------

SET role=none;
SET search_path=jazzhands_openid;

DO $$
BEGIN
	CREATE USER app_jazzhands_openid_jwt_minter IN GROUP all_app_users;
	ALTER USER app_jazzhands_openid_jwt_minter
	SET search_path = 'jazzhands_openid';
EXCEPTION WHEN duplicate_object THEN
	RAISE NOTICE 'Roles already exist.';
END;
$$;

\ir minter-grants.sql

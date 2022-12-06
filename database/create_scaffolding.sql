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
--
-- This is meant to be rerun if nothing changes.  It won't destroy anything.
--
-- runs as postgres (superuser, really)
--
\set ON_ERROR_STOP 

DO $$
BEGIN
	CREATE USER jazzhands_openid IN GROUP schema_owners;
	RAISE NOTICE 'created jazzhands_openid';
EXCEPTION WHEN duplicate_object THEN
	RAISE NOTICE 'jazzhands_openid already exists, skipping create';
END;
$$;

ALTER USER jazzhands_openid SET search_path=jazzhands_openid;

GRANT EXECUTE ON FUNCTION jazzhands.validate_json_schema(schema jsonb, data jsonb, root_schema jsonb) TO jazzhands_openid;

DO $$
DECLARE
        _tal INTEGER;
BEGIN
        select count(*)
        from pg_catalog.pg_namespace
        into _tal
        where nspname = 'jazzhands_openid';
        IF _tal = 0 THEN
                DROP SCHEMA IF EXISTS jazzhands_openid;
                CREATE SCHEMA jazzhands_openid AUTHORIZATION jazzhands_openid;
                COMMENT ON SCHEMA jazzhands_openid IS 'jazzhands stuff';

        END IF;
END;
$$;

GRANT pgcrypto_roles TO jazzhands_openid;
GRANT USAGE ON schema jazzhands TO jazzhands_openid;
GRANT SELECT ON jazzhands.account TO jazzhands_openid;
GRANT SELECT ON jazzhands.account_collection_account TO jazzhands_openid;
GRANT SELECT ON jazzhands.private_key TO jazzhands_openid;
GRANT SELECT ON jazzhands.property TO jazzhands_openid;
GRANT SELECT ON jazzhands.service TO jazzhands_openid;
GRANT SELECT ON jazzhands.service_version TO jazzhands_openid;
GRANT SELECT ON jazzhands.service_version_collection TO jazzhands_openid;
GRANT SELECT ON jazzhands.service_version_collection_service_version TO jazzhands_openid;
GRANT SELECT ON jazzhands.v_account_collection_hier_from_ancestor TO jazzhands_openid;
GRANT SELECT ON jazzhands.service_instance TO jazzhands_openid;
GRANT SELECT ON jazzhands.v_service_endpoint_service_instance TO jazzhands_openid;
GRANT SELECT ON jazzhands.v_service_endpoint_expanded TO jazzhands_openid;

GRANT SELECT ON jazzhands.v_device_collection_hier_from_ancestor TO jazzhands_openid;
GRANT SELECT ON jazzhands.device_collection_device TO jazzhands_openid;
GRANT SELECT ON jazzhands.device TO jazzhands_openid;

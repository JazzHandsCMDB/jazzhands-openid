--
-- Copyright (c) 2021-2023 Todd Kover
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
-- This covers which password methods are allowed for which users.  This implies
-- permission to get a JWT
--
CREATE OR REPLACE VIEW jazzhands_openid.authentication_rules AS
SELECT	DISTINCT service_id,
	service_endpoint_uri,
	lhs.login,
	property_value_json->>'method' as permitted_authentication_method,
	concat(property_value_json->>'prefix', lhs.login,
		property_value_json->>'suffix')
		AS translated_login,
	property_value_json->>'max_token_lifetime' as max_token_lifetime
FROM jazzhands.property
	JOIN jazzhands.service_version_collection USING (service_version_collection_id)
	JOIN jazzhands.service_version_collection_service_version USING (service_version_collection_id)
	JOIN jazzhands.service_version USING (service_version_id)
	JOIN jazzhands.service_instance USING (service_version_id)
	JOIN jazzhands.v_service_endpoint_service_instance USING (service_instance_id)
	JOIN jazzhands.v_service_endpoint_expanded USING (service_endpoint_id, service_id)
	JOIN (
		SELECT root_account_collection_id AS account_collection_id,
			account_id,  login
		FROM jazzhands.v_account_collection_hier_from_ancestor
			JOIN jazzhands.account_collection_account USING (account_collection_id)
			JOIN jazzhands.account USING (account_id)
		WHERE account.is_enabled
	) lhs USING (account_collection_id)
WHERE property_type = 'jazzhands-openid'
AND property_name = 'authentication-rules'
;


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
-- This covers if a user is able to act as another user
-- The prefix/suffix stuff is kind of BS but it's the best way to
-- abstract it out, unfortunately.
--
CREATE OR REPLACE VIEW jazzhands_openid.permitted_account_impersonation AS
SELECT	DISTINCT service_id,
	service_endpoint_uri,
	lhs.login,
	rhs.login AS actas,
	concat(prefix, rhs.login, suffix) AS translated_actas
FROM jazzhands.property
	JOIN jazzhands.service_version_collection USING (service_version_collection_id)
	JOIN jazzhands.service_version_collection_service_version USING (service_version_collection_id)
	JOIN jazzhands.service_version USING (service_version_id)
	JOIN jazzhands.service_instance USING (service_version_id)
	JOIN jazzhands.v_service_endpoint_service_instance USING (service_instance_id)
	JOIN jazzhands.v_service_endpoint_expanded USING (service_id, service_endpoint_id)
	JOIN (
		SELECT root_account_collection_id AS account_collection_id,
			account_id,  login
		FROM jazzhands.v_account_collection_hier_from_ancestor
			JOIN jazzhands.account_collection_account USING (account_collection_id)
			JOIN jazzhands.account USING (account_id)
		WHERE account.is_enabled
	) lhs USING (account_collection_id)
	JOIN (
		SELECT root_account_collection_id AS property_value_account_collection_id,
			account_id,  login
		FROM jazzhands.v_account_collection_hier_from_ancestor
			JOIN jazzhands.account_collection_account USING (account_collection_id)
			JOIN jazzhands.account USING (account_id)
		WHERE account.is_enabled
	) rhs USING (property_value_account_collection_id)
	LEFT JOIN (
		SELECT account_collection_id,
				min(property_value)	FILTER
					(WHERE property_name = 'act-as-account-prefix')
					AS prefix,
				max(property_value)	FILTER
					(WHERE property_name = 'act-as-account-suffix')
					AS suffix
		FROM jazzhands.property
		WHERE property_name IN ('act-as-account-suffix','act-as-account-prefix')
		AND property_type = 'jazzhands-openid'
		GROUP BY account_collection_id
	) xl USING (account_collection_id)
WHERE property_type = 'jazzhands-openid'
AND property_name = 'act-as-account'
;


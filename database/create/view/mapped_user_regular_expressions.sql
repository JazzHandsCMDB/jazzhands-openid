--
-- Copyright (c) 2023 Todd Kover
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
-- regular expressions to identify users that are mapped here.
--
-- This can/is used to manage users that are created in the db for
-- database access but the only access is the openid connect infrastructure.
--
CREATE OR REPLACE VIEW jazzhands_openid.mapped_user_regular_expressions (r) AS
	SELECT concat ('^', property_value_json->>'prefix')
	FROM  jazzhands.property
	WHERE property_name = 'authentication-rules'
	AND property_type = 'jazzhands-openid'
	AND property_value_json ? 'prefix'
	AND length(property_value_json->>'prefix') > 0
UNION
	SELECT concat (property_value_json->>'suffix', '$')
	FROM  jazzhands.property
	WHERE property_name = 'authentication-rules'
	AND property_type = 'jazzhands-openid'
	AND property_value_json ? 'suffix'
	AND length(property_value_json->>'suffix') > 0
UNION
	SELECT concat ('^', property_value)
	FROM jazzhands.property
	WHERE property_name = 'act-as-account-prefix'
	AND property_type = 'jazzhands-openid'
UNION
	SELECT concat (property_value_json->>'prefix', '$') AS r
	FROM jazzhands.property
	WHERE property_name = 'act-as-account-suffix'
	AND property_type = 'jazzhands-openid'

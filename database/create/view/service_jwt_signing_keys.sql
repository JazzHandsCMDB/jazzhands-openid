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
-- private key used for signing JWTs
--
CREATE OR REPLACE VIEW jazzhands_openid.service_jwt_signing_keys AS
SELECT	service_endpoint_uri, pk.*
FROM jazzhands.property p
	JOIN jazzhands.service_version_collection USING (service_version_collection_id)
	JOIN jazzhands.service_version_collection_service_version USING (service_version_collection_id)
	JOIN jazzhands.service_version USING (service_version_id)
	JOIN jazzhands.service_instance USING (service_version_id)
	JOIN jazzhands.v_service_endpoint_service_instance USING (service_instance_id)
	JOIN jazzhands.v_service_endpoint_expanded USING (service_endpoint_id)
	JOIN jazzhands.private_key pk ON
		p.property_value_private_key_id = pk.private_key_id
WHERE property_type = 'jazzhands-openid'
AND property_name = 'jwt-signer';


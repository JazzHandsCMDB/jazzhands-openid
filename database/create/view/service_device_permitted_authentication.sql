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
-- devices that can authenticate for this service
--
CREATE OR REPLACE VIEW jazzhands_openid.service_device_permitted_authentication AS
SELECT	service_id, service_endpoint_uri,
	dcd.device_id,
	device_name,
	property_value_json->>'role' AS device_role,
	property_value_json->>'max_token_lifetime' AS max_token_lifetime
FROM jazzhands.property p
	JOIN (
		SELECT root_device_collection_id AS device_collection_id,
			device_id, device_name
		FROM jazzhands.v_device_collection_hier_from_ancestor
			JOIN jazzhands.device_collection_device USING (device_collection_id)
			JOIN jazzhands.device USING (device_id)
	) dcd USING (device_collection_id)
	JOIN jazzhands.service_version_collection USING (service_version_collection_id)
	JOIN jazzhands.service_version_collection_service_version USING (service_version_collection_id)
	JOIN jazzhands.service_version USING (service_version_id)
	JOIN jazzhands.service_instance USING (service_version_id)
	JOIN jazzhands.v_service_endpoint_service_instance USING (service_instance_id)
	JOIN jazzhands.v_service_endpoint_expanded USING (service_id, service_endpoint_id)
WHERE property_type = 'jazzhands-openid'
AND property_name = 'permit-device-authentication';


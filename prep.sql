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

-------------------------------------------------------------------------

INSERT INTO val_property_type (property_type, description)
VALUES (
	'jazzhands-openid', 'properties for openid authentication'
);

DO $$
BEGIN
	INSERT INTO val_encryption_method (
		encryption_method, description
	) VALUES (
		'external', 'encryption is handled completely outside the database'
	);
EXCEPTION WHEN not_null_violation THEN
	RAISE NOTICE 'At least jazzhands 0.96';
	INSERT INTO val_encryption_method (
		encryption_method, description,
		cipher, key_size, cipher_chain_mode,
		cipher_padding, passphrase_cryptographic_hash_algorithm
	) VALUES (
		'external', 'encryption is handled completely outside the database',
		'none', 0, 'none', 'none', 'none'
	);
END;
$$;

INSERT INTO val_property (
	property_type, property_name, permit_service_version_collection_id,
	property_data_type
) VALUES (
	'jazzhands-openid', 'jwt-signer', 'REQUIRED', 'private_key_id'
);

-------------------------------------------------------------------------
-- authentication rules
-------------------------------------------------------------------------

INSERT INTO val_property  (
	property_type, property_name, permit_service_version_collection_id,
	permit_account_collection_id, property_data_type,
	property_value_json_schema
 ) VALUES (
	'jazzhands-openid', 'authentication-rules', 'REQUIRED',
	'REQUIRED', 'json', '{
		"type": "object",
		"title": "account authoriztaion properties",
		"$schema": "http://json-schema.org/draft-06/schema#",
		"required": [
			"method"
		],
		"properties": {
			"method": {
				"type": "string",
				"enum": [ "negotiate", "password" ]
			},
			"prefix": {
				"type": "string"
			},
			"suffix": {
				"type": "string"
			},
			"max_token_lifetime": {
				"type": "integer"
			}
		},
	"description": "permission and rules for authenticating users and granting JWT"
	}'
);

-------------------------------------------------------------------------
-- allowed to act as someone else
-------------------------------------------------------------------------

--This sucks but specifies what prefix to assume when acting as someone
INSERT INTO val_property  (
	property_type, property_name, permit_service_version_collection_id,
	permit_account_collection_id, property_data_type
) VALUES (
	'jazzhands-openid', 'act-as-account-prefix', 'REQUIRED',
	'REQUIRED', 'string'
);

INSERT INTO val_property  (
	property_type, property_name, permit_service_version_collection_id,
	permit_account_collection_id, property_data_type
) VALUES (
	'jazzhands-openid', 'act-as-account-suffix', 'REQUIRED',
	'REQUIRED', 'string'
);

INSERT INTO val_property  (
	property_type, property_name, permit_service_version_collection_id,
	permit_account_collection_id, property_data_type
) VALUES (
	'jazzhands-openid', 'act-as-account', 'REQUIRED', 
	'REQUIRED', 'account_collection_id'
);

-------------------------------------------------------------------------
-- act as devices
-------------------------------------------------------------------------

INSERT INTO val_property  (
	property_type, property_name, permit_service_version_collection_id,
	permit_account_collection_id, property_data_type
) VALUES (
	'jazzhands-openid', 'act-as-device', 'REQUIRED', 
	'REQUIRED', 'device_collection_id'
);

-------------------------------------------------------------------------
-- allow devices to authenticate to services
-------------------------------------------------------------------------

-- The RHS should really include a per-account account collection that points
-- to the role, but those would need to be in the database..
INSERT INTO val_property  (
	property_type, property_name, permit_service_version_collection_id,
	permit_device_collection_id, property_data_type, property_value_json_schema
) VALUES (
	'jazzhands-openid', 'permit-device-authentication', 'REQUIRED', 
	'REQUIRED', 'json', '{
		"type": "object",
		"title": "Device Authentication Permissions",
		"$schema": "http://json-schema.org/draft-06/schema#",
		"required": [
			"role"
		],
		"properties": {
			"role": {
				"type": "string"
			},
			"max_token_lifetime": {
				"type": "integer"
			}
		},
	"description": "defines how devices authenticate and use services"
	}'
);

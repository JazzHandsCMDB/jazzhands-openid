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

grant USAGE on SCHEMA jazzhands_openid TO app_jazzhands_openid_jwt_minter;

GRANT SELECT ON jazzhands_openid.authentication_rules
	TO app_jazzhands_openid_jwt_minter;
GRANT SELECT ON jazzhands_openid.service_jwt_signing_keys
	TO app_jazzhands_openid_jwt_minter;
GRANT SELECT ON jazzhands_openid.permitted_account_impersonation
	TO app_jazzhands_openid_jwt_minter;
GRANT SELECT ON jazzhands_openid.permitted_device_impersonation
	TO app_jazzhands_openid_jwt_minter;
GRANT SELECT ON jazzhands_openid.service_device_permitted_authentication
	TO app_jazzhands_openid_jwt_minter;

GRANT USAGE ON SCHEMA obfuscation_utils TO app_jazzhands_openid_jwt_minter;
GRANT USAGE ON SCHEMA account_password_manip TO app_jazzhands_openid_jwt_minter;

GRANT EXECUTE ON FUNCTION obfuscation_utils.get_session_secret(label TEXT)
	TO app_jazzhands_openid_jwt_minter;
GRANT EXECUTE ON FUNCTION account_password_manip.authenticate_account(account_id integer, password text, encode_method text, label text, raiseexception boolean)
	TO app_jazzhands_openid_jwt_minter;

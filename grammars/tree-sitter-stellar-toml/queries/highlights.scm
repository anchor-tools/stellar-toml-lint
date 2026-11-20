; SEP-1 table and array-of-table headers.
(table
  name: (bare_key) @namespace)

(array_table
  name: (bare_key) @namespace)

; The tables a stellar.toml is built from.
((bare_key) @type.builtin
  (#match? @type.builtin "^(DOCUMENTATION|PRINCIPALS|CURRENCIES|VALIDATORS|SERVERS)$"))

; Global SEP-1 keys and the fields that identify an anchor's assets, accounts,
; and validators. Everything else remains a normal TOML property.
((bare_key) @property
  (#match? @property "^(VERSION|NETWORK_PASSPHRASE|HORIZON_URL|ACCOUNTS|FEDERATION_SERVER|AUTH_SERVER|TRANSFER_SERVER|TRANSFER_SERVER_SEP0024|KYC_SERVER|WEB_AUTH_ENDPOINT|WEB_AUTH_CONTRACT_ID|WEB_AUTH_FOR_CONTRACTS_ENDPOINT|DIRECT_PAYMENT_SERVER|ANCHOR_QUOTE_SERVER|SIGNING_KEY|URI_REQUEST_SIGNING_KEY)$"))

((bare_key) @property
  (#match? @property "^(code|issuer|contract|status|display_decimals|name|desc|conditions|image|fixed_number|max_number|is_unlimited|is_asset_anchored|anchor_asset_type|anchor_asset|attestation_of_reserve|redemption_instructions|collateral_addresses|collateral_address_messages|collateral_address_signatures|regulated|approval_server|approval_criteria|toml|ALIAS|DISPLAY_NAME|PUBLIC_KEY|HOST|HISTORY|ORG_NAME|ORG_DBA|ORG_URL|ORG_LOGO|ORG_DESCRIPTION|ORG_PHYSICAL_ADDRESS|ORG_PHONE_NUMBER|ORG_KEYBASE|ORG_TWITTER|ORG_GITHUB|ORG_OFFICIAL_EMAIL|ORG_SUPPORT_EMAIL)$"))

(pair
  key: (quoted_key) @property)

(string) @string
(escape_sequence) @string.escape

(integer) @number
(float) @number
(boolean) @constant.builtin

(offset_date_time) @string.special
(local_date_time) @string.special
(local_date) @string.special
(local_time) @string.special

(comment) @comment

"," @punctuation.delimiter
"." @punctuation.delimiter
"=" @operator

"[" @punctuation.bracket
"]" @punctuation.bracket
"[[" @punctuation.bracket
"]]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket

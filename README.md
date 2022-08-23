[comment]: # "Auto-generated SOAR connector documentation"
# Sophos Endpoint Protection

Publisher: Splunk Community  
Connector Version: 1\.1\.0  
Product Vendor: Sophos  
Product Name: Sophos Endpoint Protection  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

This app supports various investigative and containment actions on Sophos Endpoint Protection

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2021-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Sophosendpint server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Sophos Endpoint Protection asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**client\_id** |  required  | string | Enter the Client ID here
**client\_secret** |  required  | password | Enter the Client Secret here

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[check updates](#action-check-updates) - Send a request to the endpoint to check for Sophos management agent software updates  
[tamper protection switch](#action-tamper-protection-switch) - Turn Tamper Protection on or off on the endpoint  
[get tamperprotection settings](#action-get-tamperprotection-settings) - Get the Tamper Protection settings for the specified endpoint  
[perform scan](#action-perform-scan) - Send a request to the specified endpoint to perform or configure a scan  
[delete endpoint](#action-delete-endpoint) - Delete the specified endpoint  
[get individual endpoint](#action-get-individual-endpoint) - Get the endpoint based on ID  
[list items](#action-list-items) - Get all allowed or blocked items  
[delete item](#action-delete-item) - Delete the specified blocked or allowed item  
[block item](#action-block-item) - Add item to blocked list  
[allow item](#action-allow-item) - Add item to allowed list  
[list sites](#action-list-sites) - Get all local sites  
[delete site](#action-delete-site) - Delete the specified local site  
[add site](#action-add-site) - Add a new local site  
[get isolation settings](#action-get-isolation-settings) - Get isolation settings for an endpoint  
[isolation switch](#action-isolation-switch) - Turn on or off endpoint isolation for multiple endpoints  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**page\_from\_key** |  optional  | The key of the item from where to fetch a page | string | 
**page\_size** |  optional  | The size of the page requested | string | 
**sort** |  optional  | Define how to sort the data \(comma separated\) | string | 
**health\_status** |  optional  | Get endpoints having any of the specified health status \(comma separated\) | string | 
**type** |  optional  | Get endpoints having any of the specified endpoint type \(comma separated\) | string | 
**tamper\_protection\_enabled** |  optional  | Tamper protection status | boolean | 
**lockdown\_status** |  optional  | Get endpoints having any of the specified lockdown statuses \(comma separated\) | string | 
**last\_seen\_before** |  optional  | Last seen after date and time \(UTC\) or duration inclusive | string | 
**last\_seen\_after** |  optional  | Last seen before date and time \(UTC\) or duration exclusive | string | 
**ids** |  optional  | Get endpoints having any of the specified ids \(comma separated\) | string | 
**fields** |  optional  | The fields to return in a partial response | string | 
**view** |  optional  | Type of view to be returned in response | string | 
**search** |  optional  | Term to search for in the specified search fields | string | 
**search\_fields** |  optional  | List of search fields for finding the given search term \(comma separated\)\. Defaults to all applicable fields | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.health\_status | string | 
action\_result\.parameter\.ids | string | 
action\_result\.parameter\.last\_seen\_after | string | 
action\_result\.parameter\.last\_seen\_before | string | 
action\_result\.parameter\.lockdown\_status | string | 
action\_result\.parameter\.page\_from\_key | string | 
action\_result\.parameter\.page\_size | string | 
action\_result\.parameter\.search | string | 
action\_result\.parameter\.search\_fields | string | 
action\_result\.parameter\.sort | string | 
action\_result\.parameter\.tamper\_protection\_enabled | string | 
action\_result\.parameter\.type | string | 
action\_result\.parameter\.view | string | 
action\_result\.data\.\*\.assignedProducts\.\*\.code | string | 
action\_result\.data\.\*\.assignedProducts\.\*\.status | string | 
action\_result\.data\.\*\.assignedProducts\.\*\.version | string | 
action\_result\.data\.\*\.associatedPerson\.id | string | 
action\_result\.data\.\*\.associatedPerson\.viaLogin | string | 
action\_result\.data\.\*\.encryption\.volumes\.\*\.status | string | 
action\_result\.data\.\*\.encryption\.volumes\.\*\.volumeId | string | 
action\_result\.data\.\*\.group\.name | string | 
action\_result\.data\.\*\.health\.overall | string | 
action\_result\.data\.\*\.health\.services\.serviceDetails\.\*\.name | string | 
action\_result\.data\.\*\.health\.services\.serviceDetails\.\*\.status | string | 
action\_result\.data\.\*\.health\.services\.status | string | 
action\_result\.data\.\*\.health\.threats\.status | string | 
action\_result\.data\.\*\.hostname | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.ipv4Addresses | string | 
action\_result\.data\.\*\.ipv6Addresses | string | 
action\_result\.data\.\*\.lastSeenAt | string | 
action\_result\.data\.\*\.lockdown\.status | string | 
action\_result\.data\.\*\.lockdown\.updateStatus | string | 
action\_result\.data\.\*\.macAddresses | string | 
action\_result\.data\.\*\.os\.build | numeric | 
action\_result\.data\.\*\.os\.isServer | boolean | 
action\_result\.data\.\*\.os\.majorVersion | numeric | 
action\_result\.data\.\*\.os\.minorVersion | numeric | 
action\_result\.data\.\*\.os\.name | string | 
action\_result\.data\.\*\.os\.platform | string | 
action\_result\.data\.\*\.tamperProtectionEnabled | boolean | 
action\_result\.data\.\*\.tenant\.id | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.total\_number\_of\_items | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'check updates'
Send a request to the endpoint to check for Sophos management agent software updates

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpointid** |  required  | The endpoint ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpointid | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.requestedAt | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.number\_of\_endpoints\_checked | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'tamper protection switch'
Turn Tamper Protection on or off on the endpoint

Type: **contain**  
Read only: **False**

Turn Tamper Protection on or off on the endpoint or generate a new Tamper Protection password\. Note that Tamper Protection can be enabled for an endpoint only if it has also been enabled globally\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpointid** |  required  | The endpoint ID | string | 
**enabled** |  optional  | Whether Tamper Protection should be turned on for the endpoint | boolean | 
**regenerate\_password** |  optional  | Whether a new Tamper Protection password should be generated | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.enabled | boolean | 
action\_result\.parameter\.endpointid | string | 
action\_result\.parameter\.regenerate\_password | boolean | 
action\_result\.data\.\*\.enabled | boolean | 
action\_result\.data\.\*\.password | password | 
action\_result\.data\.\*\.previousPasswords\.\*\.invalidatedAt | string | 
action\_result\.data\.\*\.previousPasswords\.\*\.password | password | 
action\_result\.summary\.number\_of\_endpoints\_tamperprotection\_settings\_updated | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get tamperprotection settings'
Get the Tamper Protection settings for the specified endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpointid** |  required  | The endpoint ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpointid | string | 
action\_result\.data\.\*\.enabled | boolean | 
action\_result\.data\.\*\.password | password | 
action\_result\.data\.\*\.previousPasswords\.\*\.invalidatedAt | string | 
action\_result\.data\.\*\.previousPasswords\.\*\.password | password | 
action\_result\.summary\.number\_of\_endpoints\_tamperprotection\_settings\_received | numeric | 
action\_result\.summary\.number\_of\_times\_passwords\_changed | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'perform scan'
Send a request to the specified endpoint to perform or configure a scan

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpointid** |  required  | The endpoint ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpointid | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.number\_of\_scans\_performed | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete endpoint'
Delete the specified endpoint

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpointid** |  required  | The endpoint ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpointid | string | 
action\_result\.data\.\*\.endpoint\_deleted | string | 
action\_result\.summary\.total\_endpoints\_deleted | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get individual endpoint'
Get the endpoint based on ID

Type: **contain**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpointid** |  required  | The endpoint ID | string | 
**fields** |  optional  | The fields to return in a partial response | string | 
**view** |  optional  | Type of view to be returned in response | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpointid | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.view | string | 
action\_result\.data\.\*\.assignedProducts\.\*\.code | string | 
action\_result\.data\.\*\.assignedProducts\.\*\.status | string | 
action\_result\.data\.\*\.assignedProducts\.\*\.version | string | 
action\_result\.data\.\*\.associatedPerson\.name | string | 
action\_result\.data\.\*\.associatedPerson\.viaLogin | string | 
action\_result\.data\.\*\.cloud\.instanceId | string | 
action\_result\.data\.\*\.cloud\.provider | string | 
action\_result\.data\.\*\.encryption\.volumes\.\*\.status | string | 
action\_result\.data\.\*\.encryption\.volumes\.\*\.volumeId | string | 
action\_result\.data\.\*\.group\.id | string | 
action\_result\.data\.\*\.group\.name | string | 
action\_result\.data\.\*\.health\.overall | string | 
action\_result\.data\.\*\.health\.services\.serviceDetails\.\*\.name | string | 
action\_result\.data\.\*\.health\.services\.serviceDetails\.\*\.status | string | 
action\_result\.data\.\*\.health\.services\.status | string | 
action\_result\.data\.\*\.health\.threats\.status | string | 
action\_result\.data\.\*\.hostname | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.ipv4Addresses | string | 
action\_result\.data\.\*\.ipv6Addresses | string | 
action\_result\.data\.\*\.isolation\.status | string | 
action\_result\.data\.\*\.lastSeenAt | string | 
action\_result\.data\.\*\.lockdown\.status | string | 
action\_result\.data\.\*\.lockdown\.updateStatus | string | 
action\_result\.data\.\*\.macAddresses | string | 
action\_result\.data\.\*\.os\.build | numeric | 
action\_result\.data\.\*\.os\.isServer | boolean | 
action\_result\.data\.\*\.os\.majorVersion | numeric | 
action\_result\.data\.\*\.os\.minorVersion | numeric | 
action\_result\.data\.\*\.os\.name | string | 
action\_result\.data\.\*\.os\.platform | string | 
action\_result\.data\.\*\.tamperProtectionEnabled | boolean | 
action\_result\.data\.\*\.tenant\.id | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.total\_number\_of\_items | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list items'
Get all allowed or blocked items

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**page** |  optional  | The page number to fetch, starting with 1 | numeric | 
**page\_size** |  optional  | The size of the page requested | numeric | 
**items\_type** |  required  | Specifies the type of items to be fetched\: blocked or allowed | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.items\_type | string | 
action\_result\.parameter\.page | numeric | 
action\_result\.parameter\.page\_size | numeric | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.properties\.sha256 | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.total\_number\_of\_items | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete item'
Delete the specified blocked or allowed item

Type: **correct**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**item\_id** |  required  | The item ID to be deleted | string | 
**item\_type** |  required  | Specifies the type of item to be deleted\: blocked or allowed | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.item\_id | string | 
action\_result\.parameter\.item\_type | string | 
action\_result\.data\.\*\.deleted | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block item'
Add item to blocked list

Type: **investigate**  
Read only: **True**

Block an item from exoneration by SHA256 checksum\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_name** |  required  | The file name | string | 
**path** |  required  | The path for the application | string | 
**sha256** |  required  | The SHA256 value for the application | string |  `sha256` 
**certificate\_signer** |  required  | The value saved for the certificate signer | string | 
**comment** |  required  | Comment indicating why the item should be blocked | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.certificate\_signer | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.file\_name | string | 
action\_result\.parameter\.path | string | 
action\_result\.parameter\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.properties\.certificate\_signer | string | 
action\_result\.data\.\*\.properties\.sha256 | string |  `sha256` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'allow item'
Add item to allowed list

Type: **investigate**  
Read only: **True**

Exempt an item from conviction by path, SHA256 checksum or certificate signer\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**property\_type** |  required  | Specifies the property by which an item is allowed\: path, sha256 or certificateSigner | string | 
**file\_name** |  required  | The file name | string | 
**path** |  required  | The path for the application | string | 
**sha256** |  required  | The SHA256 value for the application | string |  `sha256` 
**certificate\_signer** |  required  | The value saved for the certificate signer | string | 
**comment** |  required  | Comment indicating why the item should be allowed | string | 
**origin\_person\_id** |  optional  | Person associated with the endpoint where the item to be allowed was last seen | string | 
**origin\_endpoint\_id** |  optional  | Endpoint where the item to be allowed was last seen | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.certificate\_signer | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.file\_name | string | 
action\_result\.parameter\.origin\_endpoint\_id | string | 
action\_result\.parameter\.origin\_person\_id | string | 
action\_result\.parameter\.path | string | 
action\_result\.parameter\.property\_type | string | 
action\_result\.parameter\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.properties\.certificate\_signer | string | 
action\_result\.data\.\*\.properties\.path | string | 
action\_result\.data\.\*\.properties\.sha256 | string |  `sha256` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list sites'
Get all local sites

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**page** |  optional  | The page number to fetch, starting with 1 | numeric | 
**page\_size** |  optional  | The size of the page requested | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.page | string | 
action\_result\.parameter\.page\_size | string | 
action\_result\.data\.\*\.categoryId | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.url | string | 
action\_result\.summary\.total\_number\_of\_items | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete site'
Delete the specified local site

Type: **correct**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**site\_id** |  required  | The local site ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.site\_id | string | 
action\_result\.data\.\*\.deleted | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add site'
Add a new local site

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category\_id** |  optional  | The category Id associated with this local site | numeric | 
**tags** |  optional  | An array of tags associated with this local site setting \(comma separated\) | string | 
**url** |  required  | Local site URL | string |  `url` 
**comment** |  optional  | Comment indicating why the site should be added | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.category\_id | numeric | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.tags | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.categoryId | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get isolation settings'
Get isolation settings for an endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpoint\_id** |  required  | The endpoint ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpoint\_id | string | 
action\_result\.data\.\*\.enabled | boolean | 
action\_result\.data\.\*\.lastDisabledAt | string | 
action\_result\.data\.\*\.lastDisabledBy\.id | string | 
action\_result\.data\.\*\.lastDisabledBy\.type | string | 
action\_result\.data\.\*\.lastEnabledAt | string | 
action\_result\.data\.\*\.lastEnabledBy\.id | string | 
action\_result\.data\.\*\.lastEnabledBy\.type | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'isolation switch'
Turn on or off endpoint isolation for multiple endpoints

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** |  required  | List of endpoint IDs \(comma separated\) | string | 
**enabled** |  required  | Whether the endpoints should be isolated | boolean | 
**comment** |  optional  | Reason the endpoints should be isolated | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.enabled | string | 
action\_result\.parameter\.ids | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.isolation\.enabled | string | 
action\_result\.data\.\*\.isolation\.lastDisabledAt | string | 
action\_result\.data\.\*\.isolation\.lastDisabledBy\.id | string | 
action\_result\.data\.\*\.isolation\.lastDisabledBy\.type | string | 
action\_result\.data\.\*\.isolation\.lastEnabledAt | string | 
action\_result\.data\.\*\.isolation\.lastEnabledBy\.id | string | 
action\_result\.data\.\*\.isolation\.lastEnabledBy\.type | string | 
action\_result\.summary\.number\_of\_endpoints\_isolation\_settings\_updated | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
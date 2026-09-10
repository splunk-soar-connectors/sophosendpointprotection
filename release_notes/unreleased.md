**Unreleased**

* Fixed an intermittent connection reset (`ConnectionResetError(104)`) in `test connectivity`, caused by sending a GET request with a JSON body. The request now sends a plain GET with no body, consistent with the connector's other read actions.
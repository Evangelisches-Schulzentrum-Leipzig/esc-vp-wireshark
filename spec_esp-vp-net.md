# ESC/VP.net Protocol Specification
Link: https://ia601808.us.archive.org/8/items/manualzz-id-1050273/1050273.pdf
Revision: F
## 1. Overview
The ESC/VP.net protocol manages communication between a client (PC) and a server (Projector) over a network. It supports two modes of operation:

1. **Session-less Mode**: Uses **UDP** for device discovery and status checks.
2. **Session Mode**: Uses **TCP** for authentication and establishing a bidirectional command session.

## 2. Packet Format

### 2.1 Common Request and Response Format
The protocol uses a fixed **16-byte common part**.

| Byte Length | Type   | Value                                     | Meaning                                      |
| ----------- | ------ | ----------------------------------------- | -------------------------------------------- |
| 10          | STR    | `"ESC/VP.net"`                            | Protocol identifier                          |
| 1           | BYTE   | `0x10`                                    | Version identifier (High 4 bits: Major, Low 4 bits: Minor) |
| 1           | UCHAR  | `0..3`                                    | Type identifier: 0: NULL, 1: HELLO, 2: PASSWORD, 3: CONNECT |
| 2           | USHORT | `0x0000`                                  | Reserved for sequence number (Always 0)     |
| 1           | BYTE   | `0x00` / Status                           | Request: Always `0x00`. Response: Status code |
| 1           | UCHAR  | `0..N`                                    | Number of headers following                 |

### 2.2 Status Codes (15th Byte)
Used in response packets to indicate the result of a request.

| Code   | Status                         | Meaning                                      |
| ------ | ------------------------------ | -------------------------------------------- |
| `0x20` | OK                             | Normal termination                           |
| `0x40` | Bad Request                    | Grammar error or illegal data                |
| `0x41` | Unauthorized                   | Password required/not provided               |
| `0x43` | Forbidden                      | Password is wrong                            |
| `0x45` | Request Not Allowed            | Disallowed type request for the current mode |
| `0x53` | Service Unavailable            | Projector is BUSY                            |
| `0x55` | Version Not Supported          | Unsupported protocol version                 |

## 3. Headers
Headers follow the 16-byte common part. Each header is a **18-byte fixed length**.

### 3.1 Header Structure

| Byte Length | Type  | Value              | Meaning            |
| ----------- | ----- | ------------------ | ------------------ |
| 1           | UCHAR | `0..5`             | Header identifier  |
| 1           | UCHAR | `0..255`           | Header attribute value |
| 16          | STR   | Variable           | Header information |

### 3.2 Header Identifiers and Attributes
#### Header Identifier 1: Password / Header Identifier 2: New-Password
* **Information**: The password string.
* **Attributes**: 0 = NULL (no password), 1 = Plain (US-ASCII).

#### Header Identifier 3: Projector-Name
* **Information**: The projector name string.
* **Attributes**: 0 = NULL (no projector name), 1 = US-ASCII, 2 = Shift-JIS (Reserved), 3 = EUC-JP (Reserved).

#### Header Identifier 4: IM-Type (Projector Model)
* **Information**: Cannot be described (set all to `0x00`).
* **Attributes**:
  * `10-15` (Reserved)
  * `16-19` Type A
  * `17-19` (Reserved)
  * `0C` Type D
  * `20` Initial model of EMP/PL-735 
  * `21` Type C, Type E
  * `22` Type F
  * `23` Type G
  * `24-29` (Reserved)
  * `30` Type B
  * `31-39` (Reserved)
  * `40` Type H
  * `41` Type I
  * `42` Type J
  * `43-49` (Reserved)
  * `50` Type K
  * `51-59` (Reserved)

#### Header Identifier 5: Projector-Command-Type
* **Information**: Cannot be described (set all to `0x00`).
* **Attributes**: `0x16` = ESC/VP Level 6 (Reserved), `0x21` = ESC/VP21 Ver1.0.

## 4. Communication Modes
### 4.1 Session-less Mode (UDP)
Used for device discovery via the **HELLO** request (Type 1).

* **Port**: UDP 3629 (Broadcast address).

### 4.2 Session Mode (TCP)

Used for establishing a connection for projector commands.

* **Port**: TCP 3629.
* **Connection Flow**:
  1. Client opens TCP connection.
  2. Client sends `CONNECT` or other request.
  3. If successful and `CONNECT` request was send, the connection remains open for commands otherwise the **the TCP connection is cut** .
  4. If an error occurs, the server sends an error status and **cuts the TCP connection**.

## 5. Request examples
### 5.1 PASSWORD Request/Response (Type 2)
#### 5.1.1 PASSWORD check request
Request to confirm the presence/absence of password setting

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `2`            | Type identifier: PASSWORD |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x00`         | Status code: Always set 0x00 since it is a request. |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

The server returns the status code 0x20 (OK) when the password has not been set, or the status code 0x41 (Unauthorized) when the password has been set. 

#### 5.1.2 PASSWORD confirm request
Request to confirm the password

| Byte Length  | Type   | Value           | Meaning            |
| ------------ | ------ | --------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"`  | Protocol identifier |
| 1            | BYTE   | `0x10`          | Version identifier |
| 1            | UCHAR  | `2`             | Type identifier: PASSWORD |
| 2            | USHORT | `0`             | (Reserved) |
| 1            | BYTE   | `0x00`          | Status code: Always set 0x00 since it is a request. |
| 1            | UCHAR  | `1`             | Number of headers: 1 |
| 1            | UCHAR  | `1`             | Header 1 identifier: Password |
| 1            | UCHAR  | `1`             | Header 1 attribute value: Plain |
| 16           | STR    | `"AbCdEfGhIjk"` | Header 1 information: Password character string |

The server returns the status code 0x20 (OK) when the password is correct, or the status code 0x43 (Forbidden) when the password is wrong. 

#### 5.1.3 PASSWORD success response
Response to a success in password confirmation or change.
After the following datagram is sent, the TCP connection is cut off. 

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `2`            | Type identifier: PASSWORD |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x20`         | Status code: OK |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

#### 5.1.3 PASSWORD failure response
Response to a failure due to an authentication error
After the following datagram is sent, the TCP connection is cut off. 

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `2`            | Type identifier: PASSWORD |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x43`         | Status code: Forbidden |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

### 5.2 CONNECT Request/Response (Type 3)
#### 5.2.1 CONNECT Request without password
Request not to use the password

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `3`            | Type identifier: CONNECT |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x00`         | Status code: Always set 0x00 since it is a request. |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

#### 5.2.2 CONNECT Request with password
Request to use the password

| Byte Length  | Type   | Value           | Meaning            |
| ------------ | ------ | --------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"`  | Protocol identifier |
| 1            | BYTE   | `0x10`          | Version identifier |
| 1            | UCHAR  | `3`             | Type identifier: CONNECT |
| 2            | USHORT | `0`             | (Reserved) |
| 1            | BYTE   | `0x00`          | Status code: Always set 0x00 since it is a request. |
| 1            | UCHAR  | `1`             | Number of headers: 1 |
| 1            | UCHAR  | `1`             | Header 1 identifier: Password |
| 1            | UCHAR  | `1`             | Header 1 attribute value: Plain |
| 16           | STR    | `"AbCdEfGhIjk"` | Header 1 information: Password character string |

#### 5.2.3 CONNECT success response 
Response to a success in session start
After the following datagram is sent, the bidirectional session of ESC/VP21 starts with the TCP connection maintained. 

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `3`            | Type identifier: CONNECT |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x20`         | Status code: OK |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

After the bidirectional session has started, the ESC/VP21 commands are transferred directly since direct communication is 
made with the projector. 
The bidirectional session is continued until the TCP connection is cut off from either the server or client.

#### 5.2.4 CONNECT busy response 
Response to a failure in connection due to a BUSY status
After the following datagram is sent, the TCP connection is closed. 

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `3`            | Type identifier: CONNECT |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x53`         | Status code: Service Unavailable |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

#### 5.2.4 CONNECT password required response 
Response to the necessity of a password
After the following datagram is sent, the TCP connection is closed. 

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `3`            | Type identifier: CONNECT |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x41`         | Status code: Unauthorized |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

#### 5.2.4 CONNECT wrong password response 
Response to a wrong password
After the following datagram is sent, the TCP connection is closed. 

| Byte Length  | Type   | Value          | Meaning            |
| ------------ | ------ | -------------- | ------------------ |
| 10           | STR    | `"ESP/VP.net"` | Protocol identifier |
| 1            | BYTE   | `0x10`         | Version identifier |
| 1            | UCHAR  | `3`            | Type identifier: CONNECT |
| 2            | USHORT | `0`            | (Reserved) |
| 1            | BYTE   | `0x43`         | Status code: Forbidden |
| 1            | UCHAR  | `0`            | Number of headers: 0 |

## 6. Errors
### 6.1 Common erros
| Error Definition | Processing Method |
| ----------------------------- | -- |
| Request data is illegal.<ul><li>Protocol identifier is not "ESC/VP.net". </li><li>Type identifier is outside the defined range. </li><li>Status code is not 0x00. </li><li>Sequence number (reserved area) is not 0. </li><li>Header identifier is outside the defined range. </li><li>Header attribute value is outside the defined range. </li><li>Version identifier is not 0x10.</li></ul> | The server returns the error code 0x40 (Bad Request) in a response. After that, in the case of the session mode, the server cuts off the TCP connection and waits for the next request. |
| Version identifier is not 0x10. | The server returns the error code 0x55 (Protocol Version Not Supported) in a response. After that, in the case of the session mode, the server cuts off the TCP connection and waits for the next request. |
### 6.2 UDP (session-less mode) Specific Errors 
| Error Definition | Processing Method |
| -- | -- |
| Type identifier is not 1 (HELLO). | The server returns the error code 0x45 (Request not allowed) in a response. |
### 6.3 TCP (session mode) Specific Errors 
| Error Definition | Processing Method |
| -- | -- |
| Type identifier is not 2 (PASSWORD) or 3 (CONNECT). | The server returns the error code 0x45 (Request not allowed) in a response. After that, the server cuts off the TCP connection and waits for the next request. |
### 6.4 HELLO Message Specific Errors 
| Error Definition | Processing Method |
| -- | -- |
| In spite of the HELLO request, the request header is used. | The server returns the error code 0x40 (Bad Request) in a response. |
### 6.5 PASSWORD Message Specific Errors 
| Error Definition | Processing Method |
| -- | -- |
| In spite of the PASSWORD request, the header other than Password/New-Password is used. <hr> The password or new password includes any character that cannot be printed or that deviates from the US-ASCII code. (0-31 and 127 or more) <hr> Though the Password/New-Password header identifier is not NULL, the password is a blank character string. | The server returns the error code 0x40 (Bad Request) in a response, cuts off the TCP connection, and waits for the next request. |
| Though the password is set to the server, the password is not included in the request. | The server returns the error code 0x41 (Unauthorized) in a response, cuts off the TCP connection, and waits for the next request. |
| Though the password is not set to the server, the password is included in the request. | The server ignores the password in the request. An error does not occur. |
| The password set to the server differs from the password included in the request. | The server returns the error code 0x43 (Forbidden) in a response, cuts off the TCP connection, and waits for the next request. | 
| The server cannot respond immediately since it is processing the other request, for example. | The server returns the error code 0x53 (Service Unavailable) in a response, cuts off the TCP connection, and waits for the next request. |
### 6.4 CONNECT Message Specific Errors 
| Error Definition | Processing Method |
| -- | -- |
| Though the password is set to the server, the password is not included in the request. | The server returns the error code 0x41 (Unauthorized) in a response, cuts off the TCP connection, and waits for the next request. |
| Though the password is not set to the server, the password is included in the request. | The server ignores the password in the request. An error does not occur. |
| The password set to the server differs from the password included in the request. | The server returns the error code 0x43 (Forbidden) in a response, cuts off the TCP connection, and waits for the next request. | 
| The server cannot respond immediately since it is processing the other request, for example. | The server returns the error code 0x53 (Service Unavailable) in a response, cuts off the TCP connection, and waits for the next request. |
| The server cannot respond immediately since it is processing the other request, for example. <hr> The server cannot start a new ESC/VP21 bidirectional session. | The server returns the error code 0x53 (Service Unavailable) in a response, cuts off the TCP connection, and waits for the next request. |  
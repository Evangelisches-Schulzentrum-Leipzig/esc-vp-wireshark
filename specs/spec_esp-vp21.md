# ESC/VP21 Protocol Specification
Link: https://download.epson-europe.com/pub/download/3222/epson322269eu.pdf
Revision: J 2008-09-19
## 1. ESC/VP21 Command Formats
### 1.1. Set command format
A set command consists of a command and a parameter.
There are two types of parameters. One is fixed such as ON, OFF, or 21. Other is a step parameter such as INC, DEC or INIT.
Each set command needs to be followed by the RETURN key (carriage return, `0x0D`).

INC increments the parameter by one.
DEC decrements the parameter by one.
INIT initializes the parameter.
#### 1.1.1. Example
* SOURCE 21
* VOL INC

### 1.2. Get command format
A get command consists of a command and ?.
Each get command needs to be followed by the RETURN key (carriage return, `0x0D`).
#### 1.2.1. Examples 
* SOURCE?

### 1.3. Response format
A response has no fixed length and thus no padding.
A response is sent from the projector to the controller when a get command is received. It is also sent when a set command is received if the command is executed successfully.
A response consists of a command, an equal sign (`0x3D`), a parameter and a carriage return (`0x0D`). The command and parameter are the same as those of set commands.
Each response needs to be followed by a colon character (`0x3A`).
When a response is empty (without a command or parameter), only a colon character is sent.
#### 1.3.1. Example
* 0x3A -> : (empty response)
* 0x53 0x4E 0x4F 0x3D 0x58 0x43 0x42 0x39 0x34 0x38 0x30 0x30 0x38 0x36 0x33 0x0D 0x3A -> SNO=XCB94800863: 
* 0x4D 0x55 0x54 0x45 0x3D 0x4F 0x46 0x46 0x0D 0x3A -> MUTE=OFF:

### 1.4. Error response format
The projector returns “ERR” and a return key code (`0x0D`) and a colon (`0x3A`) when it receives invalid commands.
#### 1.4.1. Example
* 0x45 0x52 0x52 0x0D 0x3A -> ERR:

## 2. Commands
### 2.1. Get Commands
| Command | Description | Values | Remarks |
|---------|-------------|--------|---------|
| PWR? | Power state | `00`: "Standby" at the time of "Network off", `01`: Power on, `02`: Warm up, `03`: Cooling down, `04`: "Standby" at the time of "Network on", `05`: Abnomal Standby ||
| SOURCE? | Input source | `10`: Input 1(D-Sub), `11`: Input 1(RGB), `14`: Input 1(Component), `20`: Input 2, `21`: Input 2(RGB), `24`: Input 2(Component), `30`: Input 3(DVI-D/HDMI), `31`: Input 3(RGB), `33`: Input 3(RGB-Video), `34`: Input 3(YCbCr), `35`: Input 3(YPbPr), `40`: Video, `41`: Video(RCA), `42`: Video(S), `45`: Video1(BNC), `50`: EasyMP, `B0`: Input 4(BNC), `B1`: Input 4(RGB), `B2`: Input 4(YCbCr), `B3`: Input 4(YPbPr), `B4`: Input 4(Component) | Values Model dependent |
| MSEL? | A/V Mute screen setting | `00`: Black Screen, `01`: Blue Screen, `02`: User logo ||
| AUTOKEYSTONE? | Auto Keystone state | `ON`: Auto Keystone on, `OFF`: Auto Keystone off ||
| ASPECT? | Aspect ratio | `00`: Normal, `10`: 4:3, `12`: (zoom) 4:3, `20`: 16:9, `21`: 16:9 (up), `22`: 16:9 (down), `30`: Auto, `40`: Full, `50`: Zoom, `60`: Through | Values Model dependent |
| CMODE? | Color mode | `01`: sRGB, `02`: Normal, `03`: Meeting/Text, `04`: Presentation, `05`: Theater, `06`: Amusement/Living Room/Game, `08`: Dynamic/Sports, `10`: Customized, `11`: Black Board, `14`: Photo | Values Model dependent |
| LAMP? | Lamp hours | `0` to `65535` ||
| LUMINANCE? | Brightness level | `00`: High, `01`: Low ||
| MUTE? | A/V Mute state | `ON`: A/V Mute on, `OFF`: A/V Mute off ||
| FREEZE? | Freeze state | `ON`: Freeze on, `OFF`: Freeze off ||
| HREVERSE? | Rear projection state | `ON`: rear on, `OFF`: rear off ||
| VREVERSE? | Ceiling projection state | `ON`: ceiling on, `OFF`: ceiling off ||
| AUDIO? | Audio input source | `01`: Audio1, `02`: Audio2, `03`: USB | Values Model dependent |
| CCAP? | Closed caption mode | `00`: Off, `11`: CC1, `12`: CC2, `13`: CC3, `14`: CC4, `21`: TEXT1, `22`: TEXT2, `23`: TEXT3, `24`: TEXT4 | Values Model dependent |
| FLWARNING? | Filter warning state | `ON`: Warning on, `OFF`: Warning off ||
| FILTER? | Filter time | `0` to `65535` ||
| ZOOM? | E-Zoom setting | `0` to `255` ||
| SNO? | Serial number | [String] ||
| ONTIME? | Operation time in hours | `0` to `65535` ||
| SIGNAL? | Signal state | `00`: No signal, `01`: Signal detected, `FF`: Unsupported signal ||
| MENUINFO? | Info Menu | `00`: All data, `01`: Status, `02`: Operation hours, `05`: Event ID ||
| ERR? | Error code | `00`: No error/Error recovered, `01`: Fan error, `03`: Lamp failure at power on, `04`: High internal temperature error, `06`: Lamp error, `07`: Open Lamp cover door error, `08`: Cinema filter error, `09`: Electric dual-layered capacitor is disconnected , `0A`: Auto iris error, `0B`: Subsystem Error, `0C`: Low air flow error, `0D`: Air filter air flow sensor error, `0E`: Power supply unit error (Ballast) ||
| LUMCONST? | Constant brightness mode | Follows format x1 x2<br>x1: mode<ul><li>`00`: Off</li><li>`01`: On</li></ul>x2: Brightness level `0` to `255` ||
| IMNWPNAME? | Projector name | [String] ||
| NWPNAME? | Projector name | [String] ||
### 2.2. Set Commands
| Command | Description | Values | Remarks |
|---------|-------------|--------|---------|
| PWR | Power control | `ON`: Power on, `OFF`: Power off ||
| SOURCE | Input source | `10`: Input 1(D-Sub), `11`: Input 1(RGB), `14`: Input 1(Component), `20`: Input 2, `21`: Input 2(RGB), `24`: Input 2(Component), `30`: Input 3(DVI-D/HDMI), `31`: Input 3(RGB), `33`: Input 3(RGB-Video), `34`: Input 3(YCbCr), `35`: Input 3(YPbPr), `40`: Video, `41`: Video(RCA), `42`: Video(S), `45`: Video1(BNC), `50`: EasyMP, `B0`: Input 4(BNC), `B1`: Input 4(RGB), `B2`: Input 4(YCbCr), `B3`: Input 4(YPbPr), `B4`: Input 4(Component) | Values Model dependent |
| PINP | Picture in picture control | Supply value formatted as [source posX posY size]<br>source: Video source of sub-screen (Video or S-video) source code, posX: X coordinate (0-15) of sub-screen from left Horizontal is divided into 16 (default value is used when omitted), posY: Y coordinate (0-15) of sub-screen from top Vertical is divided into 16 (default value is used when omitted), size: Size of sub-screen 0-4 incremental zoom (default value is used when 0 or omitted) ||
| MSEL | A/V Mute screen setting | `00`: Black Screen, `01`: Blue Screen, `02`: User logo ||
| AUTOKEYSTONE | Auto Keystone control | `ON`: Auto Keystone on, `OFF`: Auto Keystone off ||
| ASPECT | Aspect ratio | `00`: Normal, `10`: 4:3, `12`: (zoom) 4:3, `20`: 16:9, `21`: 16:9 (up), `22`: 16:9 (down), `30`: Auto, `40`: Full, `50`: Zoom, `60`: Through | Values Model dependent |
| CMODE | Color mode | `01`: sRGB, `02`: Normal, `03`: Meeting/Text, `04`: Presentation, `05`: Theater, `06`: Amusement/Living Room/Game, `08`: Dynamic/Sports, `10`: Customized, `11`: Black Board, `14`: Photo | Values Model dependent |
| LUMINANCE | Brightness level | `00`: High, `01`: Low ||
| MUTE | A/V Mute control | `ON`: A/V Mute on, `OFF`: A/V Mute off ||
| FREEZE | Freeze control | `ON`: Freeze on, `OFF`: Freeze off ||
| HREVERSE | Rear projection control | `ON`: rear on, `OFF`: rear off ||
| VREVERSE | Ceiling projection control | `ON`: ceiling on, `OFF`: ceiling off ||
| AUDIO | Audio input source | `01`: Audio1, `02`: Audio2, `03`: USB | Values Model dependent |
| KEY | Remote control key function | `4A`: Perform ”Auto-sync” of a remote control button, `47`: Perform ”Freeze” of a remote control button ||
| CCAP | Closed caption mode | `00`: Off, `11`: CC1, `12`: CC2, `13`: CC3, `14`: CC4, `21`: TEXT1, `22`: TEXT2, `23`: TEXT3, `24`: TEXT4 | Values Model dependent |
| FLWARNING | Filter warning control | `ON`: Warning on, `OFF`: Warning off ||
| FLTIME | Filter time control | Supply value as formatted [x1 x2]; <br>x1 values:<ul><li>00 : All objects</li><li>01 : Object 1</li><li>02 : Object 2</li><li>03 : Object 3</li></ul>x2 Set time [Model dependent] ||
### 2.3. Set Commands with Step Parameters
The Range of step parameters is model dependent.
| Command | Description |
|---------|-------------|
| VOL | Set the Volume level |
| TONEH | Set treble (tone) level |
| TONEL | Set bass level |
| BRIGHT | Set brightness |
| CONTRAST | Set contrast |
| TINT | Set tint |
| VKEYSTONE | Set vertical keystone value |
| HKEYSTONE | Set horizontal keystone value |
# ESC/VP21 Protocol Specification
Link: https://download.epson-europe.com/pub/download/3222/epson322269eu.pdf
Revision: J 2008-09-19
## 1. ESC/VP21 Command Formats
### 1.1. Set command format
A set command consists of a command and a parameter.
There are two types of parameters. One is fixed such as ON, OFF, or 21.Other is a step parameter such as INC, DEC or INIT.

INC increments the parameter by one.
DEC decrements the parameter by one.
INIT initializes the parameter.
#### 1.1.1. Example
* SOURCE 21
* VOL INC

### 1.2. Get command format
A get command consists of a command and ?
#### 1.2.1. Examples 
* SOURCE?

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
| FREEZE | Freeze control | `ON`: Freeze on, `OFF`: Freeze off |
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
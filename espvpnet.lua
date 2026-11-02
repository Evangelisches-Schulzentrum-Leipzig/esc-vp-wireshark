-- ESC/VP.net Protocol Dissector for Wireshark
-- Based on: SEIKO EPSON ESC/VP.net Protocol Specification

local p_escvpnet = Proto("escvpnet", "Epson ESC/VP.net Projector Protocol")

--------------------------------------------------------------------------------
-- 1. Constants & Value Strings
--------------------------------------------------------------------------------

-- Message Types (Section 2.1)
local MSG_TYPES = {
    [0] = "NULL",
    [1] = "HELLO",
    [2] = "PASSWORD",
    [3] = "CONNECT"
}

-- Status Codes (Section 2.2)
local STATUS_CODES = {
    [0x00] = "Request (0x00)",
    [0x20] = "OK (0x20)",
    [0x40] = "Bad Request (0x40)",
    [0x41] = "Unauthorized (Password Required) (0x41)",
    [0x43] = "Forbidden (Wrong Password) (0x43)",
    [0x45] = "Request Not Allowed (0x45)",
    [0x53] = "Service Unavailable (Busy) (0x53)",
    [0x55] = "Version Not Supported (0x55)"
}

-- Header Identifiers (Section 3.2)
local HEADER_IDS = {
    [0] = "NULL",
    [1] = "Password",
    [2] = "New-Password",
    [3] = "Projector-Name",
    [4] = "IM-Type",
    [5] = "Projector-Command-Type"
}

-- Password / New-Password Attribute Values (Section 3.2)
local PASSWORD_ATTRS = {
    [0] = "NULL (No Password)",
    [1] = "Plain (US-ASCII)"
}

local V2_PASSWORD_ATTRS = {
    [3] = "Challenge / Nonce",
    [4] = "Digest (First Half)",
    [5] = "Digest (Second Half)"
}

-- Projector-Name Attribute Values (Section 3.2)
local PROJNAME_ATTRS = {
    [0] = "NULL (No Projector Name)",
    [1] = "US-ASCII",
    [2] = "Shift-JIS (Reserved)",
    [3] = "EUC-JP (Reserved)"
}

-- Header Attribute: IM-Type Mappings (Section 3.2)
local IM_TYPES = {
    [0x0C] = "Type D",
    [0x10] = "Reserved", [0x11] = "Reserved", [0x12] = "Reserved",
    [0x13] = "Reserved", [0x14] = "Reserved", [0x15] = "Reserved",
    [0x16] = "Type A",
    [0x17] = "Type A (Reserved)", [0x18] = "Type A (Reserved)", [0x19] = "Type A (Reserved)",
    [0x20] = "EMP/PL-735 Initial",
    [0x21] = "Type C / Type E",
    [0x22] = "Type F",
    [0x23] = "Type G",
    [0x24] = "Reserved", [0x25] = "Reserved", [0x26] = "Reserved",
    [0x27] = "Reserved", [0x28] = "Reserved", [0x29] = "Reserved",
    [0x30] = "Type B",
    [0x31] = "Reserved", [0x32] = "Reserved", [0x33] = "Reserved",
    [0x34] = "Reserved", [0x35] = "Reserved", [0x36] = "Reserved",
    [0x37] = "Reserved", [0x38] = "Reserved", [0x39] = "Reserved",
    [0x40] = "Type H",
    [0x41] = "Type I",
    [0x42] = "Type J",
    [0x43] = "Reserved", [0x44] = "Reserved", [0x45] = "Reserved",
    [0x46] = "Reserved", [0x47] = "Reserved", [0x48] = "Reserved",
    [0x49] = "Reserved",
    [0x50] = "Type K",
    [0x51] = "Reserved", [0x52] = "Reserved", [0x53] = "Reserved",
    [0x54] = "Reserved", [0x55] = "Reserved", [0x56] = "Reserved",
    [0x57] = "Reserved", [0x58] = "Reserved", [0x59] = "Reserved"
}

-- Header Attribute: Command Types (Section 3.2)
local CMD_TYPES = {
    [0x16] = "ESC/VP Level 6 (Reserved)",
    [0x21] = "ESC/VP21 Ver1.0"
}

--------------------------------------------------------------------------------
-- 1b. ESC/VP21 Command Tables (from ESC/VP21 Specification)
--------------------------------------------------------------------------------

-- Command descriptions
local VP21_COMMANDS = {
    PWR         = "Power",
    SOURCE      = "Input Source",
    MSEL        = "A/V Mute Screen Setting",
    AUTOKEYSTONE= "Auto Keystone",
    ASPECT      = "Aspect Ratio",
    CMODE       = "Color Mode",
    LAMP        = "Lamp Hours",
    LUMINANCE   = "Brightness Level",
    MUTE        = "A/V Mute",
    FREEZE      = "Freeze",
    HREVERSE    = "Rear Projection",
    VREVERSE    = "Ceiling Projection",
    AUDIO       = "Audio Input Source",
    CCAP        = "Closed Caption Mode",
    FLWARNING   = "Filter Warning",
    FILTER      = "Filter Time",
    VOL         = "Volume Level",
    TONEH       = "Treble (Tone) Level",
    TONEL       = "Bass Level",
    BRIGHT      = "Brightness",
    CONTRAST    = "Contrast",
    TINT        = "Tint",
    VKEYSTONE   = "Vertical Keystone",
    HKEYSTONE   = "Horizontal Keystone",
    PINP        = "Picture in Picture",
    KEY         = "Remote Control Key",
    FLTIME      = "Filter Time Control",
    ZOOM        = "E-Zoom",
    SNO         = "Serial Number",
    ONTIME      = "Operation Hours",
    SIGNAL      = "Signal State",
    MENUINFO    = "Info Menu",
    ERR         = "Error Code",
    LUMCONST    = "Constant Brightness",
    IMNWPNAME   = "Projector Name (IM)",
    NWPNAME     = "Projector Name",
    NWMAC       = "Wired MAC Address",
    NWWLMAC     = "Wireless MAC Address",
    NWCNF       = "Wired Network Config",
    NWIPDISP    = "Wired IP Address Display",
    NWWLIPDISP  = "Wireless IP Address Display",
    NWWLCNFS    = "Wireless Network Config (802.1x)",
    NWWLSEC     = "Wireless Security Config",
    NWDNS       = "Wired DNS Servers",
    NWWLCNF     = "Wireless Network Config",
    NWWLDNS     = "Wireless DNS Servers",
    NWIF        = "Network Interface Type",
    NWPRIMIF    = "Priority Network Interface",
    -- Undocumented / vendor-specific
    PWSTATUS    = "Power Status (extended)",
    VER         = "Firmware Version",
    LAMPS       = "Light Source Hours",
    SOURCELIST  = "Available Input Sources",
    NWESSDISP   = "ESSID Display",
}

-- Parameter value lookup tables per command
local VP21_PARAM_VALUES = {
    PWR = {
        ["00"] = "Standby (Network Off)",
        ["01"] = "Power On",
        ["02"] = "Warm Up",
        ["03"] = "Cooling Down",
        ["04"] = "Standby (Network On)",
        ["05"] = "Abnormal Standby",
        ON     = "Power On",
        OFF    = "Power Off",
    },
    SOURCE = {
        ["10"] = "Input 1 (D-Sub)",   ["11"] = "Input 1 (RGB)",
        ["14"] = "Input 1 (Component)",
        ["20"] = "Input 2",            ["21"] = "Input 2 (RGB)",
        ["24"] = "Input 2 (Component)",
        ["30"] = "Input 3 (DVI-D/HDMI)",["31"] = "Input 3 (RGB)",
        ["33"] = "Input 3 (RGB-Video)", ["34"] = "Input 3 (YCbCr)",
        ["35"] = "Input 3 (YPbPr)",
        ["40"] = "Video",              ["41"] = "Video (RCA)",
        ["42"] = "Video (S)",          ["45"] = "Video1 (BNC)",
        ["50"] = "EasyMP",
        B0     = "Input 4 (BNC)",       B1     = "Input 4 (RGB)",
        B2     = "Input 4 (YCbCr)",     B3     = "Input 4 (YPbPr)",
        B4     = "Input 4 (Component)",
    },
    MSEL = {
        ["00"] = "Black Screen", ["01"] = "Blue Screen", ["02"] = "User Logo",
    },
    AUTOKEYSTONE = {
        ON = "Auto Keystone On", OFF = "Auto Keystone Off",
    },
    ASPECT = {
        ["00"] = "Normal",    ["10"] = "4:3",       ["12"] = "4:3 (Zoom)",
        ["20"] = "16:9",      ["21"] = "16:9 (Up)",  ["22"] = "16:9 (Down)",
        ["30"] = "Auto",      ["40"] = "Full",
        ["50"] = "Zoom",      ["60"] = "Through",
    },
    CMODE = {
        ["01"] = "sRGB",         ["02"] = "Normal",
        ["03"] = "Meeting/Text",  ["04"] = "Presentation",
        ["05"] = "Theater",       ["06"] = "Amusement/Living Room/Game",
        ["08"] = "Dynamic/Sports",["10"] = "Customized",
        ["11"] = "Black Board",   ["14"] = "Photo",
    },
    LUMINANCE = {
        ["00"] = "High", ["01"] = "Low",
    },
    MUTE = {
        ON = "A/V Mute On", OFF = "A/V Mute Off",
    },
    FREEZE = {
        ON = "Freeze On", OFF = "Freeze Off",
    },
    HREVERSE = {
        ON = "Rear On", OFF = "Rear Off",
    },
    VREVERSE = {
        ON = "Ceiling On", OFF = "Ceiling Off",
    },
    AUDIO = {
        ["01"] = "Audio1", ["02"] = "Audio2", ["03"] = "USB",
    },
    KEY = {
        ["4A"] = "Auto-Sync", ["47"] = "Freeze",
    },
    CCAP = {
        ["00"] = "Off",
        ["11"] = "CC1",   ["12"] = "CC2",   ["13"] = "CC3",   ["14"] = "CC4",
        ["21"] = "TEXT1", ["22"] = "TEXT2", ["23"] = "TEXT3", ["24"] = "TEXT4",
    },
    FLWARNING = {
        ON = "Warning On", OFF = "Warning Off",
    },
    NWIPDISP = {
        ON = "Wired IP address display On", OFF = "Wired IP address display Off",
    },
    NWWLIPDISP = {
        ON = "Wireless IP address display On", OFF = "Wireless IP address display Off",
    },
    NWIF = {
        ["00"] = "Wired LAN",
        ["01"] = "802.11b",
        ["02"] = "802.11a",
        ["03"] = "802.11g",
    },
    NWPRIMIF = {
        ["0"] = "Wired LAN (priority)",
        ["1"] = "Wireless LAN (priority)",
    },
    SIGNAL = {
        ["00"] = "No Signal",
        ["01"] = "Signal Detected",
        ["FF"] = "Unsupported Signal",
    },
    MENUINFO = {
        ["00"] = "All Data",
        ["01"] = "Status",
        ["02"] = "Operation Hours",
        ["05"] = "Event ID",
    },
    ERR = {
        ["00"] = "No error / Error recovered",
        ["01"] = "Fan error",
        ["03"] = "Lamp failure at power on",
        ["04"] = "High internal temperature error",
        ["06"] = "Lamp error",
        ["07"] = "Open lamp cover door error",
        ["08"] = "Cinema filter error",
        ["09"] = "Electric dual-layered capacitor disconnected",
        ["0A"] = "Auto iris error",
        ["0B"] = "Subsystem error",
        ["0C"] = "Low air flow error",
        ["0D"] = "Air filter air flow sensor error",
        ["0E"] = "Power supply unit error (Ballast)",
    },
}

-- Multi-part parameter descriptors for commands whose value is space-separated fields.
-- Each entry is an ordered list of { label, values? } field descriptors.
-- The generic decoder in decode_vp21_param iterates these to build a human-readable string.
local VP21_MULTI_PARAMS = {
    -- LUMCONST: "x1 x2"  x1=mode, x2=brightness (0-255)
    LUMCONST = {
        { label = "Mode",       values = { ["00"] = "Off", ["01"] = "On" } },
        { label = "Brightness" },
    },
    -- FLTIME: "x1 x2"  x1=object, x2=time (model dependent)
    FLTIME = {
        { label = "Object", values = {
            ["00"] = "All objects",
            ["01"] = "Object 1",
            ["02"] = "Object 2",
            ["03"] = "Object 3",
        }},
        { label = "Time" },
    },
    -- PINP: "source posX posY size"
    PINP = {
        { label = "Source" },
        { label = "X Position" },
        { label = "Y Position" },
        { label = "Size" },
    },
    -- PWSTATUS (undocumented): "status flags1 flags2 field4 field5"
    PWSTATUS = {
        { label = "Status", values = {
            ["00"] = "Standby (Network Off)",
            ["01"] = "Power On",
            ["02"] = "Warm Up",
            ["03"] = "Cooling Down",
            ["04"] = "Standby (Network On)",
            ["05"] = "Abnormal Standby",
            ON     = "Power On",
            OFF    = "Power Off",
        } },
        { label = "Flags 1" },
        { label = "Flags 2" },
        { label = "Field 4" },
        { label = "Field 5" },
    },
    -- LAMPS (undocumented): "h1_normal h1_eco h2_normal h2_eco"
    LAMPS = {
        { label = "Light 1 Normal" },
        { label = "Light 1 Eco" },
        { label = "Light 2 Normal" },
        { label = "Light 2 Eco" },
    },
    -- NWCNF: "DHCP IP Subnet Gateway"
    NWCNF = {
        { label = "DHCP",    values = { ON = "On", OFF = "Off" } },
        { label = "IP" },
        { label = "Subnet" },
        { label = "Gateway" },
    },
    -- NWWLCNFS: "DHCP IP Subnet Gateway Options ESSID"
    -- Options is a 2-char hex byte: bit0=Ad-Hoc, bit1=ESSID valid
    NWWLCNFS = {
        { label = "DHCP",    values = { ON = "On", OFF = "Off" } },
        { label = "IP" },
        { label = "Subnet" },
        { label = "Gateway" },
        { label = "Options (hex)" },
        { label = "ESSID" },
    },
    -- NWDNS / NWWLDNS: "primary secondary"
    NWDNS = {
        { label = "Primary DNS" },
        { label = "Secondary DNS" },
    },
    NWWLDNS = {
        { label = "Primary DNS" },
        { label = "Secondary DNS" },
    },
}

-- Custom decoders for commands whose response format cannot be handled by a
-- simple lookup or the generic multi-part splitter.
local VP21_CUSTOM_DECODERS = {
    -- VER response: "<firmware>VER=----VER=----..." (first token is the real version,
    -- the rest are filler entries for unpopulated firmware slots)
    VER = function(param)
        local fw = param:match("^(.-)VER=") or param
        return "Firmware: " .. fw
    end,
    -- NWWLSEC: packed 6-char hex string "wxyyzz"
    -- w=encryption(4bit), x=key length(4bit), yy=EAP method(1byte), zz=auth type(1byte)
    NWWLSEC = function(param)
        if #param ~= 6 then return nil end
        local w   = param:sub(1,1)
        local x   = param:sub(2,2)
        local yy  = param:sub(3,4)
        local zz  = param:sub(5,6)
        local enc = ({ ["0"]="None", ["1"]="WEP", ["2"]="TKIP",
                       ["3"]="CKIP", ["4"]="AES" })[w] or ("Reserved ("..w..")")
        local klen= ({ ["0"]="None", ["1"]="64-bit", ["2"]="128-bit",
                       ["3"]="152-bit" })[x] or ("Reserved ("..x..")")
        local eap = ({ ["00"]="None", ["01"]="Shared Key", ["02"]="TTLS",
                       ["03"]="TLS",  ["04"]="LEAP", ["05"]="MD5",
                       ["06"]="PEAP" })[yy] or ("Reserved ("..yy..")")
        local auth= ({ ["00"]="None", ["01"]="802.1x / RADIUS", ["02"]="WPA",
                       ["03"]="WPA2" })[zz] or ("Reserved ("..zz..")")
        return "Encryption: "..enc..", Key Length: "..klen..", EAP: "..eap..", Auth: "..auth
    end,
    -- NWWLCNF: "ww IP Subnet Gateway t [ESSID] [WEPkey]"
    -- t = flag byte: bits encode ESSID-specified(2), WEP-valid(1), Adhoc(0)
    NWWLCNF = function(param)
        local FLAG_DESC = {
            ["0"] = "No ESSID, No WEP, Adhoc OFF",
            ["1"] = "No ESSID, No WEP, Adhoc ON",
            ["2"] = "No ESSID, WEP valid, Adhoc OFF",
            ["3"] = "No ESSID, WEP valid, Adhoc ON",
            ["4"] = "ESSID, No WEP, Adhoc OFF",
            ["5"] = "ESSID, No WEP, Adhoc ON",
            ["6"] = "ESSID, WEP valid, Adhoc OFF",
            ["7"] = "ESSID, WEP valid, Adhoc ON",
        }
        local parts = {}
        for p in param:gmatch("%S+") do parts[#parts+1] = p end
        if #parts < 5 then return nil end
        local dhcp    = parts[1] == "ON" and "On" or "Off"
        local flag    = parts[5]
        local fdesc   = FLAG_DESC[flag] or ("Unknown flag ("..flag..")")
        local out = "DHCP: "..dhcp..", IP: "..parts[2]..", Subnet: "..parts[3]..
                    ", Gateway: "..parts[4]..", Flags: "..fdesc
        if #parts >= 6 then out = out .. ", ESSID: " .. parts[6] end
        if #parts >= 7 then out = out .. ", WEP key: " .. parts[7] end
        return out
    end,
    -- Names may use ^ as an internal space substitute (e.g. USB^Display -> USB Display).
    SOURCELIST = function(param)
        local entries = {}
        local parts = {}
        for p in param:gmatch("%S+") do parts[#parts + 1] = p end
        local i = 1
        while i + 1 <= #parts do
            local code = parts[i]
            local name = parts[i + 1]:gsub("%^", " ")
            entries[#entries + 1] = code .. "=" .. name
            i = i + 2
        end
        return #entries > 0 and table.concat(entries, ", ") or nil
    end,
    -- NWMAC / NWWLMAC: 12-char hex string -> colon-separated MAC address
    NWMAC = function(param)
        if #param == 12 then
            return param:gsub("(..)(..)(..)(..)(..)(..)", "%1:%2:%3:%4:%5:%6")
        end
        return nil
    end,
    NWWLMAC = function(param)
        if #param == 12 then
            return param:gsub("(..)(..)(..)(..)(..)(..)", "%1:%2:%3:%4:%5:%6")
        end
        return nil
    end,
}

-- Step parameters (INC/DEC/INIT) apply to these commands
local VP21_STEP_PARAMS = {
    INC  = "Increment",
    DEC  = "Decrement",
    INIT = "Initialize",
}

-- Helper: decode a VP21 parameter value for a given command
local function decode_vp21_param(cmd, param)
    -- Check step parameters first (valid for set commands)
    if VP21_STEP_PARAMS[param] then
        return VP21_STEP_PARAMS[param]
    end
    -- Custom decoder (commands with non-standard response layout)
    local custom = VP21_CUSTOM_DECODERS[cmd]
    if custom then
        return custom(param)
    end
    -- Generic multi-part parameter decoding (space-separated fields)
    local multi = VP21_MULTI_PARAMS[cmd]
    if multi then
        local parts = {}
        for p in param:gmatch("%S+") do parts[#parts + 1] = p end
        local out = {}
        for i, field in ipairs(multi) do
            local val = parts[i]
            if val then
                local decoded = field.values and field.values[val]
                out[#out + 1] = field.label .. ": " .. (decoded and (decoded .. " (" .. val .. ")") or val)
            end
        end
        return #out > 0 and table.concat(out, ", ") or nil
    end
    -- Look up command-specific value table
    local tbl = VP21_PARAM_VALUES[cmd]
    if tbl and tbl[param] then
        return tbl[param]
    end
    return nil
end

--------------------------------------------------------------------------------
-- 2. Define Protocol Fields
--------------------------------------------------------------------------------

-- Common Header Fields (16 bytes)
local f_signature   = ProtoField.string("escvpnet.signature", "Signature", base.ASCII)
local f_ver_major   = ProtoField.uint8("escvpnet.version.major", "Major Version", base.DEC, nil, 0xF0)
local f_ver_minor   = ProtoField.uint8("escvpnet.version.minor", "Minor Version", base.DEC, nil, 0x0F)
local f_msg_type    = ProtoField.uint8("escvpnet.type", "Message Type", base.DEC, MSG_TYPES)
local f_seq_num     = ProtoField.uint16("escvpnet.seq", "Reserved / Sequence Number", base.HEX)
local f_status      = ProtoField.uint8("escvpnet.status", "Status Code", base.HEX, STATUS_CODES)
local f_hdr_count   = ProtoField.uint8("escvpnet.header_count", "Header Count", base.DEC)

-- Sub-Header Fields (18 bytes per header)
local f_h_id        = ProtoField.uint8("escvpnet.header.id", "Header ID", base.DEC, HEADER_IDS)
local f_h_attr      = ProtoField.uint8("escvpnet.header.attr", "Attribute", base.HEX)
local f_h_pwd_attr  = ProtoField.uint8("escvpnet.header.pwd_attr", "Password Attribute", base.HEX, PASSWORD_ATTRS)
local f_h_v2_auth_attr = ProtoField.uint8("escvpnet.header.v2_auth_attr", "V2 Password Attribute", base.HEX, V2_PASSWORD_ATTRS)
local f_h_name_attr = ProtoField.uint8("escvpnet.header.name_attr", "Name Attribute", base.HEX, PROJNAME_ATTRS)
local f_h_info_str  = ProtoField.string("escvpnet.header.info", "Info String", base.ASCII)
local f_h_info_raw  = ProtoField.bytes("escvpnet.header.info_raw", "Info (Raw)")
local f_h_v2_nonce  = ProtoField.bytes("escvpnet.header.v2_nonce", "V2 Challenge Nonce")
local f_h_v2_digest_first = ProtoField.bytes("escvpnet.header.v2_digest_first", "V2 Digest (First Half)")
local f_h_v2_digest_second = ProtoField.bytes("escvpnet.header.v2_digest_second", "V2 Digest (Second Half)")
local f_h_im_type   = ProtoField.uint8("escvpnet.header.im_type", "IM Type Model", base.HEX, IM_TYPES)
local f_h_cmd_type  = ProtoField.uint8("escvpnet.header.cmd_type", "Command System", base.HEX, CMD_TYPES)

-- ESC/VP21 ASCII Session Fields
local f_vp21_raw     = ProtoField.string("escvpnet.vp21.raw", "Raw Data")
local f_vp21_type    = ProtoField.string("escvpnet.vp21.type", "Message Type")
local f_vp21_cmd     = ProtoField.string("escvpnet.vp21.command", "Command")
local f_vp21_cmd_desc= ProtoField.string("escvpnet.vp21.command_desc", "Command Description")
local f_vp21_param   = ProtoField.string("escvpnet.vp21.param", "Parameter")
local f_vp21_decoded = ProtoField.string("escvpnet.vp21.decoded", "Decoded Value")

p_escvpnet.fields = {
    f_signature, f_ver_major, f_ver_minor, f_msg_type, f_seq_num,
    f_status, f_hdr_count,
    f_h_id, f_h_attr, f_h_pwd_attr, f_h_v2_auth_attr, f_h_name_attr,
    f_h_info_str, f_h_info_raw, f_h_v2_nonce, f_h_v2_digest_first,
    f_h_v2_digest_second, f_h_im_type, f_h_cmd_type,
    f_vp21_raw, f_vp21_type, f_vp21_cmd, f_vp21_cmd_desc,
    f_vp21_param, f_vp21_decoded
}

-- Expert Info
local ef_error_status = ProtoExpert.new("escvpnet.error_status", "Error Status",
    expert.group.RESPONSE_CODE, expert.severity.WARN)
local ef_malformed = ProtoExpert.new("escvpnet.malformed", "Malformed Packet",
    expert.group.MALFORMED, expert.severity.ERROR)
local ef_transport_warning = ProtoExpert.new("escvpnet.transport_warning", "Transport Rule",
    expert.group.PROTOCOL, expert.severity.WARN)

p_escvpnet.experts = { ef_error_status, ef_malformed, ef_transport_warning }

--------------------------------------------------------------------------------
-- 3. Dissector Function
--------------------------------------------------------------------------------
local SIGNATURE = "ESC/VP.net"

local function request_more_data(pinfo, offset, needed)
    if not pinfo.can_desegment then return false end
    pinfo.desegment_offset = offset
    pinfo.desegment_len = needed or DESEGMENT_ONE_MORE_SEGMENT
    return true
end

local function is_signature_prefix(data)
    return #data < #SIGNATURE and data == SIGNATURE:sub(1, #data)
end

local function is_printable_padded_ascii(value)
    local seen_nul = false
    local has_text = false
    for i = 1, #value do
        local byte = value:byte(i)
        if byte == 0 then
            seen_nul = true
        elseif seen_nul or byte < 0x20 or byte > 0x7E then
            return false
        else
            has_text = true
        end
    end
    return has_text
end

local function valid_header_attribute(version, msg_type, id, attr)
    if id == 1 then
        if version == 0x20 and msg_type == 3 then
            return V2_PASSWORD_ATTRS[attr] ~= nil
        end
        return PASSWORD_ATTRS[attr] ~= nil
    elseif id == 2 then
        return PASSWORD_ATTRS[attr] ~= nil
    elseif id == 3 then
        return PROJNAME_ATTRS[attr] ~= nil
    elseif id == 4 then
        return IM_TYPES[attr] ~= nil
    elseif id == 5 then
        return CMD_TYPES[attr] ~= nil
    end
    return false
end

local function add_malformed(item, message)
    item:add_proto_expert_info(ef_malformed, message)
end

local function dissect_binary_packet(buffer, offset, packet_length, pinfo, tree)
    local version = buffer(offset + 10, 1):uint()
    local msg_type = buffer(offset + 11, 1):uint()
    local status = buffer(offset + 14, 1):uint()
    local header_count = buffer(offset + 15, 1):uint()
    local is_v2_challenge = version == 0x20 and msg_type == 3 and status == 0x41
        and header_count == 1 and buffer(offset + 16, 1):uint() == 1
        and buffer(offset + 17, 1):uint() == 3
    local is_v2_challenge_request = version == 0x20 and msg_type == 3 and status == 0
        and header_count == 1 and buffer(offset + 16, 1):uint() == 1
        and buffer(offset + 17, 1):uint() == 3
    local is_v2_proof_request = version == 0x20 and msg_type == 3 and status == 0
        and header_count == 2 and buffer(offset + 16, 1):uint() == 1
        and buffer(offset + 17, 1):uint() == 4
        and buffer(offset + 34, 1):uint() == 1
        and buffer(offset + 35, 1):uint() == 5

    local msg_type_str = MSG_TYPES[msg_type] or "Unknown"
    local status_str = STATUS_CODES[status] or string.format("Unknown (0x%02X)", status)
    local subtree = tree:add(p_escvpnet, buffer(offset, packet_length),
        "Epson ESC/VP.net Protocol")

    subtree:add(f_signature, buffer(offset, 10))
    local ver_node = subtree:add(buffer(offset + 10, 1),
        string.format("Version: %d.%d (0x%02X)", math.floor(version / 16), version % 16, version))
    ver_node:add(f_ver_major, buffer(offset + 10, 1))
    ver_node:add(f_ver_minor, buffer(offset + 10, 1))
    subtree:add(f_msg_type, buffer(offset + 11, 1))
    subtree:add(f_seq_num, buffer(offset + 12, 2))
    local status_item = subtree:add(f_status, buffer(offset + 14, 1))
    subtree:add(f_hdr_count, buffer(offset + 15, 1))

    if status >= 0x40 and not is_v2_challenge then
        status_item:add_proto_expert_info(ef_error_status,
            "Error: " .. (STATUS_CODES[status] or "Unknown"))
    end

    local request = status == 0
    local reserved = buffer(offset + 12, 2):uint()
    if request and reserved ~= 0 then
        add_malformed(subtree, "Request reserved field is not zero")
    end
    if request and msg_type > 3 then
        add_malformed(subtree, "Request message type is outside the defined range 0..3")
    end
    if request and version ~= 0x10 and version ~= 0x20 then
        add_malformed(subtree, string.format("Unsupported protocol version 0x%02X", version))
    end

    if request and version == 0x10 then
        if pinfo.can_desegment and msg_type ~= 2 and msg_type ~= 3 then
            subtree:add_proto_expert_info(ef_transport_warning,
                "V1 TCP requests must use PASSWORD or CONNECT")
        elseif not pinfo.can_desegment and msg_type ~= 1 then
            subtree:add_proto_expert_info(ef_transport_warning,
                "V1 UDP requests must use HELLO")
        end
    end

    if version == 0x20 and msg_type == 3 and status == 0x41 and not is_v2_challenge then
        add_malformed(subtree, "V2 CONNECT challenge response is missing its nonce header")
    end

    if request and version == 0x10 then
        if msg_type == 1 and header_count ~= 0 then
            add_malformed(subtree, "V1 HELLO request must not contain headers")
        end
        if msg_type == 2 or msg_type == 3 then
            for i = 1, header_count do
                local header_offset = offset + 16 + ((i - 1) * 18)
                local id = buffer(header_offset, 1):uint()
                if msg_type == 2 and id ~= 1 and id ~= 2 then
                    add_malformed(subtree, "V1 PASSWORD request contains an unsupported header")
                elseif msg_type == 3 and id ~= 1 then
                    add_malformed(subtree, "V1 CONNECT request contains a non-password header")
                end
            end
        end
    elseif request and version == 0x20 and msg_type == 3 then
        if not is_v2_challenge_request and not is_v2_proof_request then
            add_malformed(subtree, "V2 CONNECT request does not match the challenge or proof format")
        elseif is_v2_challenge_request then
            local challenge_value = buffer(offset + 18, 16):string()
            if challenge_value ~= string.rep("\0", 16) then
                add_malformed(subtree, "V2 challenge request value must be zero-filled")
            end
        end
    end

    for i = 1, header_count do
        local header_offset = offset + 16 + ((i - 1) * 18)
        local id = buffer(header_offset, 1):uint()
        local attr = buffer(header_offset + 1, 1):uint()
        local id_str = HEADER_IDS[id] or "Unknown"
        local h_subtree = subtree:add(buffer(header_offset, 18),
            "Header " .. i .. ": " .. id_str)
        local info_range = buffer(header_offset + 2, 16)

        h_subtree:add(f_h_id, buffer(header_offset, 1))
        if id == 1 and version == 0x20 and V2_PASSWORD_ATTRS[attr] then
            h_subtree:add(f_h_v2_auth_attr, buffer(header_offset + 1, 1))
            if attr == 3 then
                h_subtree:add(f_h_v2_nonce, info_range)
            elseif attr == 4 then
                h_subtree:add(f_h_v2_digest_first, info_range)
            else
                h_subtree:add(f_h_v2_digest_second, info_range)
            end
        elseif (id == 1 or id == 2) and PASSWORD_ATTRS[attr] then
            h_subtree:add(f_h_pwd_attr, buffer(header_offset + 1, 1))
            h_subtree:add(f_h_info_str, info_range)
        elseif id == 3 then
            h_subtree:add(f_h_name_attr, buffer(header_offset + 1, 1))
            h_subtree:add(f_h_info_str, info_range)
        elseif id == 4 then
            h_subtree:add(f_h_im_type, buffer(header_offset + 1, 1))
            h_subtree:add(f_h_info_raw, info_range)
        elseif id == 5 then
            h_subtree:add(f_h_cmd_type, buffer(header_offset + 1, 1))
            h_subtree:add(f_h_info_raw, info_range)
        else
            h_subtree:add(f_h_attr, buffer(header_offset + 1, 1))
            h_subtree:add(f_h_info_raw, info_range)
        end

        if request and version == 0x10 then
            if not valid_header_attribute(version, msg_type, id, attr) then
                add_malformed(h_subtree, "Invalid V1 header ID or attribute")
            elseif (msg_type == 2 or msg_type == 3) and id == 1 and attr == 1
                and not is_printable_padded_ascii(info_range:string()) then
                add_malformed(h_subtree, "V1 password must be nonblank printable US-ASCII")
            elseif msg_type == 2 and id == 2 and attr == 1
                and not is_printable_padded_ascii(info_range:string()) then
                add_malformed(h_subtree, "V1 new password must be nonblank printable US-ASCII")
            end
        end
    end

    local info
    if is_v2_challenge then
        info = "ESC/VP.net V2 CONNECT Challenge [" .. status_str .. "]"
    elseif is_v2_challenge_request then
        info = "ESC/VP.net V2 CONNECT Challenge Request"
    elseif is_v2_proof_request then
        info = "ESC/VP.net V2 CONNECT Proof Request"
    elseif request then
        info = "ESC/VP.net Request: " .. msg_type_str
    else
        info = "ESC/VP.net Response: " .. msg_type_str .. " [" .. status_str .. "]"
    end
    return info
end

local function dissect_vp21_frame(frame_buffer, frame_data, pinfo, tree)
    local content = frame_data:gsub("\r:$", ""):gsub("\r$", "")
    local content_clean = content:gsub("[\r\n]", "")
    local subtree = tree:add(p_escvpnet, frame_buffer, "Epson ESC/VP21 Session")
    subtree:add(f_vp21_raw, frame_buffer, content_clean)

    if content_clean == ":" then
        pinfo.cols.info = "ESC/VP21 ACK (:)"
        subtree:add(f_vp21_type, frame_buffer, "ACK")
        return
    end

    local resp_cmd, resp_val = content_clean:match("^(%u+)%s*=%s*(.-)$")
    if resp_val == "" then resp_cmd = nil end
    if not resp_cmd and content_clean == "ERR" then
        pinfo.cols.info = "ESC/VP21 ERROR"
        subtree:add(f_vp21_type, frame_buffer, "Error")
        return
    end
    if resp_cmd and pinfo.src_port == 3629 and VP21_COMMANDS[resp_cmd] then
        local cmd_desc = VP21_COMMANDS[resp_cmd]
        local decoded = decode_vp21_param(resp_cmd, resp_val)
        local info = "ESC/VP21 Response: " .. cmd_desc .. " = " .. resp_val
        if decoded then info = info .. " (" .. decoded .. ")" end
        pinfo.cols.info = info
        subtree:add(f_vp21_type, frame_buffer, "Query Response")
        subtree:add(f_vp21_cmd, frame_buffer, resp_cmd)
        subtree:add(f_vp21_cmd_desc, frame_buffer, cmd_desc)
        subtree:add(f_vp21_param, frame_buffer, resp_val)
        if decoded then subtree:add(f_vp21_decoded, frame_buffer, decoded) end
        return
    end

    local query_cmd = content_clean:match("^(%u+)%?$")
    if query_cmd and VP21_COMMANDS[query_cmd] then
        local cmd_desc = VP21_COMMANDS[query_cmd]
        pinfo.cols.info = "ESC/VP21 Query: " .. cmd_desc
        subtree:add(f_vp21_type, frame_buffer, "Get (Query)")
        subtree:add(f_vp21_cmd, frame_buffer, query_cmd)
        subtree:add(f_vp21_cmd_desc, frame_buffer, cmd_desc)
        return
    end

    local set_cmd, set_param = content_clean:match("^(%u+)%s+(.+)$")
    if set_cmd and VP21_COMMANDS[set_cmd] then
        local cmd_desc = VP21_COMMANDS[set_cmd]
        local decoded = decode_vp21_param(set_cmd, set_param)
        local info = "ESC/VP21 Set: " .. cmd_desc .. " " .. set_param
        if decoded then info = info .. " (" .. decoded .. ")" end
        pinfo.cols.info = info
        subtree:add(f_vp21_type, frame_buffer, "Set Command")
        subtree:add(f_vp21_cmd, frame_buffer, set_cmd)
        subtree:add(f_vp21_cmd_desc, frame_buffer, cmd_desc)
        subtree:add(f_vp21_param, frame_buffer, set_param)
        if decoded then subtree:add(f_vp21_decoded, frame_buffer, decoded) end
        return
    end

    if pinfo.src_port == 3629 then
        pinfo.cols.info = "ESC/VP21 Unknown Response: " .. content_clean
        subtree:add(f_vp21_type, frame_buffer, "Response (Unknown)")
    else
        pinfo.cols.info = "ESC/VP21 Unknown Command: " .. content_clean
        subtree:add(f_vp21_type, frame_buffer, "Command (Unknown)")
    end
end

function p_escvpnet.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = p_escvpnet.name
    local offset = 0
    local packet_infos = {}

    while offset < length do
        local remaining = length - offset
        local remaining_data = buffer(offset, remaining):string()
        if remaining >= #SIGNATURE and remaining_data:sub(1, #SIGNATURE) == SIGNATURE then
            if remaining < 16 then
                if request_more_data(pinfo, offset, 16 - remaining) then return end
                local item = tree:add(p_escvpnet, buffer(offset, remaining),
                    "Truncated ESC/VP.net Common Header")
                add_malformed(item, "Packet is shorter than the 16-byte common header")
                return
            end

            local packet_length = 16 + (buffer(offset + 15, 1):uint() * 18)
            if remaining < packet_length then
                if request_more_data(pinfo, offset, packet_length - remaining) then return end
                local item = tree:add(p_escvpnet, buffer(offset, remaining),
                    "Truncated ESC/VP.net Packet")
                add_malformed(item, string.format("Expected %d bytes, got %d",
                    packet_length, remaining))
                return
            end

            packet_infos[#packet_infos + 1] = dissect_binary_packet(
                buffer, offset, packet_length, pinfo, tree)
            offset = offset + packet_length
        elseif remaining < #SIGNATURE and is_signature_prefix(remaining_data) then
            if request_more_data(pinfo, offset, #SIGNATURE - remaining) then return end
            local item = tree:add(p_escvpnet, buffer(offset, remaining),
                "Truncated ESC/VP.net Signature")
            add_malformed(item, "Packet ends inside the ESC/VP.net signature")
            return
        else
            break
        end
    end

    if offset == length then
        if #packet_infos > 0 then pinfo.cols.info = table.concat(packet_infos, "; ") end
        return
    end

    if not pinfo.can_desegment then
        local item = tree:add(p_escvpnet, buffer(offset, length - offset),
            "Unexpected non-ESC/VP.net UDP payload")
        add_malformed(item, "Only UDP HELLO packets are defined by the specification")
        if #packet_infos > 0 then pinfo.cols.info = table.concat(packet_infos, "; ") end
        return
    end

    local is_response = pinfo.src_port == 3629
    local stream_offset = offset
    local stream_length = length - stream_offset
    local stream_data = buffer(stream_offset, stream_length):string()
    local is_partial_signature = stream_length < #SIGNATURE and is_signature_prefix(stream_data)

    if is_partial_signature and request_more_data(pinfo, stream_offset, #SIGNATURE - stream_length) then
        if #packet_infos > 0 then pinfo.cols.info = table.concat(packet_infos, "; ") end
        return
    end

    while stream_offset < length do
        local data = buffer(stream_offset, length - stream_offset):string()
        local frame_length
        if is_response and data:sub(1, 1) == ":" then
            frame_length = 1
        elseif is_response then
            local terminator = data:find("\r:", 1, true)
            if terminator then frame_length = terminator + 1 end
        else
            local terminator = data:find("\r", 1, true)
            if terminator then frame_length = terminator end
        end

        if not frame_length then
            if request_more_data(pinfo, stream_offset) then
                if #packet_infos > 0 then pinfo.cols.info = table.concat(packet_infos, "; ") end
                return
            end
            local item = tree:add(p_escvpnet, buffer(stream_offset, length - stream_offset),
                "Incomplete ESC/VP21 Stream Data")
            add_malformed(item, "ESC/VP21 data does not contain its complete terminator")
            return
        end

        local frame_buffer = buffer(stream_offset, frame_length)
        local frame_data = frame_buffer:string()
        dissect_vp21_frame(frame_buffer, frame_data, pinfo, tree)
        stream_offset = stream_offset + frame_length
    end

    if #packet_infos > 0 then
        pinfo.cols.info = table.concat(packet_infos, "; ") .. "; " .. pinfo.cols.info
    end
end

--------------------------------------------------------------------------------
-- 4. Registration
--------------------------------------------------------------------------------
-- Register for both UDP (HELLO) and TCP (CONNECT/Session) on port 3629
local tcp_port = DissectorTable.get("tcp.port")
local udp_port = DissectorTable.get("udp.port")

tcp_port:add(3629, p_escvpnet)
udp_port:add(3629, p_escvpnet)
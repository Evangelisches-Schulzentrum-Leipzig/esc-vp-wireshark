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
local f_seq_num     = ProtoField.uint16("escvpnet.seq", "Sequence Number", base.DEC)
local f_status      = ProtoField.uint8("escvpnet.status", "Status Code", base.HEX, STATUS_CODES)
local f_hdr_count   = ProtoField.uint8("escvpnet.header_count", "Header Count", base.DEC)

-- Sub-Header Fields (18 bytes per header)
local f_h_id        = ProtoField.uint8("escvpnet.header.id", "Header ID", base.DEC, HEADER_IDS)
local f_h_attr      = ProtoField.uint8("escvpnet.header.attr", "Attribute", base.HEX)
local f_h_pwd_attr  = ProtoField.uint8("escvpnet.header.pwd_attr", "Password Attribute", base.HEX, PASSWORD_ATTRS)
local f_h_name_attr = ProtoField.uint8("escvpnet.header.name_attr", "Name Attribute", base.HEX, PROJNAME_ATTRS)
local f_h_info_str  = ProtoField.string("escvpnet.header.info", "Info String", base.ASCII)
local f_h_info_raw  = ProtoField.bytes("escvpnet.header.info_raw", "Info (Raw)")
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
    f_h_id, f_h_attr, f_h_pwd_attr, f_h_name_attr,
    f_h_info_str, f_h_info_raw, f_h_im_type, f_h_cmd_type,
    f_vp21_raw, f_vp21_type, f_vp21_cmd, f_vp21_cmd_desc,
    f_vp21_param, f_vp21_decoded
}

-- Expert Info
local ef_error_status = ProtoExpert.new("escvpnet.error_status", "Error Status",
    expert.group.RESPONSE_CODE, expert.severity.WARN)
local ef_malformed = ProtoExpert.new("escvpnet.malformed", "Malformed Packet",
    expert.group.MALFORMED, expert.severity.ERROR)

p_escvpnet.experts = { ef_error_status, ef_malformed }

--------------------------------------------------------------------------------
-- 3. Dissector Function
--------------------------------------------------------------------------------
function p_escvpnet.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = p_escvpnet.name

    -- A. BINARY PROTOCOL DETECTION (Handshake)
    -- "ESC/VP.net" is 10 bytes. The common header is 16 bytes.
    if length >= 16 and buffer(0, 10):string() == "ESC/VP.net" then

        local msg_type_val = buffer(11, 1):uint()
        local msg_type_str = MSG_TYPES[msg_type_val] or "Unknown"
        local status_val = buffer(14, 1):uint()
        local status_str = STATUS_CODES[status_val] or string.format("Unknown (0x%02X)", status_val)
        local hdr_count = buffer(15, 1):uint()

        -- Update Info Column
        if status_val == 0x00 then
            pinfo.cols.info = "ESC/VP.net Request:  " .. msg_type_str
        else
            pinfo.cols.info = "ESC/VP.net Response: " .. msg_type_str .. " [" .. status_str .. "]"
        end

        -- Create Tree
        local subtree = tree:add(p_escvpnet, buffer(), "Epson ESC/VP.net Protocol")

        -- Common Header (16 bytes)
        subtree:add(f_signature, buffer(0, 10))
        local ver_byte = buffer(10, 1):uint()
        local ver_major = math.floor(ver_byte / 16)
        local ver_minor = ver_byte % 16
        local ver_node = subtree:add(buffer(10, 1),
            string.format("Version: %d.%d (0x%02X)", ver_major, ver_minor, ver_byte))
        ver_node:add(f_ver_major, buffer(10, 1))
        ver_node:add(f_ver_minor, buffer(10, 1))

        subtree:add(f_msg_type, buffer(11, 1))
        subtree:add(f_seq_num, buffer(12, 2))
        local status_item = subtree:add(f_status, buffer(14, 1))
        -- Flag error status codes with expert info
        if status_val >= 0x40 then
            status_item:add_proto_expert_info(ef_error_status,
                "Error: " .. (STATUS_CODES[status_val] or "Unknown"))
        end
        subtree:add(f_hdr_count, buffer(15, 1))

        -- Validate expected packet length
        local expected_len = 16 + (hdr_count * 18)
        if length < expected_len then
            subtree:add_proto_expert_info(ef_malformed,
                string.format("Packet too short: expected %d bytes, got %d", expected_len, length))
        end

        -- Variable Headers Processing (Section 3)
        -- Each header is 18 bytes fixed length
        local offset = 16
        for i = 1, hdr_count do
            if offset + 18 > length then
                subtree:add_proto_expert_info(ef_malformed, "Truncated header " .. i)
                break
            end

            local h_id = buffer(offset, 1):uint()
            local h_id_str = HEADER_IDS[h_id] or "Unknown"
            local h_subtree = subtree:add(buffer(offset, 18), "Header " .. i .. ": " .. h_id_str)

            h_subtree:add(f_h_id, buffer(offset, 1))

            -- Decode Attribute and Info based on Header ID
            if h_id == 1 or h_id == 2 then
                -- Password / New-Password: attribute indicates encoding
                h_subtree:add(f_h_pwd_attr, buffer(offset + 1, 1))
                h_subtree:add(f_h_info_str, buffer(offset + 2, 16))
            elseif h_id == 3 then
                -- Projector-Name: attribute indicates encoding
                h_subtree:add(f_h_name_attr, buffer(offset + 1, 1))
                h_subtree:add(f_h_info_str, buffer(offset + 2, 16))
            elseif h_id == 4 then
                -- IM-Type: info is all 0x00 per spec
                h_subtree:add(f_h_im_type, buffer(offset + 1, 1))
                h_subtree:add(f_h_info_raw, buffer(offset + 2, 16))
            elseif h_id == 5 then
                -- Projector-Command-Type: info is all 0x00 per spec
                h_subtree:add(f_h_cmd_type, buffer(offset + 1, 1))
                h_subtree:add(f_h_info_raw, buffer(offset + 2, 16))
            else
                h_subtree:add(f_h_attr, buffer(offset + 1, 1))
                h_subtree:add(f_h_info_str, buffer(offset + 2, 16))
            end

            offset = offset + 18
        end
        return
    end

    -- B. ASCII SESSION DETECTION (ESC/VP21)
    -- After a CONNECT success, the TCP connection carries ESC/VP21 ASCII commands.
    -- Set:      "CMD PARAM\r"          (step: INC/DEC/INIT instead of PARAM)
    -- Get:      "CMD?\r"
    -- Response: "CMD=VALUE\r:"         (colon terminates every response, section 1.3)
    -- Empty:    ":"                    (ACK with no data)
    -- Error:    "ERR\r:"              (invalid command received, section 1.4)

    local content_raw = buffer():string()
    local content_clean = content_raw:gsub("[\r\n]", "")

    local subtree = tree:add(p_escvpnet, buffer(), "Epson ESC/VP21 Session")
    subtree:add(f_vp21_raw, buffer(), content_clean)

    -- ACK prompt from projector
    if content_clean == ":" then
        pinfo.cols.info = "ESC/VP21 ACK (:)"
        subtree:add(f_vp21_type, buffer(), "ACK")
        return
    end

    -- Query response: "CMD=VALUE" or "CMD=VALUE:" (from projector, src port 3629)
    -- Responses are terminated with \r: per spec (section 1.3); strip trailing colon.
    local resp_cmd, resp_val = content_clean:match("^(%u+)%s*=%s*(.-):?$")
    if resp_val == "" then resp_cmd = nil end  -- guard against bare "CMD:"

    -- Error response from projector: bare "ERR" or "ERR:" (section 1.4)
    -- Must be checked AFTER response pattern so "ERR=00" is parsed as a response.
    if not resp_cmd and content_clean:match("^ERR:?$") then
        pinfo.cols.info = "ESC/VP21 ERROR"
        subtree:add(f_vp21_type, buffer(), "Error")
        return
    end
    if resp_cmd and pinfo.src_port == 3629 and VP21_COMMANDS[resp_cmd] then
        local cmd_desc = VP21_COMMANDS[resp_cmd] or resp_cmd
        local decoded = decode_vp21_param(resp_cmd, resp_val)
        local info = "ESC/VP21 Response: " .. cmd_desc .. " = " .. resp_val
        if decoded then info = info .. " (" .. decoded .. ")" end
        pinfo.cols.info = info

        subtree:add(f_vp21_type,     buffer(), "Query Response")
        subtree:add(f_vp21_cmd,      buffer(), resp_cmd)
        subtree:add(f_vp21_cmd_desc, buffer(), cmd_desc)
        subtree:add(f_vp21_param,    buffer(), resp_val)
        if decoded then
            subtree:add(f_vp21_decoded, buffer(), decoded)
        end
        return
    end

    -- Get command: "CMD?" (from client)
    local query_cmd = content_clean:match("^(%u+)%?$")
    if query_cmd and VP21_COMMANDS[query_cmd] then
        local cmd_desc = VP21_COMMANDS[query_cmd] or query_cmd
        pinfo.cols.info = "ESC/VP21 Query: " .. cmd_desc

        subtree:add(f_vp21_type,     buffer(), "Get (Query)")
        subtree:add(f_vp21_cmd,      buffer(), query_cmd)
        subtree:add(f_vp21_cmd_desc, buffer(), cmd_desc)
        return
    end

    -- Set command: "CMD PARAM" (from client)
    local set_cmd, set_param = content_clean:match("^(%u+)%s+(.+)$")
    if set_cmd and VP21_COMMANDS[set_cmd] then
        local cmd_desc = VP21_COMMANDS[set_cmd] or set_cmd
        local decoded = decode_vp21_param(set_cmd, set_param)
        local info = "ESC/VP21 Set: " .. cmd_desc .. " " .. set_param
        if decoded then info = info .. " (" .. decoded .. ")" end
        pinfo.cols.info = info

        subtree:add(f_vp21_type,     buffer(), "Set Command")
        subtree:add(f_vp21_cmd,      buffer(), set_cmd)
        subtree:add(f_vp21_cmd_desc, buffer(), cmd_desc)
        subtree:add(f_vp21_param,    buffer(), set_param)
        if decoded then
            subtree:add(f_vp21_decoded, buffer(), decoded)
        end
        return
    end

    -- Fallback: unrecognized ASCII data
    if pinfo.src_port == 3629 then
        pinfo.cols.info = "ESC/VP21 Unknown Response: " .. content_clean
        subtree:add(f_vp21_type, buffer(), "Response (Unknown)")
    else
        pinfo.cols.info = "ESC/VP21 Unknown Command: " .. content_clean
        subtree:add(f_vp21_type, buffer(), "Command (Unknown)")
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
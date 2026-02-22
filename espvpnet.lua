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

-- ASCII Session Fields (ESC/VP21)
local f_ascii_cmd   = ProtoField.string("escvpnet.ascii_cmd", "ASCII Command")
local f_ascii_rsp   = ProtoField.string("escvpnet.ascii_rsp", "ASCII Response")

p_escvpnet.fields = {
    f_signature, f_ver_major, f_ver_minor, f_msg_type, f_seq_num,
    f_status, f_hdr_count,
    f_h_id, f_h_attr, f_h_pwd_attr, f_h_name_attr,
    f_h_info_str, f_h_info_raw, f_h_im_type, f_h_cmd_type,
    f_ascii_cmd, f_ascii_rsp
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
    -- Examples: "PWR ON\r", "VOL?\r", "LAMP=3000\r\n:", or ":" acknowledgement

    local content_raw = buffer():string()
    local content_clean = content_raw:gsub("[\r\n]", "")

    local ascii_subtree = tree:add(p_escvpnet, buffer(), "Epson ESC/VP21 Session")

    if content_clean == ":" then
        pinfo.cols.info = "ESC/VP21 ACK (:)"
        ascii_subtree:add(f_ascii_rsp, buffer(), content_clean)
    elseif content_clean == "ERR" then
        pinfo.cols.info = "ESC/VP21 ERROR"
        ascii_subtree:add(f_ascii_rsp, buffer(), content_clean)
    elseif content_clean:find("=") and pinfo.src_port == 3629 then
        -- Query response with value, e.g. "LAMP=3000"
        pinfo.cols.info = "ESC/VP21 Response: " .. content_clean
        ascii_subtree:add(f_ascii_rsp, buffer(), content_clean)
    elseif content_clean:find("?") then
        pinfo.cols.info = "ESC/VP21 Query: " .. content_clean
        ascii_subtree:add(f_ascii_cmd, buffer(), content_clean)
    else
        if pinfo.src_port == 3629 then
            pinfo.cols.info = "ESC/VP21 Response: " .. content_clean
            ascii_subtree:add(f_ascii_rsp, buffer(), content_clean)
        else
            pinfo.cols.info = "ESC/VP21 Command: " .. content_clean
            ascii_subtree:add(f_ascii_cmd, buffer(), content_clean)
        end
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
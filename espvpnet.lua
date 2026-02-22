-- ESC/VP.net Protocol Dissector for Wireshark
-- Based on: SEIKO EPSON CONFIDENTIAL - ESC/VP.net Protocol Spec

local p_escvpnet = Proto("escvpnet", "Epson ESC/VP.net Projector Protocol")

--------------------------------------------------------------------------------
-- 1. Constants & Value Strings (Mappings from PDF)
--------------------------------------------------------------------------------

-- Message Types [cite: 5]
local MSG_TYPES = {
    [1] = "HELLO",
    [2] = "PASSWORD",
    [3] = "CONNECT"
}

-- Status Codes 
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

-- Header Identifiers 
local HEADER_IDS = {
    [0] = "NULL",
    [1] = "Password",
    [2] = "New-Password",
    [3] = "Projector-Name",
    [4] = "IM-Type",
    [5] = "Projector-Command-Type"
}

-- Header Attribute: IM-Type Mappings 
local IM_TYPES = {
    [0x0C] = "Type D",
    [0x10] = "Type A", [0x11]="Type A", [0x12]="Type A", [0x13]="Type A",
    [0x20] = "EMP/PL-735 Initial",
    [0x21] = "Type C / Type E",
    [0x22] = "Type F",
    [0x23] = "Type G",
    [0x30] = "Type B",
    [0x40] = "Type H",
    [0x41] = "Type I",
    [0x42] = "Type J",
    [0x50] = "Type K"
}

-- Header Attribute: Command Types [cite: 38]
local CMD_TYPES = {
    [0x16] = "ESC/VP Level 6",
    [0x21] = "ESC/VP21 Ver1.0"
}

--------------------------------------------------------------------------------
-- 2. Define Protocol Fields
--------------------------------------------------------------------------------

-- Common Header Fields (16 bytes)
local f_signature   = ProtoField.string("escvpnet.signature", "Signature", base.ASCII)
local f_ver_major   = ProtoField.uint8("escvpnet.version.major", "Major Version", base.HEX, nil, 0xF0)
local f_ver_minor   = ProtoField.uint8("escvpnet.version.minor", "Minor Version", base.HEX, nil, 0x0F)
local f_msg_type    = ProtoField.uint8("escvpnet.type", "Message Type", base.DEC, MSG_TYPES)
local f_seq_num     = ProtoField.uint16("escvpnet.seq", "Sequence Number", base.DEC)
local f_status      = ProtoField.uint8("escvpnet.status", "Status Code", base.HEX, STATUS_CODES)
local f_hdr_count   = ProtoField.uint8("escvpnet.header_count", "Header Count", base.DEC)

-- Sub-Header Fields (18 bytes per header)
local f_h_id        = ProtoField.uint8("escvpnet.header.id", "Header ID", base.DEC, HEADER_IDS)
local f_h_attr      = ProtoField.uint8("escvpnet.header.attr", "Attribute", base.HEX)
local f_h_info_str  = ProtoField.string("escvpnet.header.info", "Info String", base.ASCII)
local f_h_im_type   = ProtoField.uint8("escvpnet.header.im_type", "IM Type Model", base.HEX, IM_TYPES)
local f_h_cmd_type  = ProtoField.uint8("escvpnet.header.cmd_type", "Command System", base.HEX, CMD_TYPES)

-- ASCII Session Fields (ESC/VP21)
local f_ascii_cmd   = ProtoField.string("escvpnet.ascii_cmd", "ASCII Command")
local f_ascii_rsp   = ProtoField.string("escvpnet.ascii_rsp", "ASCII Response")

p_escvpnet.fields = {
    f_signature, f_ver_major, f_ver_minor, f_msg_type, f_seq_num,
    f_status, f_hdr_count,
    f_h_id, f_h_attr, f_h_info_str, f_h_im_type, f_h_cmd_type,
    f_ascii_cmd, f_ascii_rsp
}

--------------------------------------------------------------------------------
-- 3. Dissector Function
--------------------------------------------------------------------------------
function p_escvpnet.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = p_escvpnet.name

    -- A. BINARY PROTOCOL DETECTION (Handshake)
    -- "ESC/VP.net" is 10 bytes. The header is 16 bytes minimum.
    if length >= 16 and buffer(0, 10):string() == "ESC/VP.net" then
        
        local msg_type_val = buffer(11,1):uint()
        local msg_type_str = MSG_TYPES[msg_type_val] or "Unknown"
        local status_val = buffer(14,1):uint()
        local status_str = STATUS_CODES[status_val] or "Unknown"
        
        -- Update Info Column
        if status_val == 0 then
            pinfo.cols.info = "Request: " .. msg_type_str
        else
            pinfo.cols.info = "Response: " .. msg_type_str .. " [" .. status_str .. "]"
        end

        -- Create Tree
        local subtree = tree:add(p_escvpnet, buffer(), "Epson ESC/VP.net Handshake")
        
        -- Common Header (16 bytes) [cite: 5]
        subtree:add(f_signature, buffer(0, 10))
        local ver_node = subtree:add(buffer(10,1), "Version")
        ver_node:add(f_ver_major, buffer(10, 1))
        ver_node:add(f_ver_minor, buffer(10, 1))
        
        subtree:add(f_msg_type, buffer(11, 1))
        subtree:add(f_seq_num, buffer(12, 2))
        subtree:add(f_status, buffer(14, 1))
        
        local hdr_count = buffer(15, 1):uint()
        subtree:add(f_hdr_count, buffer(15, 1))

        -- Variable Headers Processing [cite: 13]
        -- Each header is 18 bytes fixed length
        local offset = 16
        for i = 1, hdr_count do
            if offset + 18 > length then break end -- Safety check
            
            local h_subtree = subtree:add(buffer(offset, 18), "Header " .. i)
            local h_id = buffer(offset, 1):uint()
            
            h_subtree:add(f_h_id, buffer(offset, 1))
            
            -- Decode Attribute based on ID 
            if h_id == 4 then -- IM-Type
                h_subtree:add(f_h_im_type, buffer(offset + 1, 1))
            elseif h_id == 5 then -- Projector-Command-Type
                h_subtree:add(f_h_cmd_type, buffer(offset + 1, 1))
            else
                h_subtree:add(f_h_attr, buffer(offset + 1, 1))
            end
            
            h_subtree:add(f_h_info_str, buffer(offset + 2, 16))
            
            offset = offset + 18
        end
        return
    end

    -- B. ASCII SESSION DETECTION (ESC/VP21) [cite: 83]
    -- If we are here, it's likely an open session sending ASCII commands.
    -- (e.g., "PWR ON\r", "VOL?\r", or ":" responses)
    
    local content_raw = buffer():string()
    local content_clean = content_raw:gsub("[\r\n]", "") -- Remove CR/LF for display

    local ascii_subtree = tree:add(p_escvpnet, buffer(), "Epson Command Session (ESC/VP21)")

    if content_clean == ":" then
        pinfo.cols.info = "ACK (:)"
        ascii_subtree:add(f_ascii_rsp, buffer(), content_clean)
    elseif content_clean == "ERR" then
        pinfo.cols.info = "ERROR (ERR)"
        ascii_subtree:add(f_ascii_rsp, buffer(), content_clean)
    elseif content_clean:find("?") then
        pinfo.cols.info = "Query: " .. content_clean
        ascii_subtree:add(f_ascii_cmd, buffer(), content_clean)
    else
        -- Heuristic: If src port is 3629, it's likely a value response (e.g. "LAMP=3000")
        if pinfo.src_port == 3629 then
            pinfo.cols.info = "Response Val: " .. content_clean
            ascii_subtree:add(f_ascii_rsp, buffer(), content_clean)
        else
            pinfo.cols.info = "Command: " .. content_clean
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
-- ESC/VP.net Protocol Dissector for Wireshark
-- Save this file as "escvpnet.lua" and load it into Wireshark

-- 1. Create the protocol object
local p_escvpnet = Proto("escvpnet", "Epson ESC/VP.net Projector Protocol")

-- 2. Define the protocol fields
local f_signature  = ProtoField.string("escvpnet.signature", "Signature", base.ASCII)
local f_version_mj = ProtoField.uint8("escvpnet.version_major", "Version Major", base.HEX)
local f_version_mn = ProtoField.uint8("escvpnet.version_minor", "Version Minor", base.HEX)
local f_reserved   = ProtoField.bytes("escvpnet.reserved", "Reserved/Padding", base.SPACE)

local f_command    = ProtoField.string("escvpnet.command", "Command String", base.ASCII)
local f_response   = ProtoField.string("escvpnet.response", "Response String", base.ASCII)
local f_type       = ProtoField.string("escvpnet.type", "Type") -- Info column type

-- Add fields to the protocol
p_escvpnet.fields = {
    f_signature, f_version_mj, f_version_mn, f_reserved,
    f_command, f_response, f_type
}

-- 3. Define the dissector function
function p_escvpnet.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    -- Set the Protocol Name in the packet list
    pinfo.cols.protocol = p_escvpnet.name

    -- Create the protocol tree
    local subtree = tree:add(p_escvpnet, buffer(), "Epson ESC/VP.net Data")

    -- HANDSHAKE DETECTION
    -- The connection handshake is a fixed 16-byte binary sequence:
    -- "ESC/VP.net" (10 bytes) + Ver (1 byte) + Ver (1 byte) + Padding (4 bytes)
    if length >= 10 and buffer(0, 10):string() == "ESC/VP.net" then
        pinfo.cols.info = "Connection Handshake"
        
        subtree:add(f_signature, buffer(0, 10))
        
        if length >= 16 then
            subtree:add(f_version_mj, buffer(10, 1))
            subtree:add(f_version_mn, buffer(11, 1))
            subtree:add(f_reserved, buffer(12, 4))
        end
        return
    end

    -- COMMAND / RESPONSE DETECTION (ASCII)
    -- Subsequent traffic is ASCII text terminated by CR (0x0D)
    
    -- Heuristic to distinguish Command vs Response
    -- Responses are usually ":" (Success) or "ERR"
    local content = buffer():string()
    
    -- Clean up CR/LF for display
    local clean_content = content:gsub("\r", ""):gsub("\n", "")
    
    if clean_content == ":" then
        pinfo.cols.info = "Response: ACK (:)"
        subtree:add(f_response, buffer(), clean_content)
    elseif clean_content == "ERR" then
        pinfo.cols.info = "Response: ERROR"
        subtree:add(f_response, buffer(), clean_content)
    elseif clean_content:find("?") then
        pinfo.cols.info = "Query: " .. clean_content
        subtree:add(f_command, buffer(), clean_content)
    elseif clean_content:match("^%w") then
        -- If it starts with alphanumeric, assume it's a command or value return
        if pinfo.src_port == 3629 then
            pinfo.cols.info = "Response Value: " .. clean_content
            subtree:add(f_response, buffer(), clean_content)
        else
            pinfo.cols.info = "Command: " .. clean_content
            subtree:add(f_command, buffer(), clean_content)
        end
    else
        -- Fallback for unknown data
        pinfo.cols.info = "Data: " .. clean_content
        subtree:add(f_command, buffer(), clean_content)
    end
end

-- 4. Register the dissector
-- The default port for Epson ESC/VP.net is TCP 3629
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(3629, p_escvpnet)
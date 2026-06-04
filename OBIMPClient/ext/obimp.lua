-- OBIMP (Open Binary Instant Messaging Protocol) Wireshark Dissector
-- Draft 1.1, Revision C
-- Установить в ~/.local/lib/wireshark/plugins/ или %APPDATA%\Wireshark\plugins\

local obimp_proto = Proto("obimp", "Open Binary Instant Messaging Protocol")

-- =============================================================================
-- PROTO FIELDS
-- =============================================================================
local f_header_start   = ProtoField.uint8("obimp.header.start", "Header Start", base.HEX)
local f_header_seq     = ProtoField.uint32("obimp.header.seq", "Sequence", base.DEC)
local f_header_bex     = ProtoField.uint16("obimp.header.bex_type", "BEX Type", base.HEX)
local f_header_sub     = ProtoField.uint16("obimp.header.bex_subtype", "BEX Subtype", base.HEX)
local f_header_reqid   = ProtoField.uint32("obimp.header.req_id", "Request ID", base.DEC)
local f_header_datalen = ProtoField.uint32("obimp.header.data_len", "Following Data Length", base.DEC)

local f_wtld_type      = ProtoField.uint32("obimp.wtld.type", "wTLD Type", base.HEX)
local f_wtld_len       = ProtoField.uint32("obimp.wtld.len", "wTLD Length", base.DEC)
local f_wtld_data      = ProtoField.bytes("obimp.wtld.data", "wTLD Data")

local f_stld_type      = ProtoField.uint16("obimp.stld.type", "sTLD Type", base.HEX)
local f_stld_len       = ProtoField.uint16("obimp.stld.len", "sTLD Length", base.DEC)
local f_stld_data      = ProtoField.bytes("obimp.stld.data", "sTLD Data")

obimp_proto.fields = {
    f_header_start, f_header_seq, f_header_bex, f_header_sub, f_header_reqid, f_header_datalen,
    f_wtld_type, f_wtld_len, f_wtld_data,
    f_stld_type, f_stld_len, f_stld_data
}

-- =============================================================================
-- LOOKUP TABLES
-- =============================================================================
local BEX_NAMES = {
    [0x0001] = "Common (COM)", [0x0002] = "Contact List (CL)", [0x0003] = "Presence (PRES)",
    [0x0004] = "Instant Messaging (IM)", [0x0005] = "Users Directory (UD)", [0x0006] = "User Avatars (UA)",
    [0x0007] = "File Transfer (FT)", [0x0008] = "Transports (TP)"
}

local SUB_NAMES = {
    [0x0001] = {
        [0x0001]="CLI_HELLO", [0x0002]="SRV_HELLO", [0x0003]="CLI_LOGIN", [0x0004]="SRV_LOGIN_REPLY",
        [0x0005]="SRV_BYE", [0x0006]="CLI_SRV_KEEPALIVE_PING", [0x0007]="CLI_SRV_KEEPALIVE_PONG",
        [0x0008]="CLI_REGISTER", [0x0009]="SRV_REGISTER_REPLY"
    },
    [0x0002] = {
        [0x0001]="CLI_PARAMS", [0x0002]="SRV_PARAMS_REPLY", [0x0003]="CLI_REQUEST", [0x0004]="SRV_REPLY",
        [0x0005]="CLI_VERIFY", [0x0006]="SRV_VERIFY_REPLY", [0x0007]="CLI_ADD_ITEM", [0x0008]="SRV_ADD_ITEM_REPLY",
        [0x0009]="CLI_DEL_ITEM", [0x000A]="SRV_DEL_ITEM_REPLY", [0x000B]="CLI_UPD_ITEM", [0x000C]="SRV_UPD_ITEM_REPLY",
        [0x000D]="CLI_SRV_AUTH_REQUEST", [0x000E]="CLI_SRV_AUTH_REPLY", [0x000F]="CLI_SRV_AUTH_REVOKE",
        [0x0010]="CLI_REQ_OFFAUTH", [0x0011]="SRV_DONE_OFFAUTH", [0x0012]="CLI_DEL_OFFAUTH",
        [0x0013]="SRV_ITEM_OPER", [0x0014]="SRV_BEGIN_UPDATE", [0x0015]="SRV_END_UPDATE"
    },
    [0x0003] = {
        [0x0001]="CLI_PARAMS", [0x0002]="SRV_PARAMS_REPLY", [0x0003]="CLI_SET_PRES_INFO", [0x0004]="CLI_SET_STATUS",
        [0x0005]="CLI_ACTIVATE", [0x0006]="SRV_CONTACT_ONLINE", [0x0007]="SRV_CONTACT_OFFLINE",
        [0x0008]="CLI_REQ_PRES_INFO", [0x0009]="SRV_PRES_INFO", [0x000A]="SRV_MAIL_NOTIF",
        [0x000B]="CLI_REQ_OWN_MAIL_URL", [0x000C]="SRV_OWN_MAIL_URL"
    },
    [0x0004] = {
        [0x0001]="CLI_PARAMS", [0x0002]="SRV_PARAMS_REPLY", [0x0003]="CLI_REQ_OFFLINE", [0x0004]="SRV_DONE_OFFLINE",
        [0x0005]="CLI_DEL_OFFLINE", [0x0006]="CLI_MESSAGE", [0x0007]="SRV_MESSAGE", [0x0008]="CLI_SRV_MSG_REPORT",
        [0x0009]="CLI_SRV_NOTIFY", [0x000A]="CLI_SRV_ENCRYPT_KEY_REQ", [0x000B]="CLI_SRV_ENCRYPT_KEY_REPLY",
        [0x000C]="CLI_MULTIPLE_MSG"
    },
    [0x0005] = {
        [0x0001]="CLI_PARAMS", [0x0002]="SRV_PARAMS_REPLY", [0x0003]="CLI_DETAILS_REQ", [0x0004]="SRV_DETAILS_REQ_REPLY",
        [0x0005]="CLI_DETAILS_UPD", [0x0006]="SRV_DETAILS_UPD_REPLY", [0x0007]="CLI_SEARCH", [0x0008]="SRV_SEARCH_REPLY",
        [0x0009]="CLI_SECURE_UPD", [0x000A]="SRV_SECURE_UPD_REPLY"
    },
    [0x0006] = {
        [0x0001]="CLI_PARAMS", [0x0002]="SRV_PARAMS_REPLY", [0x0003]="CLI_AVATAR_REQ", [0x0004]="SRV_AVATAR_REPLY",
        [0x0005]="CLI_AVATAR_SET", [0x0006]="SRV_AVATAR_SET_REPLY"
    },
    [0x0007] = {
        [0x0001]="CLI_PARAMS", [0x0002]="SRV_PARAMS_REPLY", [0x0003]="CLI_SRV_SEND_FILE_REQUEST",
        [0x0004]="CLI_SRV_SEND_FILE_REPLY", [0x0005]="CLI_SRV_CONTROL",
        [0x0101]="DIR_PROX_ERROR", [0x0102]="DIR_PROX_HELLO", [0x0103]="DIR_PROX_FILE",
        [0x0104]="DIR_PROX_FILE_REPLY", [0x0105]="DIR_PROX_FILE_DATA"
    },
    [0x0008] = {
        [0x0001]="CLI_PARAMS", [0x0002]="SRV_PARAMS_REPLY", [0x0003]="SRV_ITEM_READY",
        [0x0004]="CLI_SETTINGS", [0x0005]="SRV_SETTINGS_REPLY", [0x0006]="CLI_MANAGE",
        [0x0007]="SRV_TRANSPORT_INFO", [0x0008]="SRV_SHOW_NOTIF", [0x0009]="SRV_OWN_AVATAR_HASH"
    }
}

-- Enum справочники
local HELLO_ERRORS = {[1]="ACCOUNT_INVALID",[2]="SERVICE_TEMP_UNAVAILABLE",[3]="ACCOUNT_BANNED",[4]="WRONG_COOKIE",[5]="TOO_MANY_CLIENTS",[6]="INVALID_LOGIN"}
local LOGIN_ERRORS = {[1]="ACCOUNT_INVALID",[2]="SERVICE_TEMP_UNAVAILABLE",[3]="ACCOUNT_BANNED",[4]="WRONG_PASSWORD",[5]="INVALID_LOGIN"}
local BYE_REASONS  = {[1]="SRV_SHUTDOWN",[2]="CLI_NEW_LOGIN",[3]="ACCOUNT_KICKED",[4]="INCORRECT_SEQ",[5]="INCORRECT_BEX_TYPE",[6]="INCORRECT_BEX_SUB",[7]="INCORRECT_BEX_STEP",[8]="TIMEOUT",[9]="INCORRECT_WTLD",[10]="NOT_ALLOWED",[11]="FLOODING"}
local PRES_STATUS  = {[0]="ONLINE",[1]="INVISIBLE",[2]="INVISIBLE_FOR_ALL",[3]="FREE_FOR_CHAT",[4]="AT_HOME",[5]="AT_WORK",[6]="LUNCH",[7]="AWAY",[8]="NOT_AVAILABLE",[9]="OCCUPIED",[10]="DO_NOT_DISTURB"}
local PRIV_TYPES   = {[0]="NONE",[1]="VISIBLE_LIST",[2]="INVISIBLE_LIST",[3]="IGNORE_LIST",[4]="IGNORE_NOT_IN_LIST"}
local NOTE_TYPES   = {[0]="TEXT",[1]="COMMAND",[2]="LINK",[3]="EMAIL",[4]="PHONE"}
local MSG_TYPES    = {[1]="UTF-8",[2]="RTF",[3]="HTML"}
local ENC_TYPES    = {[0]="DISABLED",[1]="OBIMP_TDES_RSA1024",[2]="PGP"}
local AUTH_REPLY   = {[1]="GRANTED",[2]="DENIED"}
local OPER_CODES   = {[1]="ADD_ITEM",[2]="DEL_ITEM",[3]="UPD_ITEM"}
local CL_ITEM_TYPE = {[1]="GROUP",[2]="CONTACT",[3]="TRANSPORT",[4]="NOTE"}

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================
local function safe_utf8(tvb, offset, len)
    if len == 0 then return "" end
    local ok, val = pcall(function() return tvb:range(offset, len):string() end)
    return ok and val or "<non-utf8> " .. tvb:range(offset, len):tohex()
end

local function parse_stld_array(tvb, tree, offset, max_offset)
    local base = offset
    while offset < max_offset do
        if offset + 4 > max_offset then break end
        local stld_type = tvb:range(offset, 2):uint()
        local stld_len  = tvb:range(offset+2, 2):uint()
        local stld_data_off = offset + 4
        if stld_data_off + stld_len > max_offset then break end

        local stld_tree = tree:add(obimp_proto, tvb(offset, 4 + stld_len), string.format("sTLD 0x%04X", stld_type))
        stld_tree:add(f_stld_type, tvb(offset, 2))
        stld_tree:add(f_stld_len, tvb(offset+2, 2))
        stld_tree:add(f_stld_data, tvb(stld_data_off, stld_len))

        -- Автоматическая попытка отобразить как UTF-8 или HEX
        local val = safe_utf8(tvb, stld_data_off, stld_len)
        stld_tree:append_text(" = " .. val)
        offset = stld_data_off + stld_len
    end
    return offset
end

-- Парсер сложной структуры Contact List Blob (wTLD 0x0001 в BEX 0x0002/0x0004)
local function parse_cl_blob(tvb, tree, offset, len)
    local end_off = offset + len
    if offset + 4 > end_off then return end_off end
    local items_count = tvb:range(offset, 4):uint()
    local items_tree = tree:add(obimp_proto, tvb(offset, 4), "Contact List Items Count: " .. items_count)
    offset = offset + 4

    for i = 1, items_count do
        if offset + 12 > end_off then break end
        local item_type = tvb:range(offset, 2):uint()
        local item_id   = tvb:range(offset+2, 4):uint()
        local group_id  = tvb:range(offset+6, 4):uint()
        local stld_len  = tvb:range(offset+10, 4):uint()

        local item_tree = tree:add(obimp_proto, tvb(offset, 14 + stld_len), "Contact List Item #" .. i)
        item_tree:add(obimp_proto, tvb(offset, 2), "Item Type: 0x" .. string.format("%04X", item_type) .. " (" .. (CL_ITEM_TYPE[item_type] or "Unknown") .. ")")
        item_tree:add(obimp_proto, tvb(offset+2, 4), "Item ID: " .. item_id)
        item_tree:add(obimp_proto, tvb(offset+6, 4), "Group ID: " .. group_id)
        item_tree:add(obimp_proto, tvb(offset+10, 4), "sTLDs Length: " .. stld_len)
        offset = offset + 14
        if stld_len > 0 then offset = parse_stld_array(tvb, item_tree, offset, offset + stld_len) end
    end
    return end_off
end

-- Парсер массива опций транспорта (wTLD 0x0002 в BEX 0x0008/0x0003)
local function parse_tp_options_array(tvb, tree, offset, len)
    local end_off = offset + len
    if offset + 4 > end_off then return end_off end
    local settings_flags = tvb:range(offset, 2):uint()
    local options_count  = tvb:range(offset+2, 2):uint()
    local opts_tree = tree:add(obimp_proto, tvb(offset, 4), string.format("Options Array (Flags: 0x%04X, Count: %d)", settings_flags, options_count))
    offset = offset + 4

    for i = 1, options_count do
        if offset + 11 > end_off then break end
        local opt_len   = tvb:range(offset, 2):uint()
        local opt_id    = tvb:range(offset+2, 2):uint()
        local opt_type  = tvb:range(offset+4, 1):uint()
        local opt_flags = tvb:range(offset+5, 4):uint()
        local name_len  = tvb:range(offset+9, 2):uint()
        local name_val  = safe_utf8(tvb, offset+11, name_len)
        local value_len = opt_len - 11 - name_len
        local value_val = safe_utf8(tvb, offset+11+name_len, value_len)

        local opt_tree = opts_tree:add(obimp_proto, tvb(offset, opt_len), string.format("Option #%d (ID: 0x%04X)", i, opt_id))
        opt_tree:add(obimp_proto, tvb(offset, 2), "Option Length: " .. opt_len)
        opt_tree:add(obimp_proto, tvb(offset+2, 2), "Option ID: 0x" .. string.format("%04X", opt_id))
        opt_tree:add(obimp_proto, tvb(offset+4, 1), "Type: " .. opt_type)
        opt_tree:add(obimp_proto, tvb(offset+5, 4), "Flags: 0x" .. string.format("%08X", opt_flags))
        opt_tree:add(obimp_proto, tvb(offset+9, 2), "Name Length: " .. name_len)
        opt_tree:add(obimp_proto, tvb(offset+11, name_len), "Name: " .. name_val)
        opt_tree:add(obimp_proto, tvb(offset+11+name_len, value_len), "Value: " .. value_val)
        offset = offset + opt_len
    end
    return end_off
end

-- =============================================================================
-- CONTEXT-AWARE WTLD PARSER
-- =============================================================================
local function parse_wtld_context(tvb, tree, offset, wtld_type, wtld_len, bex_type, bex_sub)
    local data_off = offset
    local val

    -- Специфичный разбор известных wTLD
    if bex_type == 0x0001 then -- Common
        if wtld_type == 0x0001 then
            val = safe_utf8(tvb, data_off, wtld_len)
            tree:append_text(" (Account: " .. val .. ")")
        elseif wtld_type == 0x0002 then tree:append_text(" (Server Cookie/Key)")
        elseif wtld_type == 0x0003 then tree:append_text(" (Registration Flag/Redirect Host)")
        elseif wtld_type == 0x0004 then tree:append_text(" (Redirect Port: " .. tvb:range(data_off, 4):uint() .. ")")
        elseif wtld_type == 0x0005 and bex_sub == 0x0002 then tree:append_text(" (Registration Enabled: " .. (tvb:range(data_off, 1):uint() == 1 and "True" or "False") .. ")")
        elseif wtld_type == 0x0006 then tree:append_text(" (Reg URL: " .. safe_utf8(tvb, data_off, wtld_len) .. ")")
        elseif wtld_type == 0x0007 and bex_sub == 0x0002 then tree:append_text(" (Plain-text Auth Required)")
        elseif wtld_type == 0x0001 and bex_sub == 0x0005 then
            local code = tvb:range(data_off, 2):uint()
            tree:append_text(" (Bye Reason: " .. (BYE_REASONS[code] or "Unknown") .. ")")
        end
    elseif bex_type == 0x0002 and wtld_type == 0x0001 and bex_sub == 0x0004 then
        return parse_cl_blob(tvb, tree, data_off, wtld_len)
    elseif bex_type == 0x0004 then -- IM
        if wtld_type == 0x0001 then tree:append_text(" (Account: " .. safe_utf8(tvb, data_off, wtld_len) .. ")")
        elseif wtld_type == 0x0002 then tree:append_text(" (Msg ID: " .. tvb:range(data_off, 4):uint() .. ")")
        elseif wtld_type == 0x0003 then
            local t = tvb:range(data_off, 4):uint()
            tree:append_text(" (Msg Type: " .. (MSG_TYPES[t] or "Unknown") .. ")")
        elseif wtld_type == 0x0004 then tree:append_text(" (Message Data [" .. wtld_len .. " bytes])")
        elseif wtld_type == 0x0006 then
            local e = tvb:range(data_off, 4):uint()
            tree:append_text(" (Encryption: " .. (ENC_TYPES[e] or "Unknown") .. ")")
        end
    elseif bex_type == 0x0008 and wtld_type == 0x0002 and bex_sub == 0x0003 then
        return parse_tp_options_array(tvb, tree, data_off, wtld_len)
    end

    -- Fallback: отображение данных в виде UTF-8 или HEX
    local fallback = safe_utf8(tvb, data_off, wtld_len)
    tree:add(f_wtld_data, tvb(data_off, wtld_len))
    tree:append_text(" [" .. wtld_len .. "B] = " .. (fallback ~= "" and fallback or "<binary>"))
    return data_off + wtld_len
end

-- =============================================================================
-- MAIN DISSECTOR
-- =============================================================================
function obimp_proto.dissector(tvb, pinfo, tree)
    local pkt_len = tvb:len()
    if pkt_len < 17 then return 0 end

    pinfo.cols.protocol = "OBIMP"
    local obimp_tree = tree:add(obimp_proto, tvb(), "Open Binary Instant Messaging Protocol")

    local offset = 0
    local start_byte = tvb:range(offset, 1):uint()
    if start_byte ~= 0x23 then return 0 end
    obimp_tree:add(f_header_start, tvb(offset, 1)); offset = offset + 1

    local seq     = tvb:range(offset, 4):uint(); obimp_tree:add(f_header_seq, tvb(offset, 4)); offset = offset + 4
    local bex     = tvb:range(offset, 2):uint(); obimp_tree:add(f_header_bex, tvb(offset, 2)):append_text(" (" .. (BEX_NAMES[bex] or "Unknown") .. ")"); offset = offset + 2
    local sub     = tvb:range(offset, 2):uint(); obimp_tree:add(f_header_sub, tvb(offset, 2)):append_text(" (" .. ((SUB_NAMES[bex] and SUB_NAMES[bex][sub]) or "Unknown") .. ")"); offset = offset + 2
    local req_id  = tvb:range(offset, 4):uint(); obimp_tree:add(f_header_reqid, tvb(offset, 4)); offset = offset + 4
    local data_len= tvb:range(offset, 4):uint(); obimp_tree:add(f_header_datalen, tvb(offset, 4)); offset = offset + 4

    pinfo.cols.info = string.format("%s / %s / Req:%d", BEX_NAMES[bex] or "Unknown", (SUB_NAMES[bex] and SUB_NAMES[bex][sub]) or "Unknown", req_id)

    if pkt_len < 17 + data_len then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return 0
    end

    local payload_end = 17 + data_len
    local payload_tree = obimp_tree:add(obimp_proto, tvb(offset, data_len), "Payload Data")

    while offset < payload_end do
        if offset + 8 > payload_end then break end
        local wtld_type = tvb:range(offset, 4):uint()
        local wtld_len  = tvb:range(offset+4, 4):uint()
        local wtld_data_off = offset + 8
        if wtld_data_off + wtld_len > payload_end then break end

        local wtld_tree = payload_tree:add(obimp_proto, tvb(offset, 8 + wtld_len), string.format("wTLD 0x%04X", wtld_type))
        wtld_tree:add(f_wtld_type, tvb(offset, 4))
        wtld_tree:add(f_wtld_len, tvb(offset+4, 4))

        offset = parse_wtld_context(tvb, wtld_tree, wtld_data_off, wtld_type, wtld_len, bex, sub)
    end

    return payload_end
end

-- =============================================================================
-- REGISTRATION
-- =============================================================================
local tcp_port = DissectorTable.get("tcp.port")
for _, port in ipairs({7023, 7024, 7025, 7033, 7034, 7035}) do
    tcp_port:add(port, obimp_proto)
end
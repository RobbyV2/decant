-- Cheat Engine autorun probe for the Decant interposer + mock guest.
-- Copy into the CE install's autorun/ folder (name sorts first so it runs
-- before CE's own autorun scripts) and launch CE through wine-env/run.sh.
-- Writes results to C:\decant_probe.txt.

local out = io.open([[C:\decant_probe.txt]], "w")
local function log(s) out:write(tostring(s) .. "\n") out:flush() end

local sig = "44 45 43 41 4E 54 3A 3A 4D 41 47 49 43 00 DE AD"
local expect = {0x44,0x45,0x43,0x41,0x4E,0x54,0x3A,0x3A,0x4D,0x41,0x47,0x49,0x43,0x00,0xDE,0xAD}
local magic_addr = 0x140010100
local slot_addr = 0x140010400
local pass = true
local function check(name, ok, detail)
  if not ok then pass = false end
  log(string.format("%-20s %s  %s", name, ok and "PASS" or "FAIL", detail or ""))
end

local okhk, patched = pcall(function() return executeCodeLocal("decant_interpose.decant_install_hooks") end)
log("reinstall_hooks=" .. tostring(okhk and patched or ("err:" .. tostring(patched))))

local ok, plist = pcall(getProcessList)
local found = false
if ok and type(plist) == "table" then
  for k, v in pairs(plist) do
    if (tostring(k) .. ":" .. tostring(v)):lower():find("decant%-target") then found = true end
  end
end
check("enumProcesses", ok and found, "decant-target.exe present=" .. tostring(found))

pcall(function() openProcess("decant-target.exe") end)
local opid = getOpenedProcessID()
if opid == 0 or opid == nil then pcall(function() openProcess(1234) end) opid = getOpenedProcessID() end
local okh, handle = pcall(getOpenedProcessHandle)
log(string.format("openedHandle=0x%x (carafe handles are 0xdec0...)", okh and handle or 0))
check("openProcess", opid == 1234, "openedPID=" .. tostring(opid))

local okr, bytes = pcall(function() return readBytes(magic_addr, 16, true) end)
local rmatch, got = false, ""
if okr and type(bytes) == "table" and #bytes == 16 then
  rmatch = true
  for i = 1, 16 do
    got = got .. string.format("%02X ", bytes[i])
    if bytes[i] ~= expect[i] then rmatch = false end
  end
end
check("readBytes_magic", rmatch, "got=" .. got)

local oks, results = pcall(function() return AOBScan(sig) end)
local hits = {}
if oks and results ~= nil then
  for i = 0, results.Count - 1 do hits[#hits + 1] = results[i] end
  results.destroy()
end
local sfound = false
for _, a in ipairs(hits) do if tonumber(a, 16) == magic_addr then sfound = true end end
check("AOBScan", sfound, "hits=" .. table.concat(hits, ",") .. " (count=" .. #hits .. ")")

local okw = pcall(function() writeBytes(slot_addr, 0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04) end)
local okrb, rb = pcall(function() return readBytes(slot_addr, 8, true) end)
local wexp = {0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04}
local wmatch, rbs = okw and okrb and type(rb) == "table" and #rb == 8, ""
if okrb and type(rb) == "table" then
  for i = 1, #rb do
    rbs = rbs .. string.format("%02X ", rb[i])
    if rb[i] ~= wexp[i] then wmatch = false end
  end
end
check("writeBytes_slot", wmatch, "readback=" .. rbs)

log("")
log(pass and "RESULT ALL PASS" or "RESULT SOME FAIL")
out:close()
closeCE()

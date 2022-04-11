import idaapi
import idautils
import idc

def GetFilePath():
    return "C:\\Games\\SkyrimMods\\RETools\\Data\\"
    
def IsUserName(ea):
    functionFlags = idc.GetFunctionFlags(ea)
    if functionFlags != -1 and (functionFlags & idc.FUNC_LIB or functionFlags & idc.FUNC_THUNK):
        return False
    return idc.hasUserName(idc.GetFlags(ea))

def GetStr(num):
    return "%X" % num

print "Beginning export\n"

handle = open(GetFilePath() + "idanames.txt", "w")
handle.truncate()
for key, value in Names():
    if IsUserName(key) != True:
        continue
    if value.startswith("jpt_") or value.startswith("def_"):
        continue
    handle.write(GetStr(key))
    handle.write("\t")
    handle.write(value)
    handle.write("\t")
    name_str = Demangle(value, GetLongPrm(INF_SHORT_DN))
    if name_str:
        handle.write(name_str)
    handle.write("\n")
handle.close()

print "Done with export\n"

Wireshark plugin to parser snmp protocol
==========================================

Put two lua files under your wireshark installed directory

to make them effective, edit init.lua:
'''
disable_lua = false

if disable_lua then
    return
end
'''

'''
dofile(DATA_DIR.."console.lua")
'''

then, when you open wireshark application, lua plugin take effect, it will parse snmp protocol when the packet meet criteria

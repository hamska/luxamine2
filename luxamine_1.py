# -*- coding: utf-8 -*-
# This Python script is a direct port of the provided Lua script.
# It intentionally preserves the original logic and behavior.

copyright = ''
author = 'PLS'
version = 'v0.0.1'
desc = """
This is a script to decrypt the data of a specific type of Mifare token called Amine tag.
Input file is an eml file without extension.
"""
example = """
    script run luxeodecode -i myfile-unciphered -c
    script run luxeodecode -i myfile-ciphered -o myfile-unciphered
"""
usage = """
script run luxeodecode -i [myfile] [-o [myoutputfile] ] [-c]
"""

# Changer les valeurs ici
emlfile = "nouveau.eml"  # fichier in
cipher = True            # si cipher=True, on crypt, sinon on decrypt

# the AZTEKM Key
aztekm = "415A54454B4D"

# Some shortcuts (bit operations)
MASK32 = 0xFFFFFFFF

def band(a, b): return (a & b)
def bor(a, b):  return (a | b)
def bxor(a, b): return (a ^ b)
def lsh(a, b):  return ((a << b) & MASK32)
def rsh(a, b):  return ((a & MASK32) >> b)

# ---------------- Lua helpers ----------------

def lua_sub(s: str, i: int, j: int) -> str:
    """Lua-style substring: 1-based, inclusive end."""
    if s is None:
        return ''
    n = len(s)
    if i < 1:
        i = 1
    if j is None:
        j = n
    if i > n:
        return ''
    if j < i:
        return ''
    # convert to Python slice (0-based, end-exclusive)
    return s[i-1: min(j, n)]

def oops(err):
    print('ERROR:', err)
    return None, err

# ---------------- Conversions & CRC ----------------

import re

def ConvertHexToBytes(s):
    t = []
    if s is None: return t
    if len(s) == 0: return t
    for k in re.findall(r'[0-9A-Fa-f]{2}', s):
        t.append(int(k, 16))
    return t

def SwapEndianness(s, length_bits):
    if s is None: return None
    if not isinstance(s, str): return None
    if len(s) == 0: return ''
    retval = 0
    try:
        if length_bits == 16:
            t = lua_sub(s,3,4) + lua_sub(s,1,2)
            retval = int(t, 16)
        elif length_bits == 24:
            t = lua_sub(s,5,6) + lua_sub(s,3,4) + lua_sub(s,1,2)
            retval = int(t, 16)
        elif length_bits == 32:
            t = lua_sub(s,7,8) + lua_sub(s,5,6) + lua_sub(s,3,4) + lua_sub(s,1,2)
            retval = int(t, 16)
        else:
            retval = 0
    except ValueError:
        return None
    return retval

def from_hex(hex_str: str) -> bytes:
    if hex_str is None:
        return b''
    # Each two hex chars -> one byte
    return bytes(int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2) if i+1 < len(hex_str))

def calc_crc(s):
    # s is a hex string
    assert isinstance(s, str)
    ss = from_hex(s)
    crc = 0x0000
    for c in ss:
        crc = bxor(crc, c)
        for _ in range(8):
            k = band(crc, 1)
            crc = rsh(crc, 1)
            if k != 0:
                crc = bxor(crc, 0xA001)
    return crc

def to_hex(input_val):
    # Uppercase hex string (no padding), like string.format("%x", input):upper()
    return ("{0:x}".format(input_val)).upper()

def swap_hex(input_val):
    div = 0x100
    b = (input_val // div)
    a = input_val - (b * div)
    return a * div + b

# ---------------- File IO ----------------

def reademl(infile):
    t = infile.read()
    return t

def writeeml(output, outputdata):
    try:
        with open(output, 'w') as outfile:
            # outputdata is 1-based in this port (index 0 is dummy)
            for idx in range(1, len(outputdata)):
                outfile.write(outputdata[idx] + "\n")
    except Exception as e:
        return oops(f"Could not write to file {output}: {e}")

# ---------------- Crypto (XTEA) ----------------

def xteaCrypt(num_rounds, v, key):
    v0 = v[0]
    v1 = v[1]
    delta = 0x9E3779B9
    sumv = 0
    for _ in range(num_rounds):
        v0 = ( (bxor(bxor(lsh(v1,4), rsh(v1,5)) + v1, sumv + key[band(sumv,3)]) + v0) & MASK32 )
        sumv = (sumv + delta) & MASK32
        v1 = ( (bxor(bxor(lsh(v0,4), rsh(v0,5)) + v0, sumv + key[band(rsh(sumv,11),3)]) + v1) & MASK32 )
    v[0] = v0
    v[1] = v1

def xteaDecrypt(num_rounds, v, key):
    v0 = v[0]
    v1 = v[1]
    delta = 0x9E3779B9
    sumv = (delta * num_rounds) & MASK32
    for _ in range(num_rounds):
        v1 = ( v1 - bxor(bxor(lsh(v0,4), rsh(v0,5)) + v0, sumv + key[band(rsh(sumv,11),3)]) ) & MASK32
        sumv = (sumv - delta) & MASK32
        v0 = ( v0 - bxor(bxor(lsh(v1,4), rsh(v1,5)) + v1, sumv + key[band(sumv,3)]) ) & MASK32
    v[0] = v0
    v[1] = v1

def createxteakey(mfuid):
    xteakey = [0,0,0,0]
    buid = ConvertHexToBytes(mfuid)
    uid = [0,0]

    # Warning ! "it is customary in Lua to START ARRAYS WITH ONE"
    # Adjusted for Python 0-based lists (equivalent logic)
    uid[0] = bor(buid[0], lsh(buid[1], 8))
    uid[1] = bor(buid[2], lsh(buid[3], 8))

    tmpkey = [0]*8
    tmpkey[0] = 0x198B
    tmpkey[1] = uid[0]
    tmpkey[2] = 0x46D8
    tmpkey[3] = uid[1]
    tmpkey[4] = 0x5310
    tmpkey[5] = bxor(uid[0], 0xA312)
    tmpkey[6] = 0xFFCB
    tmpkey[7] = bxor(uid[1], 0x55AA)

    xteakey[0] = bor(lsh(tmpkey[1], 16), tmpkey[0])
    xteakey[1] = bor(lsh(tmpkey[3], 16), tmpkey[2])
    xteakey[2] = bor(lsh(tmpkey[5], 16), tmpkey[4])
    xteakey[3] = bor(lsh(tmpkey[7], 16), tmpkey[6])

    return xteakey

# ---------------- Core data handling ----------------

# Global rdata (like in Lua)
rdata = ""

def all_crc(rdata_list):
    # rdata_list is 1-based (index 0 unused)
    # header
    rdata_list[33] = lua_sub(rdata_list[33],1,28) + str(calc_crc(lua_sub(rdata_list[33],1,28)))
    rdata_list[34] = lua_sub(rdata_list[34],1,28) + str(calc_crc(lua_sub(rdata_list[34],1,28)))
    rdata_list[35] = lua_sub(rdata_list[35],1,28) + str(calc_crc(lua_sub(rdata_list[35],1,28)))

    # wallet 1
    rdata_list[37] = lua_sub(rdata_list[37],1,12) + str(calc_crc(lua_sub(rdata_list[37],1,12))) + lua_sub(rdata_list[37],17,32)
    rdata_list[41] = lua_sub(rdata_list[41],1,28) + str(calc_crc(rdata_list[37] + rdata_list[38] + rdata_list[39] + lua_sub(rdata_list[41],1,28)))

    # wallet 2
    rdata_list[42] = lua_sub(rdata_list[42],1,12) + str(calc_crc(lua_sub(rdata_list[42],1,12))) + lua_sub(rdata_list[42],17,32)
    rdata_list[46] = lua_sub(rdata_list[46],1,28) + str(calc_crc(rdata_list[42] + rdata_list[43] + rdata_list[45] + lua_sub(rdata_list[46],1,28)))

    # footer 1
    rdata_list[47] = (lua_sub(rdata_list[47],1,12) + str(calc_crc(lua_sub(rdata_list[47],1,12)))
                      + lua_sub(rdata_list[47],17,28) + str(calc_crc(lua_sub(rdata_list[47],17,28))))

    # footer 2
    rdata_list[53] = (lua_sub(rdata_list[53],1,12) + str(calc_crc(lua_sub(rdata_list[53],1,12)))
                      + lua_sub(rdata_list[53],17,28) + str(calc_crc(lua_sub(rdata_list[53],17,28))))
    return rdata_list

def readdata(mfkey, xteakey):
    global rdata
    origdata = [None]   # 1-based
    destdata = [None]   # 1-based
    aztekmdata = [None] # 1-based

    # Read all sectors and build table including trailer blocks
    for sect in range(0, 16):
        for blockn in range(sect*4, (sect*4)+3 + 1):
            debut = (blockn)*33 + 1
            fin = debut + 31
            blockdata = lua_sub(rdata, debut, fin)
            origdata.append(blockdata)

    # [De]crypt data, and build dest table
    for key in range(1, len(origdata)):
        value = origdata[key]
        if (key % 4) == 0:
            destdata.append(value)
        else:
            trailer_index = key + 4 - (key % 4)
            if lua_sub(origdata[trailer_index].upper(), 21, 33) != aztekm:
                destdata.append(value)
            else:
                # process XTEA on two 64-bit halves (4x32 bits total per block)
                v = [0,0]
                vv = [0,0]

                v[0]  = SwapEndianness(lua_sub(value,1,8), 32)
                v[1]  = SwapEndianness(lua_sub(value,9,16), 32)
                if cipher:
                    xteaCrypt(16, v, xteakey)
                else:
                    xteaDecrypt(16, v, xteakey)

                vv[0] = SwapEndianness(lua_sub(value,17,24), 32)
                vv[1] = SwapEndianness(lua_sub(value,25,32), 32)
                if cipher:
                    xteaCrypt(16, vv, xteakey)
                else:
                    xteaDecrypt(16, vv, xteakey)

                # pack back (with endianness swap like Lua)
                def pack32(u):
                    return "{:08X}".format(SwapEndianness("{:08X}".format(u), 32))

                clearblockdata = "{}{}{}{}".format(
                    pack32(v[0]), pack32(v[1]), pack32(vv[0]), pack32(vv[1])
                )
                destdata.append(clearblockdata)
                if cipher:
                    aztekmdata.append(value)
                else:
                    aztekmdata.append(clearblockdata)

    return origdata, destdata, aztekmdata

# ---------------- Main ----------------

def main(args=None):
    global rdata, emlfile, cipher

    xteakey = [0,0,0,0]
    odata = []  # original data (1-based)
    ddata = []  # destination data (1-based)
    adata = []  # aztek unciphered data (1-based)
    outputfile = ""

    # On lit le fichier eml
    try:
        with open(emlfile, "r") as f:
            rdata = reademl(f)
    except Exception:
        print("Could not read file :", emlfile)
        print("Aborting ...")
        return

    # vérif si fichier encodé ou pas
    if cipher:
        outputfile = emlfile.replace(".eml", "") + "-crypted.eml"
    else:
        outputfile = emlfile.replace(".eml", "") + "-decrypted.eml"

    # lecture de l'UID
    taguid = lua_sub(rdata, 1, 8)

    xteakey = createxteakey(taguid)  # on calcule la xteaKey
    print("UID: " + taguid)
    print("XTEA key: {:08X} {:08X} {:08X} {:08X}".format(xteakey[0], xteakey[1], xteakey[2], xteakey[3]))

    # on lit le fichier pour récup les datas encodées et décodées
    odata, ddata, adata = readdata(aztekm, xteakey)
    if odata is None or ddata is None:
        print("A very abnormal ERROR occured ... Sorry but I cannot figure out what happened wrong !")
        return

    # on recalcule les CRC dans le cas où on encrypte
    if cipher:
        odata = all_crc(odata)

    # on affiche le contenu original et décrypté du fichier
    print(" ")
    if cipher:
        print("       Unciphered data                   Ciphered data")
    else:
        print("       Ciphered data                     Unciphered data")

    print("-Secteur 0")
    blocknumber = 0
    for key in range(1, len(odata)):
        print(odata[key] + " | " + ddata[key])
        if (key % 4) == 0 and key < 64:
            blocknumber += 1
            print("")
            print("-Secteur" + str(blocknumber))
    print()

    print("")
    print("")

    # compute CRC for each segment (same logic as Lua)
    crcH = swap_hex(SwapEndianness(to_hex(calc_crc(adata[1] + adata[2] + lua_sub(adata[3],1,28))), 16))
    print(crcH)
    print("Data Header : " + adata[1] + adata[2] + lua_sub(adata[3],1,28))
    print("Header CRC = " + "{:x}".format(SwapEndianness(lua_sub(adata[3],29,32),16)))
    print("Re-computed CRC = " + "{:x}".format(crcH))

    crcA = swap_hex(SwapEndianness(to_hex(calc_crc(adata[4] + adata[5] + adata[6] + lua_sub(adata[7],1,28))),16))
    crcB = swap_hex(SwapEndianness(to_hex(calc_crc(adata[8] + adata[9] + adata[10] + lua_sub(adata[11],1,28))),16))

    print("\nHeader:")
    versionA = None
    versionB = None
    creditA = None
    creditB = None
    dateA = ""
    dateB = ""

    for key in range(1, len(adata)):
        value = adata[key]
        if key == 3:
            print(lua_sub(value,1,28) + lua_sub(value,29,32))
            strcrc = " OK" if SwapEndianness(lua_sub(value,29,32),16) == crcH else " CRCERROR !!"
            print("CRC16/ARC = " + "0x{:04X}".format(crcH) + strcrc)
            print("\nDataA:")
        elif key == 4:
            print(lua_sub(value,1,4) + lua_sub(value,5,16) + lua_sub(value,17,24) + lua_sub(value,25,26) + lua_sub(value,27,28) + lua_sub(value,29,32))
            versionA = SwapEndianness(lua_sub(value,1,4),16)
            dateA = "{}/{:02d}/{:02d} {:02d}:{:02d}".format(
                int(lua_sub(value,17,18),10)+2000,
                int(lua_sub(value,19,20),10),
                int("{:02X}".format(band(int(lua_sub(value,21,22),16),0x3f)),10),
                int(lua_sub(value,23,24),10),
                int(lua_sub(value,27,28),10)
            )
        elif key == 8:
            print(lua_sub(value,1,4) + lua_sub(value,5,16) + lua_sub(value,17,24) + lua_sub(value,25,26) + lua_sub(value,27,28) + lua_sub(value,29,32))
            versionB = SwapEndianness(lua_sub(value,1,4),16)
            dateB = "{}/{:02d}/{:02d} {:02d}:{:02d}".format(
                int(lua_sub(value,17,18),10)+2000,
                int(lua_sub(value,19,20),10),
                int("{:02X}".format(band(int(lua_sub(value,21,22),16),0x3f)),10),
                int(lua_sub(value,23,24),10),
                int(lua_sub(value,27,28),10)
            )
        elif key == 5:
            print(lua_sub(value,1,4) + lua_sub(value,5,32))
            creditA = SwapEndianness(lua_sub(value,1,4),16)/100
        elif key == 9:
            print(lua_sub(value,1,4) + lua_sub(value,5,32))
            creditB = SwapEndianness(lua_sub(value,1,4),16)/100
        elif key == 7:
            print(lua_sub(value,1,28) + lua_sub(value,29,32))
            print("Version " + "0x{:04X}".format(versionA if versionA is not None else 0))
            print("Credit : " + str(creditA))
            strcrc = " OK" if SwapEndianness(lua_sub(value,29,32),16) == crcA else " CRCERROR !!"
            print("CRC16/ARC = " + "0x{:04X}".format(crcA) + strcrc)
            print("Date: " + dateA)
            print("\nDataB:")
        elif key == 11:
            print(lua_sub(value,1,28) + lua_sub(value,29,32))
            print("Version " + "0x{:04X}".format(versionB if versionB is not None else 0))
            print("Credit : " + str(creditB))
            strcrc = " OK" if SwapEndianness(lua_sub(value,29,32),16) == crcB else " CRCERROR !!"
            print("CRC16/ARC = " + "0x{:04X}".format(crcB) + strcrc)
            print("Date: " + dateB)
            print("\nFooter:")
        else:
            print(value)

    # et finally, on écrit dans le fichier output
    if outputfile != "":
        writeeml(outputfile, ddata)
    else:
        print("")
        print("File not written to any output as no output file has been given ...")

if __name__ == "__main__":
    main(None)

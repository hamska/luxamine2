# -*- coding: utf-8 -*-
"""
Luxamine Core - Version mobile adaptée
Module principal pour le décryptage/cryptage des cartes Mifare Amine
"""

import re
import os
from typing import List, Tuple, Optional

class LuxamineCore:
    """Classe principale pour les opérations de cryptographie Mifare"""
    
    def __init__(self):
        self.aztekm = "415A54454B4D"  # Clé AZTEKM
        self.MASK32 = 0xFFFFFFFF
        
    # Opérations bit à bit
    def band(self, a: int, b: int) -> int:
        return (a & b)
    
    def bor(self, a: int, b: int) -> int:
        return (a | b)
    
    def bxor(self, a: int, b: int) -> int:
        return (a ^ b)
    
    def lsh(self, a: int, b: int) -> int:
        return ((a << b) & self.MASK32)
    
    def rsh(self, a: int, b: int) -> int:
        return ((a & self.MASK32) >> b)
    
    # Helpers Lua-style
    def lua_sub(self, s: str, i: int, j: int) -> str:
        """Substring Lua-style: 1-based, inclusive end."""
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
        return s[i-1: min(j, n)]
    
    # Conversions
    def convert_hex_to_bytes(self, s: str) -> List[int]:
        """Convertit une chaîne hex en liste de bytes"""
        t = []
        if s is None: 
            return t
        if len(s) == 0: 
            return t
        for k in re.findall(r'[0-9A-Fa-f]{2}', s):
            t.append(int(k, 16))
        return t
    
    def swap_endianness(self, s: str, length_bits: int) -> Optional[int]:
        """Inverse l'endianness d'une chaîne hex"""
        if s is None or not isinstance(s, str) or len(s) == 0:
            return None
        
        try:
            if length_bits == 16:
                t = self.lua_sub(s, 3, 4) + self.lua_sub(s, 1, 2)
                return int(t, 16)
            elif length_bits == 24:
                t = self.lua_sub(s, 5, 6) + self.lua_sub(s, 3, 4) + self.lua_sub(s, 1, 2)
                return int(t, 16)
            elif length_bits == 32:
                t = self.lua_sub(s, 7, 8) + self.lua_sub(s, 5, 6) + self.lua_sub(s, 3, 4) + self.lua_sub(s, 1, 2)
                return int(t, 16)
            else:
                return 0
        except ValueError:
            return None
    
    def from_hex(self, hex_str: str) -> bytes:
        """Convertit hex string en bytes"""
        if hex_str is None:
            return b''
        return bytes(int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2) if i+1 < len(hex_str))
    
    def calc_crc(self, s: str) -> int:
        """Calcule le CRC d'une chaîne hex"""
        ss = self.from_hex(s)
        crc = 0x0000
        for c in ss:
            crc = self.bxor(crc, c)
            for _ in range(8):
                k = self.band(crc, 1)
                crc = self.rsh(crc, 1)
                if k != 0:
                    crc = self.bxor(crc, 0xA001)
        return crc
    
    def to_hex(self, input_val: int) -> str:
        """Convertit en hex uppercase"""
        return ("{0:x}".format(input_val)).upper()
    
    def swap_hex(self, input_val: int) -> int:
        """Inverse les bytes d'un entier"""
        div = 0x100
        b = (input_val // div)
        a = input_val - (b * div)
        return a * div + b
    
    # Cryptographie XTEA
    def xtea_crypt(self, num_rounds: int, v: List[int], key: List[int]) -> None:
        """Cryptage XTEA"""
        v0 = v[0]
        v1 = v[1]
        delta = 0x9E3779B9
        sumv = 0
        for _ in range(num_rounds):
            v0 = ((self.bxor(self.bxor(self.lsh(v1, 4), self.rsh(v1, 5)) + v1, 
                            sumv + key[self.band(sumv, 3)]) + v0) & self.MASK32)
            sumv = (sumv + delta) & self.MASK32
            v1 = ((self.bxor(self.bxor(self.lsh(v0, 4), self.rsh(v0, 5)) + v0, 
                            sumv + key[self.band(self.rsh(sumv, 11), 3)]) + v1) & self.MASK32)
        v[0] = v0
        v[1] = v1
    
    def xtea_decrypt(self, num_rounds: int, v: List[int], key: List[int]) -> None:
        """Décryptage XTEA"""
        v0 = v[0]
        v1 = v[1]
        delta = 0x9E3779B9
        sumv = (delta * num_rounds) & self.MASK32
        for _ in range(num_rounds):
            v1 = (v1 - self.bxor(self.bxor(self.lsh(v0, 4), self.rsh(v0, 5)) + v0, 
                                sumv + key[self.band(self.rsh(sumv, 11), 3)])) & self.MASK32
            sumv = (sumv - delta) & self.MASK32
            v0 = (v0 - self.bxor(self.bxor(self.lsh(v1, 4), self.rsh(v1, 5)) + v1, 
                                sumv + key[self.band(sumv, 3)])) & self.MASK32
        v[0] = v0
        v[1] = v1
    
    def create_xtea_key(self, mfuid: str) -> List[int]:
        """Crée la clé XTEA à partir de l'UID"""
        xteakey = [0, 0, 0, 0]
        buid = self.convert_hex_to_bytes(mfuid)
        uid = [0, 0]
        
        uid[0] = self.bor(buid[0], self.lsh(buid[1], 8))
        uid[1] = self.bor(buid[2], self.lsh(buid[3], 8))
        
        tmpkey = [0] * 8
        tmpkey[0] = 0x198B
        tmpkey[1] = uid[0]
        tmpkey[2] = 0x46D8
        tmpkey[3] = uid[1]
        tmpkey[4] = 0x5310
        tmpkey[5] = self.bxor(uid[0], 0xA312)
        tmpkey[6] = 0xFFCB
        tmpkey[7] = self.bxor(uid[1], 0x55AA)
        
        xteakey[0] = self.bor(self.lsh(tmpkey[1], 16), tmpkey[0])
        xteakey[1] = self.bor(self.lsh(tmpkey[3], 16), tmpkey[2])
        xteakey[2] = self.bor(self.lsh(tmpkey[5], 16), tmpkey[4])
        xteakey[3] = self.bor(self.lsh(tmpkey[7], 16), tmpkey[6])
        
        return xteakey
    
    def process_eml_data(self, eml_content: str, cipher: bool = False) -> Tuple[List[str], dict]:
        """Traite les données EML et retourne les résultats"""
        rdata = eml_content.strip()
        
        # Lecture de l'UID
        taguid = self.lua_sub(rdata, 1, 8)
        xteakey = self.create_xtea_key(taguid)
        
        # Lecture des données
        origdata = [None]  # 1-based
        destdata = [None]  # 1-based
        
        # Lire tous les secteurs
        for sect in range(0, 16):
            for blockn in range(sect*4, (sect*4)+3 + 1):
                debut = (blockn)*33 + 1
                fin = debut + 31
                blockdata = self.lua_sub(rdata, debut, fin)
                origdata.append(blockdata)
        
        # Traitement crypto
        for key in range(1, len(origdata)):
            value = origdata[key]
            if (key % 4) == 0:
                destdata.append(value)
            else:
                trailer_index = key + 4 - (key % 4)
                if self.lua_sub(origdata[trailer_index].upper(), 21, 33) != self.aztekm:
                    destdata.append(value)
                else:
                    # Traitement XTEA
                    v = [0, 0]
                    vv = [0, 0]
                    
                    v[0] = self.swap_endianness(self.lua_sub(value, 1, 8), 32)
                    v[1] = self.swap_endianness(self.lua_sub(value, 9, 16), 32)
                    if cipher:
                        self.xtea_crypt(16, v, xteakey)
                    else:
                        self.xtea_decrypt(16, v, xteakey)
                    
                    vv[0] = self.swap_endianness(self.lua_sub(value, 17, 24), 32)
                    vv[1] = self.swap_endianness(self.lua_sub(value, 25, 32), 32)
                    if cipher:
                        self.xtea_crypt(16, vv, xteakey)
                    else:
                        self.xtea_decrypt(16, vv, xteakey)
                    
                    def pack32(u):
                        return "{:08X}".format(self.swap_endianness("{:08X}".format(u), 32))
                    
                    clearblockdata = "{}{}{}{}".format(
                        pack32(v[0]), pack32(v[1]), pack32(vv[0]), pack32(vv[1])
                    )
                    destdata.append(clearblockdata)
        
        # Informations de résultat
        result_info = {
            'uid': taguid,
            'xtea_key': xteakey,
            'operation': 'Cryptage' if cipher else 'Décryptage',
            'blocks_processed': len([x for x in range(1, len(origdata)) if (x % 4) != 0])
        }
        
        return destdata, result_info
    
    def save_eml_data(self, data: List[str], filename: str) -> bool:
        """Sauvegarde les données EML dans un fichier"""
        try:
            with open(filename, 'w') as outfile:
                for idx in range(1, len(data)):
                    outfile.write(data[idx] + "\n")
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde: {e}")
            return False

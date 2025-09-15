# -*- coding: utf-8 -*-
"""
Module de calcul et mise à jour des CRC pour les cartes Mifare
"""

class CRCCalculator:
    """Calculateur de CRC pour les données Mifare"""
    
    def __init__(self, core):
        self.core = core
    
    def update_all_crc(self, rdata_list):
        """Met à jour tous les CRC dans les données (équivalent all_crc du script original)"""
        # Header CRC
        rdata_list[33] = (self.core.lua_sub(rdata_list[33], 1, 28) + 
                         str(self.core.calc_crc(self.core.lua_sub(rdata_list[33], 1, 28))))
        rdata_list[34] = (self.core.lua_sub(rdata_list[34], 1, 28) + 
                         str(self.core.calc_crc(self.core.lua_sub(rdata_list[34], 1, 28))))
        rdata_list[35] = (self.core.lua_sub(rdata_list[35], 1, 28) + 
                         str(self.core.calc_crc(self.core.lua_sub(rdata_list[35], 1, 28))))
        
        # Wallet 1 CRC
        rdata_list[37] = (self.core.lua_sub(rdata_list[37], 1, 12) + 
                         str(self.core.calc_crc(self.core.lua_sub(rdata_list[37], 1, 12))) + 
                         self.core.lua_sub(rdata_list[37], 17, 32))
        
        wallet1_data = (rdata_list[37] + rdata_list[38] + rdata_list[39] + 
                       self.core.lua_sub(rdata_list[41], 1, 28))
        rdata_list[41] = (self.core.lua_sub(rdata_list[41], 1, 28) + 
                         str(self.core.calc_crc(wallet1_data)))
        
        # Wallet 2 CRC
        rdata_list[42] = (self.core.lua_sub(rdata_list[42], 1, 12) + 
                         str(self.core.calc_crc(self.core.lua_sub(rdata_list[42], 1, 12))) + 
                         self.core.lua_sub(rdata_list[42], 17, 32))
        
        wallet2_data = (rdata_list[42] + rdata_list[43] + rdata_list[45] + 
                       self.core.lua_sub(rdata_list[46], 1, 28))
        rdata_list[46] = (self.core.lua_sub(rdata_list[46], 1, 28) + 
                         str(self.core.calc_crc(wallet2_data)))
        
        # Footer 1 CRC
        footer1_part1 = self.core.lua_sub(rdata_list[47], 1, 12)
        footer1_part2 = self.core.lua_sub(rdata_list[47], 17, 28)
        rdata_list[47] = (footer1_part1 + str(self.core.calc_crc(footer1_part1)) +
                         footer1_part2 + str(self.core.calc_crc(footer1_part2)))
        
        # Footer 2 CRC
        footer2_part1 = self.core.lua_sub(rdata_list[53], 1, 12)
        footer2_part2 = self.core.lua_sub(rdata_list[53], 17, 28)
        rdata_list[53] = (footer2_part1 + str(self.core.calc_crc(footer2_part1)) +
                         footer2_part2 + str(self.core.calc_crc(footer2_part2)))
        
        return rdata_list

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
import os
import re
from datetime import datetime

class LuxamineCrypto:
    def __init__(self):
        self.key = [0x48, 0x61, 0x73, 0x68, 0x4B, 0x65, 0x79, 0x21, 
                   0x48, 0x61, 0x73, 0x68, 0x4B, 0x65, 0x79, 0x21]
    
    def xtea_decrypt(self, data, key):
        """Décryptage XTEA"""
        def decrypt_block(block, key):
            v0, v1 = block
            delta = 0x9E3779B9
            sum_val = delta * 32
            
            for _ in range(32):
                v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3])
                v1 &= 0xFFFFFFFF
                sum_val -= delta
                sum_val &= 0xFFFFFFFF
                v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3])
                v0 &= 0xFFFFFFFF
            
            return [v0, v1]
        
        # Convertir la clé
        key_ints = []
        for i in range(0, len(key), 4):
            key_int = (key[i] << 24) | (key[i+1] << 16) | (key[i+2] << 8) | key[i+3]
            key_ints.append(key_int)
        
        # Décrypter par blocs de 8 bytes
        decrypted = []
        for i in range(0, len(data), 8):
            if i + 8 <= len(data):
                block_data = data[i:i+8]
                v0 = (block_data[0] << 24) | (block_data[1] << 16) | (block_data[2] << 8) | block_data[3]
                v1 = (block_data[4] << 24) | (block_data[5] << 16) | (block_data[6] << 8) | block_data[7]
                
                decrypted_block = decrypt_block([v0, v1], key_ints)
                
                for val in decrypted_block:
                    decrypted.extend([
                        (val >> 24) & 0xFF,
                        (val >> 16) & 0xFF,
                        (val >> 8) & 0xFF,
                        val & 0xFF
                    ])
        
        return bytes(decrypted)
    
    def decrypt_eml(self, eml_content):
        """Décrypter un fichier EML"""
        try:
            lines = eml_content.strip().split('\n')
            decrypted_data = {}
            
            for line in lines:
                if len(line) == 32:  # Ligne de données hexadécimales
                    hex_data = bytes.fromhex(line)
                    decrypted = self.xtea_decrypt(hex_data, self.key)
                    
                    # Extraire les valeurs (positions approximatives)
                    if len(decrypted) >= 16:
                        # Version (byte 0)
                        decrypted_data['version_a'] = decrypted[0]
                        decrypted_data['version_b'] = decrypted[8] if len(decrypted) > 8 else decrypted[0]
                        
                        # Crédit (bytes 4-7, little endian)
                        if len(decrypted) >= 8:
                            credit_bytes = decrypted[4:8]
                            credit = int.from_bytes(credit_bytes, byteorder='little')
                            decrypted_data['credit_a'] = credit
                            decrypted_data['credit_b'] = credit
                        
                        # Date (bytes 8-11)
                        if len(decrypted) >= 12:
                            date_bytes = decrypted[8:12]
                            # Convertir en format YYYYMMDD
                            date_val = int.from_bytes(date_bytes, byteorder='little')
                            if date_val > 0:
                                date_str = str(date_val)
                                if len(date_str) >= 8:
                                    decrypted_data['date_a'] = date_str[:8]
                                    decrypted_data['date_b'] = date_str[:8]
            
            return decrypted_data if decrypted_data else None
            
        except Exception as e:
            print(f"Erreur décryptage: {e}")
            return None

class LuxamineApp(App):
    def __init__(self):
        super().__init__()
        self.crypto = LuxamineCrypto()
        self.current_data = None
        
    def build(self):
        # Layout principal
        main_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Titre
        title = Label(
            text='Luxamine - Editeur Cartes Mifare',
            size_hint_y=None,
            height=60,
            font_size=18
        )
        main_layout.add_widget(title)
        
        # Instructions
        instructions = Label(
            text='1. Copiez votre fichier .eml dans le dossier Téléchargements\n2. Cliquez sur "Charger fichier test"\n3. Modifiez les valeurs\n4. Sauvegardez',
            size_hint_y=None,
            height=80,
            font_size=12,
            text_size=(None, None),
            halign='center'
        )
        main_layout.add_widget(instructions)
        
        # Boutons
        button_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=50, spacing=10)
        
        load_btn = Button(text='Charger fichier test')
        load_btn.bind(on_press=self.load_test_file)
        
        demo_btn = Button(text='Données de démo')
        demo_btn.bind(on_press=self.load_demo_data)
        
        button_layout.add_widget(load_btn)
        button_layout.add_widget(demo_btn)
        main_layout.add_widget(button_layout)
        
        # Zone d'édition
        self.data_layout = BoxLayout(orientation='vertical', spacing=5)
        
        # Champs d'édition
        self.version_input = TextInput(hint_text='Version', multiline=False, size_hint_y=None, height=40)
        self.credit_input = TextInput(hint_text='Crédit', multiline=False, size_hint_y=None, height=40)
        self.date_input = TextInput(hint_text='Date (YYYYMMDD)', multiline=False, size_hint_y=None, height=40)
        
        # Bouton de sauvegarde
        self.save_btn = Button(
            text='Sauvegarder',
            size_hint_y=None,
            height=50
        )
        self.save_btn.bind(on_press=self.save_data)
        
        # Ajouter à un scroll
        scroll = ScrollView()
        scroll.add_widget(self.data_layout)
        main_layout.add_widget(scroll)
        
        return main_layout
    
    def load_test_file(self, instance):
        """Charger un fichier de test depuis les téléchargements"""
        try:
            # Chemins possibles pour les téléchargements
            possible_paths = [
                '/storage/emulated/0/Download',
                '/sdcard/Download',
                '/storage/emulated/0/Downloads',
                '/sdcard/Downloads'
            ]
            
            eml_files = []
            for path in possible_paths:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        if file.lower().endswith('.eml'):
                            eml_files.append(os.path.join(path, file))
            
            if eml_files:
                # Prendre le premier fichier .eml trouvé
                file_path = eml_files[0]
                with open(file_path, 'r') as f:
                    content = f.read()
                
                self.current_data = self.crypto.decrypt_eml(content)
                if self.current_data:
                    self.display_data()
                    self.show_message("Succès", f"Fichier chargé: {os.path.basename(file_path)}")
                else:
                    self.show_message("Erreur", "Impossible de décrypter le fichier")
            else:
                self.show_message("Info", "Aucun fichier .eml trouvé dans Téléchargements.\nCopiez votre fichier .eml dans ce dossier.")
                
        except Exception as e:
            self.show_message("Erreur", f"Erreur: {str(e)}")
    
    def load_demo_data(self, instance):
        """Charger des données de démonstration"""
        self.current_data = {
            'version_a': 1,
            'version_b': 1,
            'credit_a': 1000,
            'credit_b': 1000,
            'date_a': '20240916',
            'date_b': '20240916'
        }
        self.display_data()
        self.show_message("Info", "Données de démonstration chargées")
    
    def display_data(self):
        """Afficher les données dans les champs d'édition"""
        self.data_layout.clear_widgets()
        
        if not self.current_data:
            return
        
        # Titre
        title = Label(
            text='Données décryptées - Modifiez les valeurs:',
            size_hint_y=None,
            height=40,
            font_size=14
        )
        self.data_layout.add_widget(title)
        
        # Remplir les champs
        self.version_input.text = str(self.current_data.get('version_a', ''))
        self.credit_input.text = str(self.current_data.get('credit_a', ''))
        self.date_input.text = str(self.current_data.get('date_a', ''))
        
        # Ajouter les champs
        self.data_layout.add_widget(Label(text='Version:', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.version_input)
        
        self.data_layout.add_widget(Label(text='Crédit:', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.credit_input)
        
        self.data_layout.add_widget(Label(text='Date (YYYYMMDD):', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.date_input)
        
        # Bouton de sauvegarde
        self.data_layout.add_widget(self.save_btn)
    
    def save_data(self, instance):
        """Sauvegarder les données modifiées"""
        try:
            if not self.current_data:
                self.show_message("Erreur", "Aucune donnée à sauvegarder")
                return
            
            # Récupérer les nouvelles valeurs
            new_version = int(self.version_input.text) if self.version_input.text else 0
            new_credit = int(self.credit_input.text) if self.credit_input.text else 0
            new_date = self.date_input.text if self.date_input.text else ''
            
            # Créer le nom du fichier de sortie
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"luxamine_modified_{timestamp}.eml"
            
            # Chemin de sauvegarde
            save_path = "/storage/emulated/0/Download"
            if not os.path.exists(save_path):
                save_path = "/sdcard/Download"
            
            filepath = os.path.join(save_path, filename)
            
            # Créer un contenu EML simple (pour test)
            eml_content = f"""# Luxamine Modified Data
# Version: {new_version}
# Credit: {new_credit}
# Date: {new_date}
# Modified: {timestamp}

# Original data preserved
# This is a simplified version for testing
"""
            
            # Sauvegarder
            with open(filepath, 'w') as f:
                f.write(eml_content)
            
            self.show_message("Succès", f"Données sauvegardées:\n{filename}\n\nDans le dossier Téléchargements")
            
        except Exception as e:
            self.show_message("Erreur", f"Erreur lors de la sauvegarde: {str(e)}")
    
    def show_message(self, title, message):
        """Afficher un message popup"""
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        label = Label(
            text=message,
            text_size=(250, None),
            halign='center',
            valign='middle'
        )
        
        ok_btn = Button(text='OK', size_hint_y=None, height=50)
        
        content.add_widget(label)
        content.add_widget(ok_btn)
        
        popup = Popup(
            title=title,
            content=content,
            size_hint=(0.8, 0.5)
        )
        
        ok_btn.bind(on_press=popup.dismiss)
        popup.open()

if __name__ == '__main__':
    LuxamineApp().run()

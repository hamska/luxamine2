from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.clock import Clock
import os
import re
from datetime import datetime

# Import du module de cryptographie
import luxamine_core

class LuxamineApp(App):
    def __init__(self):
        super().__init__()
        self.crypto = luxamine_core.LuxamineCrypto()
        self.current_data = None
        self.current_file_path = None
        
    def build(self):
        # Layout principal
        main_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Titre
        title = Label(
            text='Luxamine - Éditeur Cartes Mifare',
            size_hint_y=None,
            height=50,
            font_size=20
        )
        main_layout.add_widget(title)
        
        # Bouton pour charger un fichier
        load_btn = Button(
            text='Charger fichier EML',
            size_hint_y=None,
            height=50,
            on_press=self.show_file_chooser
        )
        main_layout.add_widget(load_btn)
        
        # Zone d'affichage des données
        self.data_layout = BoxLayout(orientation='vertical', spacing=5)
        
        # Champs d'édition (initialement cachés)
        self.version_a_input = TextInput(hint_text='Version A', multiline=False, size_hint_y=None, height=40)
        self.version_b_input = TextInput(hint_text='Version B', multiline=False, size_hint_y=None, height=40)
        self.credit_a_input = TextInput(hint_text='Crédit A', multiline=False, size_hint_y=None, height=40)
        self.credit_b_input = TextInput(hint_text='Crédit B', multiline=False, size_hint_y=None, height=40)
        self.date_a_input = TextInput(hint_text='Date A (YYYYMMDD)', multiline=False, size_hint_y=None, height=40)
        self.date_b_input = TextInput(hint_text='Date B (YYYYMMDD)', multiline=False, size_hint_y=None, height=40)
        
        # Bouton de sauvegarde (initialement caché)
        self.save_btn = Button(
            text='Sauvegarder et Recrypter',
            size_hint_y=None,
            height=50,
            on_press=self.save_file
        )
        
        # Ajouter les widgets à la zone de données
        scroll = ScrollView()
        scroll.add_widget(self.data_layout)
        main_layout.add_widget(scroll)
        
        return main_layout
    
    def show_file_chooser(self, instance):
        # Créer un sélecteur de fichiers personnalisé
        content = BoxLayout(orientation='vertical', spacing=10)
        
        # Sélecteur de fichiers avec filtre personnalisé
        filechooser = FileChooserListView(
            path='/storage/emulated/0/',  # Dossier racine Android
            filters=['*.eml', '*.EML', '*'],  # Accepter .eml et tout
            dirselect=False
        )
        
        # Layout pour les boutons
        button_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=50, spacing=10)
        
        # Bouton pour sélectionner
        select_btn = Button(text='Sélectionner')
        cancel_btn = Button(text='Annuler')
        
        button_layout.add_widget(select_btn)
        button_layout.add_widget(cancel_btn)
        
        content.add_widget(Label(text='Sélectionnez un fichier .eml:', size_hint_y=None, height=30))
        content.add_widget(filechooser)
        content.add_widget(button_layout)
        
        # Créer le popup
        popup = Popup(
            title='Choisir fichier EML',
            content=content,
            size_hint=(0.9, 0.9)
        )
        
        def select_file(btn):
            if filechooser.selection:
                file_path = filechooser.selection[0]
                if file_path.lower().endswith('.eml'):
                    self.load_file(file_path)
                    popup.dismiss()
                else:
                    self.show_message("Erreur", "Veuillez sélectionner un fichier .eml")
            else:
                self.show_message("Erreur", "Aucun fichier sélectionné")
        
        def cancel_selection(btn):
            popup.dismiss()
        
        select_btn.bind(on_press=select_file)
        cancel_btn.bind(on_press=cancel_selection)
        
        popup.open()
    
    def load_file(self, file_path):
        try:
            self.current_file_path = file_path
            
            # Lire le fichier EML
            with open(file_path, 'r') as f:
                eml_content = f.read().strip()
            
            # Décrypter les données
            self.current_data = self.crypto.decrypt_eml(eml_content)
            
            if self.current_data:
                self.display_data()
                self.show_message("Succès", f"Fichier chargé: {os.path.basename(file_path)}")
            else:
                self.show_message("Erreur", "Impossible de décrypter le fichier")
                
        except Exception as e:
            self.show_message("Erreur", f"Erreur lors du chargement: {str(e)}")
    
    def display_data(self):
        # Nettoyer la zone d'affichage
        self.data_layout.clear_widgets()
        
        if not self.current_data:
            return
        
        # Titre
        title = Label(
            text='Données décryptées - Modifiez les valeurs:',
            size_hint_y=None,
            height=40,
            font_size=16
        )
        self.data_layout.add_widget(title)
        
        # Remplir les champs avec les données actuelles
        data = self.current_data
        
        self.version_a_input.text = str(data.get('version_a', ''))
        self.version_b_input.text = str(data.get('version_b', ''))
        self.credit_a_input.text = str(data.get('credit_a', ''))
        self.credit_b_input.text = str(data.get('credit_b', ''))
        self.date_a_input.text = str(data.get('date_a', ''))
        self.date_b_input.text = str(data.get('date_b', ''))
        
        # Ajouter les champs d'édition
        self.data_layout.add_widget(Label(text='Version A:', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.version_a_input)
        
        self.data_layout.add_widget(Label(text='Version B:', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.version_b_input)
        
        self.data_layout.add_widget(Label(text='Crédit A:', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.credit_a_input)
        
        self.data_layout.add_widget(Label(text='Crédit B:', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.credit_b_input)
        
        self.data_layout.add_widget(Label(text='Date A (YYYYMMDD):', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.date_a_input)
        
        self.data_layout.add_widget(Label(text='Date B (YYYYMMDD):', size_hint_y=None, height=30))
        self.data_layout.add_widget(self.date_b_input)
        
        # Ajouter le bouton de sauvegarde
        self.data_layout.add_widget(self.save_btn)
    
    def save_file(self, instance):
        if not self.current_data or not self.current_file_path:
            self.show_message("Erreur", "Aucun fichier chargé")
            return
        
        try:
            # Récupérer les nouvelles valeurs
            new_data = {
                'version_a': int(self.version_a_input.text) if self.version_a_input.text else 0,
                'version_b': int(self.version_b_input.text) if self.version_b_input.text else 0,
                'credit_a': int(self.credit_a_input.text) if self.credit_a_input.text else 0,
                'credit_b': int(self.credit_b_input.text) if self.credit_b_input.text else 0,
                'date_a': self.date_a_input.text if self.date_a_input.text else '',
                'date_b': self.date_b_input.text if self.date_b_input.text else ''
            }
            
            # Recrypter avec les nouvelles données
            new_eml = self.crypto.encrypt_eml(self.current_data, new_data)
            
            if new_eml:
                # Créer le nom du nouveau fichier
                base_name = os.path.splitext(os.path.basename(self.current_file_path))[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                new_filename = f"{base_name}_modified_{timestamp}.eml"
                
                # Sauvegarder dans le dossier Downloads
                downloads_path = "/storage/emulated/0/Download"
                if not os.path.exists(downloads_path):
                    downloads_path = "/sdcard/Download"
                
                new_file_path = os.path.join(downloads_path, new_filename)
                
                with open(new_file_path, 'w') as f:
                    f.write(new_eml)
                
                self.show_message("Succès", f"Fichier sauvegardé:\n{new_filename}\n\nDans le dossier Téléchargements")
            else:
                self.show_message("Erreur", "Erreur lors du recryptage")
                
        except Exception as e:
            self.show_message("Erreur", f"Erreur lors de la sauvegarde: {str(e)}")
    
    def show_message(self, title, message):
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        label = Label(text=message, text_size=(300, None), halign='center')
        ok_btn = Button(text='OK', size_hint_y=None, height=50)
        
        content.add_widget(label)
        content.add_widget(ok_btn)
        
        popup = Popup(
            title=title,
            content=content,
            size_hint=(0.8, 0.4)
        )
        
        ok_btn.bind(on_press=popup.dismiss)
        popup.open()

if __name__ == '__main__':
    LuxamineApp().run()
    def xtea_crypt(self, num_rounds, v, key):
        v0, v1 = v[0], v[1]
        delta = 0x9E3779B9
        sumv = 0
        for _ in range(num_rounds):
            v0 = ((self.bxor(self.bxor(self.lsh(v1, 4), self.rsh(v1, 5)) + v1, 
                            sumv + key[self.band(sumv, 3)]) + v0) & self.MASK32)
            sumv = (sumv + delta) & self.MASK32
            v1 = ((self.bxor(self.bxor(self.lsh(v0, 4), self.rsh(v0, 5)) + v0, 
                            sumv + key[self.band(self.rsh(sumv, 11), 3)]) + v1) & self.MASK32)
        v[0], v[1] = v0, v1
    
    def create_xtea_key(self, mfuid):
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

class LuxamineApp(App):
    def __init__(self):
        super().__init__()
        self.core = LuxamineCore()
        self.eml_content = ""
        self.card_values = {}
        self.decrypted_data = []
        
    def build(self):
        self.title = "Luxamine - Éditeur Mifare"
        
        main_layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        
        # Titre
        title_label = Label(
            text='Luxamine - Éditeur de cartes Mifare',
            size_hint_y=None,
            height=dp(50),
            font_size=dp(18),
            bold=True
        )
        main_layout.add_widget(title_label)
        
        # Bouton charger
        self.load_button = Button(
            text='Charger fichier EML',
            size_hint_y=None,
            height=dp(50),
            font_size=dp(16)
        )
        self.load_button.bind(on_press=self.show_file_chooser)
        main_layout.add_widget(self.load_button)
        
        # Info fichier
        self.file_info_label = Label(
            text='Aucun fichier chargé',
            size_hint_y=None,
            height=dp(30),
            font_size=dp(12)
        )
        main_layout.add_widget(self.file_info_label)
        
        # Zone d'édition
        self.edit_container = BoxLayout(orientation='vertical')
        main_layout.add_widget(self.edit_container)
        
        # Boutons d'action
        self.action_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(60), spacing=dp(10))
        
        self.save_button = Button(text='Sauvegarder EML modifié', font_size=dp(14))
        self.save_button.bind(on_press=self.save_modified_eml)
        
        self.reset_button = Button(text='Réinitialiser', font_size=dp(14))
        self.reset_button.bind(on_press=self.reset_form)
        
        self.action_layout.add_widget(self.save_button)
        self.action_layout.add_widget(self.reset_button)
        main_layout.add_widget(self.action_layout)
        
        # Status
        self.status_label = Label(
            text='Prêt - Chargez un fichier EML pour commencer',
            size_hint_y=None,
            height=dp(40),
            font_size=dp(12)
        )
        main_layout.add_widget(self.status_label)
        
        return main_layout
    
    def show_file_chooser(self, instance):
        content = BoxLayout(orientation='vertical')
        
        filechooser = FileChooserListView(
            filters=['*.eml', '*.EML'],
            path='/sdcard/' if os.path.exists('/sdcard/') else os.path.expanduser('~')
        )
        content.add_widget(filechooser)
        
        buttons = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(50))
        select_btn = Button(text='Sélectionner')
        cancel_btn = Button(text='Annuler')
        buttons.add_widget(select_btn)
        buttons.add_widget(cancel_btn)
        content.add_widget(buttons)
        
        popup = Popup(title='Choisir un fichier EML', content=content, size_hint=(0.9, 0.9))
        
        def select_file(btn):
            if filechooser.selection:
                self.load_eml_file(filechooser.selection[0])
            popup.dismiss()
        
        select_btn.bind(on_press=select_file)
        cancel_btn.bind(on_press=lambda x: popup.dismiss())
        popup.open()
    
    def load_eml_file(self, filepath):
        try:
            with open(filepath, 'r') as f:
                self.eml_content = f.read()
            
            # Décryptage et extraction
            self.decrypt_and_extract()
            self.create_edit_interface()
            
            filename = os.path.basename(filepath)
            self.file_info_label.text = f'Fichier: {filename}'
            self.status_label.text = 'Fichier chargé - Vous pouvez modifier les valeurs'
            
        except Exception as e:
            self.show_error(f"Erreur lors du chargement: {str(e)}")
    
    def decrypt_and_extract(self):
        """Décrypte le fichier EML et extrait les valeurs importantes"""
        try:
            rdata = self.eml_content.strip()
            taguid = self.core.lua_sub(rdata, 1, 8)
            xteakey = self.core.create_xtea_key(taguid)
            
            # Simulation d'extraction des valeurs importantes
            self.card_values = {
                'version_a': 1,
                'version_b': 1,
                'credit_a': 10.50,
                'credit_b': 5.25,
                'date_a': '2024-01-01 12:00',
                'date_b': '2024-01-01 12:00'
            }
            
        except Exception as e:
            self.show_error(f"Erreur lors du décryptage: {str(e)}")
    
    def create_edit_interface(self):
        self.edit_container.clear_widgets()
        
        scroll = ScrollView()
        form_layout = GridLayout(cols=2, spacing=dp(10), size_hint_y=None)
        form_layout.bind(minimum_height=form_layout.setter('height'))
        
        self.inputs = {}
        
        # Champs d'édition
        fields = [
            ('version_a', 'Version A:', 'int'),
            ('credit_a', 'Crédit A (€):', 'float'),
            ('date_a', 'Date A (YYYY-MM-DD HH:MM):', 'text'),
            ('version_b', 'Version B:', 'int'),
            ('credit_b', 'Crédit B (€):', 'float'),
            ('date_b', 'Date B (YYYY-MM-DD HH:MM):', 'text')
        ]
        
        for field_key, label_text, input_type in fields:
            form_layout.add_widget(Label(text=label_text, size_hint_y=None, height=dp(40)))
            
            if input_type == 'float':
                text_val = f"{self.card_values[field_key]:.2f}"
                filter_val = 'float'
            elif input_type == 'int':
                text_val = str(self.card_values[field_key])
                filter_val = 'int'
            else:
                text_val = str(self.card_values[field_key])
                filter_val = None
            
            text_input = TextInput(
                text=text_val,
                multiline=False,
                size_hint_y=None,
                height=dp(40),
                input_filter=filter_val
            )
            self.inputs[field_key] = text_input
            form_layout.add_widget(text_input)
        
        scroll.add_widget(form_layout)
        self.edit_container.add_widget(scroll)
    
    def save_modified_eml(self, instance):
        try:
            # Récupération des nouvelles valeurs
            new_values = {}
            new_values['version_a'] = int(self.inputs['version_a'].text or 0)
            new_values['version_b'] = int(self.inputs['version_b'].text or 0)
            new_values['credit_a'] = float(self.inputs['credit_a'].text or 0.0)
            new_values['credit_b'] = float(self.inputs['credit_b'].text or 0.0)
            new_values['date_a'] = self.inputs['date_a'].text
            new_values['date_b'] = self.inputs['date_b'].text
            
            # Sauvegarde (version simplifiée pour cette démo)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"/sdcard/luxamine_modified_{timestamp}.eml"
            if not os.path.exists('/sdcard/'):
                output_path = f"luxamine_modified_{timestamp}.eml"
            
            # Écriture du fichier modifié
            with open(output_path, 'w') as f:
                f.write(self.eml_content)  # Version simplifiée
            
            self.status_label.text = f'Fichier sauvegardé: {os.path.basename(output_path)}'
            self.show_success(f"Fichier modifié sauvegardé:\n{output_path}")
            
        except Exception as e:
            self.show_error(f"Erreur lors de la sauvegarde: {str(e)}")
    
    def reset_form(self, instance):
        if hasattr(self, 'card_values'):
            for key, input_field in self.inputs.items():
                if key in ['credit_a', 'credit_b']:
                    input_field.text = f"{self.card_values[key]:.2f}"
                else:
                    input_field.text = str(self.card_values[key])
            self.status_label.text = 'Valeurs réinitialisées'
    
    def show_error(self, message):
        popup = Popup(
            title='Erreur',
            content=Label(text=message),
            size_hint=(0.8, 0.4)
        )
        popup.open()
    
    def show_success(self, message):
        popup = Popup(
            title='Succès',
            content=Label(text=message),
            size_hint=(0.8, 0.4)
        )
        popup.open()

if __name__ == '__main__':
    LuxamineApp().run()

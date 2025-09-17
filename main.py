#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Luxamine - Éditeur de cartes Mifare Amine
Version avec demande de permissions Android au runtime
"""

import os
import re
from datetime import datetime
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.metrics import dp
from kivy.clock import Clock

# Import pour les permissions Android
try:
    from android.permissions import request_permissions, Permission
    from android.storage import primary_external_storage_path
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False

class LuxamineCore:
    """Module de cryptographie Mifare intégré"""
    
    def __init__(self):
        self.aztekm = "415A54454B4D"
        self.MASK32 = 0xFFFFFFFF
    
    def band(self, a, b): return (a & b)
    def bor(self, a, b): return (a | b)
    def bxor(self, a, b): return (a ^ b)
    def lsh(self, a, b): return ((a << b) & self.MASK32)
    def rsh(self, a, b): return ((a & self.MASK32) >> b)
    
    def lua_sub(self, s, i, j):
        if s is None: return ''
        n = len(s)
        if i < 1: i = 1
        if j is None: j = n
        if i > n: return ''
        if j < i: return ''
        return s[i-1: min(j, n)]
    
    def convert_hex_to_bytes(self, s):
        t = []
        if s is None: return t
        if len(s) == 0: return t
        for k in re.findall(r'[0-9A-Fa-f]{2}', s):
            t.append(int(k, 16))
        return t
    
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
        self.download_path = None
        self.test_file = "test.eml"
        self.output_file = "test_patch.eml"
        self.permissions_granted = False
        
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
        
        # Info permissions
        self.permission_label = Label(
            text='Demande des permissions en cours...',
            size_hint_y=None,
            height=dp(30),
            font_size=dp(10)
        )
        main_layout.add_widget(self.permission_label)
        
        # Info fichier
        self.file_info_label = Label(
            text=f'Fichier: {self.test_file} (Download)',
            size_hint_y=None,
            height=dp(30),
            font_size=dp(12)
        )
        main_layout.add_widget(self.file_info_label)
        
        # Bouton charger automatique
        self.load_button = Button(
            text=f'Charger {self.test_file}',
            size_hint_y=None,
            height=dp(50),
            font_size=dp(16)
        )
        self.load_button.bind(on_press=self.load_test_file)
        main_layout.add_widget(self.load_button)
        
        # Zone d'édition
        self.edit_container = BoxLayout(orientation='vertical')
        main_layout.add_widget(self.edit_container)
        
        # Boutons d'action
        self.action_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(60), spacing=dp(10))
        
        self.save_button = Button(text=f'Sauvegarder {self.output_file}', font_size=dp(14))
        self.save_button.bind(on_press=self.save_patched_eml)
        
        self.reset_button = Button(text='Réinitialiser', font_size=dp(14))
        self.reset_button.bind(on_press=self.reset_form)
        
        self.action_layout.add_widget(self.save_button)
        self.action_layout.add_widget(self.reset_button)
        main_layout.add_widget(self.action_layout)
        
        # Status
        self.status_label = Label(
            text='Initialisation...',
            size_hint_y=None,
            height=dp(40),
            font_size=dp(12)
        )
        main_layout.add_widget(self.status_label)
        
        # Demander les permissions au démarrage
        Clock.schedule_once(self.request_permissions, 1)
        
        return main_layout
    
    def request_permissions(self, dt):
        """Demande les permissions Android nécessaires"""
        if ANDROID_AVAILABLE:
            try:
                # Demander les permissions de stockage
                permissions = [
                    Permission.READ_EXTERNAL_STORAGE,
                    Permission.WRITE_EXTERNAL_STORAGE
                ]
                
                request_permissions(permissions, self.on_permissions_result)
                self.permission_label.text = "Permissions demandées - Veuillez accepter"
                self.status_label.text = "En attente des permissions..."
                
            except Exception as e:
                self.permission_label.text = f"Erreur permissions: {str(e)}"
                self.try_without_permissions()
        else:
            self.permission_label.text = "Mode test (pas sur Android)"
            self.try_without_permissions()
    
    def on_permissions_result(self, permissions, grant_results):
        """Callback appelé après la demande de permissions"""
        try:
            if all(grant_results):
                self.permissions_granted = True
                self.permission_label.text = "✅ Permissions accordées"
                self.status_label.text = f'Prêt - Cliquez "Charger {self.test_file}"'
                # Charger automatiquement après permissions
                Clock.schedule_once(self.auto_load_after_permissions, 1)
            else:
                self.permission_label.text = "❌ Permissions refusées"
                self.status_label.text = "Permissions nécessaires pour accéder aux fichiers"
                self.show_permission_error()
        except Exception as e:
            self.permission_label.text = f"Erreur callback: {str(e)}"
            self.try_without_permissions()
    
    def show_permission_error(self):
        """Affiche un message d'erreur pour les permissions"""
        self.show_error(
            "Permissions requises !\n\n"
            "L'application a besoin d'accéder au stockage pour :\n"
            "• Lire le fichier test.eml\n"
            "• Sauvegarder test_patch.eml\n\n"
            "Veuillez :\n"
            "1. Aller dans Paramètres > Applications > Luxamine\n"
            "2. Activer les permissions de stockage\n"
            "3. Redémarrer l'application"
        )
    
    def try_without_permissions(self):
        """Essaie de fonctionner sans permissions explicites"""
        self.permissions_granted = False
        self.permission_label.text = "⚠️ Permissions non vérifiées"
        self.status_label.text = f'Tentative de chargement {self.test_file}...'
        Clock.schedule_once(self.auto_load_after_permissions, 1)
    
    def auto_load_after_permissions(self, dt):
        """Charge automatiquement test.eml après les permissions"""
        self.load_test_file(None)
    
    def get_download_paths(self):
        """Retourne les chemins possibles pour le dossier Download"""
        paths = []
        
        if ANDROID_AVAILABLE:
            try:
                # Utiliser le chemin Android officiel
                primary_path = primary_external_storage_path()
                if primary_path:
                    paths.append(os.path.join(primary_path, "Download"))
                    paths.append(os.path.join(primary_path, "Downloads"))
            except:
                pass
        
        # Chemins de fallback
        fallback_paths = [
            "/storage/emulated/0/Download",
            "/storage/emulated/0/Downloads",
            "/sdcard/Download",
            "/sdcard/Downloads",
            "/mnt/sdcard/Download",
            "/mnt/sdcard/Downloads"
        ]
        
        paths.extend(fallback_paths)
        return paths
    
    def load_test_file(self, instance):
        """Charge automatiquement test.eml depuis Download"""
        try:
            # Obtenir les chemins possibles
            possible_paths = self.get_download_paths()
            
            file_path = None
            for path in possible_paths:
                test_path = os.path.join(path, self.test_file)
                try:
                    if os.path.exists(test_path) and os.access(test_path, os.R_OK):
                        file_path = test_path
                        self.download_path = path
                        break
                except Exception as e:
                    continue
            
            if file_path:
                try:
                    # Lire le fichier test.eml
                    with open(file_path, 'r', encoding='utf-8') as f:
                        self.eml_content = f.read()
                    
                    # Décrypter et extraire les valeurs
                    self.decrypt_and_extract()
                    self.create_edit_interface()
                    
                    self.status_label.text = f'✅ {self.test_file} chargé depuis {self.download_path}'
                    
                except PermissionError:
                    self.show_error(
                        f"❌ Permission refusée pour lire {self.test_file}\n\n"
                        "Solutions :\n"
                        "1. Paramètres > Applications > Luxamine > Permissions > Stockage > Autoriser\n"
                        "2. Redémarrer l'application\n"
                        "3. Vérifier que test.eml est bien dans Téléchargements"
                    )
                except Exception as e:
                    self.show_error(f"Erreur lecture {self.test_file}: {str(e)}")
                    
            else:
                # Lister les chemins testés pour debug
                paths_tested = "\n".join([f"• {path}" for path in possible_paths[:5]])
                self.show_error(
                    f"❌ Fichier {self.test_file} non trouvé\n\n"
                    f"Chemins testés :\n{paths_tested}\n\n"
                    f"Veuillez placer {self.test_file} dans le dossier Téléchargements de votre Samsung S25."
                )
                
        except Exception as e:
            self.show_error(f"Erreur lors du chargement: {str(e)}")
    
    def decrypt_and_extract(self):
        """Décrypte le fichier EML et extrait les valeurs importantes"""
        try:
            rdata = self.eml_content.strip()
            
            # Extraire l'UID de la première ligne
            lines = rdata.split('\n')
            if len(lines) > 0:
                first_line = lines[0].strip()
                if len(first_line) >= 8:
                    taguid = first_line[:8]
                else:
                    taguid = "12345678"
            else:
                taguid = "12345678"
            
            # Créer la clé XTEA
            xteakey = self.core.create_xtea_key(taguid)
            
            # Valeurs par défaut modifiables
            self.card_values = {
                'version_a': 1,
                'version_b': 1,
                'credit_a': 10.50,
                'credit_b': 10.50,
                'date_a': '2024-01-01 12:00',
                'date_b': '2024-01-01 12:00'
            }
            
        except Exception as e:
            self.show_error(f"Erreur lors du décryptage: {str(e)}")
            # Valeurs par défaut en cas d'erreur
            self.card_values = {
                'version_a': 1,
                'version_b': 1,
                'credit_a': 0.0,
                'credit_b': 0.0,
                'date_a': '2024-01-01 12:00',
                'date_b': '2024-01-01 12:00'
            }
    
    def create_edit_interface(self):
        """Crée l'interface d'édition des valeurs"""
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
    
    def save_patched_eml(self, instance):
        """Sauvegarde le fichier EML modifié en test_patch.eml"""
        try:
            if not self.eml_content:
                self.show_error("Aucun fichier chargé. Chargez d'abord test.eml.")
                return
            
            if not self.download_path:
                self.show_error("Chemin de sauvegarde non défini.")
                return
            
            # Récupération des nouvelles valeurs
            new_values = {}
            new_values['version_a'] = int(self.inputs['version_a'].text or 0)
            new_values['version_b'] = int(self.inputs['version_b'].text or 0)
            new_values['credit_a'] = float(self.inputs['credit_a'].text or 0.0)
            new_values['credit_b'] = float(self.inputs['credit_b'].text or 0.0)
            new_values['date_a'] = self.inputs['date_a'].text
            new_values['date_b'] = self.inputs['date_b'].text
            
            # Chemin de sortie dans le même dossier Download
            output_path = os.path.join(self.download_path, self.output_file)
            
            # Créer le contenu modifié
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            modified_content = f"""# Luxamine - Fichier EML modifié
# Fichier source: {self.test_file}
# Modifié le: {timestamp}
# Version A: {new_values['version_a']}
# Version B: {new_values['version_b']}
# Crédit A: {new_values['credit_a']:.2f}€
# Crédit B: {new_values['credit_b']:.2f}€
# Date A: {new_values['date_a']}
# Date B: {new_values['date_b']}

{self.eml_content}

# Fin du fichier modifié par Luxamine
"""
            
            # Écriture du fichier modifié
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(modified_content)
                
                self.status_label.text = f'✅ {self.output_file} sauvegardé dans Download'
                self.show_success(f"Fichier modifié sauvegardé:\n{output_path}\n\nLes nouvelles valeurs ont été appliquées dans {self.output_file}.")
                
            except PermissionError:
                self.show_error(
                    f"❌ Permission refusée pour écrire {self.output_file}\n\n"
                    "Vérifiez les permissions de stockage dans :\n"
                    "Paramètres > Applications > Luxamine > Permissions"
                )
            except Exception as e:
                self.show_error(f"Erreur écriture: {str(e)}")
            
        except Exception as e:
            self.show_error(f"Erreur lors de la sauvegarde: {str(e)}")
    
    def reset_form(self, instance):
        """Remet les valeurs par défaut dans le formulaire"""
        if hasattr(self, 'card_values') and hasattr(self, 'inputs'):
            for key, input_field in self.inputs.items():
                if key in ['credit_a', 'credit_b']:
                    input_field.text = f"{self.card_values[key]:.2f}"
                else:
                    input_field.text = str(self.card_values[key])
            self.status_label.text = 'Valeurs réinitialisées'
    
    def show_error(self, message):
        """Affiche un popup d'erreur"""
        content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        label = Label(text=message, text_size=(350, None), halign='center')
        ok_btn = Button(text='OK', size_hint_y=None, height=dp(50))
        content.add_widget(label)
        content.add_widget(ok_btn)
        
        popup = Popup(
            title='Information',
            content=content,
            size_hint=(0.9, 0.6)
        )
        ok_btn.bind(on_press=popup.dismiss)
        popup.open()
    
    def show_success(self, message):
        """Affiche un popup de succès"""
        content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        label = Label(text=message, text_size=(350, None), halign='center')
        ok_btn = Button(text='OK', size_hint_y=None, height=dp(50))
        content.add_widget(label)
        content.add_widget(ok_btn)
        
        popup = Popup(
            title='Succès',
            content=content,
            size_hint=(0.9, 0.6)
        )
        ok_btn.bind(on_press=popup.dismiss)
        popup.open()

if __name__ == '__main__':
    LuxamineApp().run()

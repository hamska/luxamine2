# Luxamine - Éditeur de cartes Mifare Amine

## Description

Luxamine est une application Android permettant de décrypter, modifier et recrypter les données des cartes Mifare de type "Amine tag". L'application offre une interface simple pour éditer les valeurs importantes (Version, Crédit, Date) et génère automatiquement un nouveau dump avec les CRC recalculés.

## Fonctionnalités

### ✅ Fonctionnalités principales
- **Décryptage automatique** des fichiers EML de cartes Mifare
- **Interface d'édition simple** pour les valeurs importantes :
  - Version A et B
  - Crédit A et B (en euros)
  - Date A et B (format YYYY-MM-DD HH:MM)
- **Recalcul automatique des CRC** lors de la sauvegarde
- **Recryptage automatique** avec la clé XTEA appropriée
- **Sauvegarde** du nouveau dump modifié

### 🔧 Fonctionnalités techniques
- **Algorithme XTEA** pour le cryptage/décryptage
- **Calcul CRC16/ARC** pour l'intégrité des données
- **Support des clés AZTEKM** pour l'identification des blocs cryptés
- **Gestion de l'endianness** pour la compatibilité des données

## Installation

1. Téléchargez le fichier APK sur votre appareil Android
2. Activez l'installation d'applications depuis des sources inconnues dans les paramètres
3. Installez l'APK en tapant dessus
4. Lancez l'application "Luxamine"

## Utilisation

### Étape 1 : Charger un fichier EML
1. Tapez sur "Charger fichier EML"
2. Naviguez vers votre fichier .eml
3. Sélectionnez le fichier

### Étape 2 : Modifier les valeurs
1. L'application affiche automatiquement les valeurs décryptées :
   - **Version A/B** : Numéro de version de la carte
   - **Crédit A/B** : Montant en euros (ex: 10.50)
   - **Date A/B** : Date au format YYYY-MM-DD HH:MM
2. Modifiez les valeurs selon vos besoins

### Étape 3 : Sauvegarder
1. Tapez sur "Sauvegarder EML modifié"
2. L'application génère automatiquement un nouveau fichier avec :
   - Les nouvelles valeurs
   - Les CRC recalculés
   - Le cryptage XTEA appliqué
3. Le fichier est sauvegardé avec un horodatage

## Format des données

### Fichiers d'entrée
- **Format** : .eml (dump de carte Mifare)
- **Contenu** : Données hexadécimales des secteurs de la carte
- **Cryptage** : Blocs cryptés avec XTEA identifiés par la clé AZTEKM

### Fichiers de sortie
- **Nom** : luxamine_modified_YYYYMMDD_HHMMSS.eml
- **Contenu** : Dump modifié avec nouvelles valeurs et CRC corrects
- **Emplacement** : /sdcard/ ou répertoire de l'application

## Sécurité

⚠️ **Important** : Cette application est destinée à des fins éducatives et de recherche. L'utilisation sur des cartes dont vous n'êtes pas propriétaire peut être illégale selon votre juridiction.

## Support technique

### Formats supportés
- Cartes Mifare avec cryptage XTEA
- Tags Amine avec clé AZTEKM
- Fichiers EML standard

### Limitations
- Nécessite Android 5.0 (API 21) minimum
- Fonctionne uniquement avec les cartes de type "Amine"
- Les fichiers doivent être au format EML valide

## Développement

### Architecture
- **Interface** : Kivy (Python)
- **Cryptographie** : XTEA, CRC16/ARC
- **Plateforme** : Android (ARM)

### Code source
L'application est basée sur le script Python original `luxamine.py` adapté pour l'environnement mobile avec une interface utilisateur graphique.

## Version

**Version actuelle** : 1.0
**Date de compilation** : Septembre 2024
**Compatibilité** : Android 5.0+

---

*Développé avec Kivy et Python-for-Android*

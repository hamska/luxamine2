[app]
title = Luxamine
package.name = luxamine
package.domain = com.luxamine.editor
source.dir = .
source.include_exts = py,eml
version = 1.8
requirements = python3,kivy
orientation = portrait

android.api = 30
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True

# AUCUNE permission de stockage nécessaire (dossier privé)
# android.permissions = 

[buildozer]
log_level = 2
warn_on_root = 1

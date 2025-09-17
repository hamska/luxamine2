[app]
title = Luxamine
package.name = luxamine
package.domain = com.luxamine.editor
source.dir = .
source.include_exts = py,eml
version = 1.6
requirements = python3,kivy
orientation = portrait

android.api = 30
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True

# Permissions complètes pour accès stockage
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE

# Permissions runtime pour Android 6+
android.private_storage = True

# Manifest pour permissions explicites
android.add_src = src/

[buildozer]
log_level = 2
warn_on_root = 1

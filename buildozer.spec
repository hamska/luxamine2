[app]
title = Luxamine
package.name = luxamine
package.domain = com.luxamine.editor
source.dir = .
source.include_exts = py,eml
version = 1.1
requirements = python3,kivy
orientation = portrait

android.api = 30
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True

# Permissions pour accéder aux fichiers
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE

[buildozer]
log_level = 2
warn_on_root = 1

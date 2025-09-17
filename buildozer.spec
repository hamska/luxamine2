[app]
title = Luxamine
package.name = luxamine
package.domain = com.luxamine.editor
source.dir = .
source.include_exts = py,eml
version = 1.4
requirements = python3,kivy,plyer
orientation = portrait

android.api = 30
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True

# Permissions pour Plyer et accès fichiers
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE

# Gradle dependencies pour SAF (Storage Access Framework)
android.gradle_dependencies = androidx.documentfile:documentfile:1.0.1

[buildozer]
log_level = 2
warn_on_root = 1

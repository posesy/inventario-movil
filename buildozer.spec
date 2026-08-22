[app]

title = Inventario Movil
package.name = inventariomovil
package.domain = org.patriciomedina

source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 0.1

requirements = python3,kivy,pyjnius,opencv,pyzbar,pycryptodome,pillow,pg8000,charset-normalizer,scramp,numpy

orientation = portrait
fullscreen = 0

android.permissions = CAMERA,INTERNET
android.api = 33
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a,armeabi-v7a
android.allow_backup = True

[buildozer]

log_level = 2
warn_on_root = 1

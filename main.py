# -*- coding: utf-8 -*-
"""
inventario_movil_app.py

App Kivy responsive para Android (sin scroll): escanea QR de conexion,
luego usa la camara para leer codigos de barras, trae datos desde
PostgreSQL y permite sumar/restar cantidades al stock.

Requiere (buildozer.spec):
    requirements = python3,kivy,pyjnius,opencv,pyzbar,pycryptodome,pillow,pg8000,charset-normalizer,scramp,numpy
    android.permissions = CAMERA,INTERNET

La clave de conexion NUNCA se guarda en disco.
"""

import json
import time
import base64
import os
import sys
import platform
import threading
from datetime import date, datetime

from kivy.app import App
from kivy.uix.screenmanager import Screen, ScreenManager, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.clock import Clock
from kivy.graphics.texture import Texture
from kivy.core.window import Window
from kivy.metrics import dp, sp

import cv2
import numpy as np
from PIL import Image as PILImage

from pyzbar.pyzbar import decode as zbar_decode

import pg8000
from pg8000.exceptions import DatabaseError, InterfaceError

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


# ================= SONIDO CROSS-PLATFORM =================

def beep(tipo="ok"):
    duracion = 200
    try:
        from jnius import autoclass
        ToneGenerator = autoclass('android.media.ToneGenerator')
        AudioManager = autoclass('android.media.AudioManager')
        tg = ToneGenerator(AudioManager.STREAM_NOTIFICATION, 100)
        if tipo == "error":
            tg.startTone(ToneGenerator.TONE_PROP_BEEP2, duracion)
        else:
            tg.startTone(ToneGenerator.TONE_PROP_BEEP, duracion)
    except ImportError:
        try:
            import winsound
            if tipo == "error":
                winsound.Beep(800, 300)
            elif tipo == "guardar":
                winsound.Beep(2000, 100)
            else:
                winsound.Beep(1200, 200)
        except ImportError:
            try:
                print('\a', end='', flush=True)
            except Exception:
                pass


# ================= FILTRO INPUT =================

def filtro_entero(text, from_undo):
    return ''.join(c for c in text if c in '-0123456789')


def abrir_camara(indice=0):
    """Abre la camara con el backend adecuado segun el sistema operativo.
    En Windows se fuerza DirectShow (CAP_DSHOW): el backend por defecto
    (MSMF) tiene un problema conocido de OpenCV que puede quedarse
    colgado al hacer release() y volver a abrir la camara enseguida
    (justo lo que pasa al cerrar sesion y volver a la pantalla de QR).
    En Android/Linux se deja el backend por defecto."""
    if platform.system() == "Windows":
        return cv2.VideoCapture(indice, cv2.CAP_DSHOW)
    return cv2.VideoCapture(indice)


# ================= SEGURIDAD QR =================
CLAVE_APP = "CAMBIAR_ESTA_CLAVE_COMPARTIDA"

ITERACIONES_PBKDF2 = 200_000
LARGO_CLAVE = 32
LARGO_SALT = 16
LARGO_IV = 12
LARGO_TAG = 16


class QRInvalidoError(Exception):
    pass


class QRExpiradoError(Exception):
    pass


def _derivar_clave(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=LARGO_CLAVE,
        count=ITERACIONES_PBKDF2,
        hmac_hash_module=SHA256,
    )


def desencriptar_datos(paquete_b64: str, password: str = CLAVE_APP) -> dict:
    try:
        paquete_limpio = paquete_b64.strip().replace("\n", "").replace("\r", "")
        paquete = base64.b64decode(paquete_limpio)

        salt = paquete[:LARGO_SALT]
        iv = paquete[LARGO_SALT:LARGO_SALT + LARGO_IV]
        cifrado_y_tag = paquete[LARGO_SALT + LARGO_IV:]
        ciphertext = cifrado_y_tag[:-LARGO_TAG]
        tag = cifrado_y_tag[-LARGO_TAG:]

        clave = _derivar_clave(password, salt)
        cipher = AES.new(clave, AES.MODE_GCM, nonce=iv)
        plano = cipher.decrypt_and_verify(ciphertext, tag)
        datos = json.loads(plano.decode("utf-8"))
    except Exception as e:
        raise QRInvalidoError(f"QR invalido o clave incorrecta: {e}")

    ahora = int(time.time())
    validez = datos.get("valido_seg", 180)
    ts = datos.get("ts", 0)
    if ahora - ts > validez:
        raise QRExpiradoError("El QR ya expiro. Pide que generen uno nuevo.")

    return datos


# ================= POPUP CON BOTON CERRAR =================

def mostrar_popup(titulo, mensaje):
    box = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(10))
    box.add_widget(Label(text=mensaje, font_size=sp(16)))
    btn_cerrar = Button(text="Cerrar", size_hint=(1, None), height=dp(45), font_size=sp(16))
    box.add_widget(btn_cerrar)

    popup = Popup(
        title=titulo,
        content=box,
        size_hint=(0.9, None),
        height=dp(200),
        auto_dismiss=False
    )
    btn_cerrar.bind(on_press=popup.dismiss)
    popup.open()


# ================= PANTALLA DE ESCANEO QR =================

class PantallaEscaneo(Screen):
    INTERVALO_VIDEO_SEG = 1.0 / 30.0
    INTERVALO_QR_SEG = 0.3
    RESOLUCION_CAMARA = (640, 480)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._cap = None
        self._detector = cv2.QRCodeDetector()
        self._escaneando = False
        self._frame_actual = None
        self._evt_video = None
        self._evt_qr = None

        # Layout vertical que ocupa toda la pantalla, sin scroll
        self.layout = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(6))

        self.estado = Label(
            text="Apunta la camara al QR de conexion",
            size_hint=(1, 0.12),
            font_size=sp(18),
            halign="center",
            valign="middle"
        )
        self.estado.bind(size=self.estado.setter('text_size'))

        # Camara ocupa el 68% del espacio restante
        self.vista_camara = Image(size_hint=(1, 0.68))

        self.btn_reintentar = Button(
            text="Reintentar escaneo",
            size_hint=(1, 0.12),
            font_size=sp(16),
            disabled=True
        )
        self.btn_reintentar.bind(on_press=self._on_reintentar)

        self.layout.add_widget(self.estado)
        self.layout.add_widget(self.vista_camara)
        self.layout.add_widget(self.btn_reintentar)
        self.add_widget(self.layout)

    def on_enter(self):
        self.iniciar_escaneo()

    def on_leave(self):
        self._detener_escaneo()

    def _on_reintentar(self, *args):
        self._detener_escaneo()
        Clock.schedule_once(lambda dt: self.iniciar_escaneo(), 0.3)

    def iniciar_escaneo(self):
        self._detener_escaneo()
        self._frame_actual = None
        self.estado.text = "Apunta la camara al QR de conexion"
        self.estado.color = (1, 1, 1, 1)
        self.btn_reintentar.disabled = True
        self._escaneando = True

        self._cap = abrir_camara(0)
        self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.RESOLUCION_CAMARA[0])
        self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.RESOLUCION_CAMARA[1])

        if not self._cap.isOpened():
            self.estado.text = "No se pudo abrir la camara."
            self.estado.color = (1, 0.3, 0.3, 1)
            self.btn_reintentar.disabled = False
            self._escaneando = False
            return

        self._evt_video = Clock.schedule_interval(self._actualizar_video, self.INTERVALO_VIDEO_SEG)
        self._evt_qr = Clock.schedule_interval(self._revisar_qr, self.INTERVALO_QR_SEG)

    def _detener_escaneo(self):
        self._escaneando = False
        if self._evt_video:
            self._evt_video.cancel()
            self._evt_video = None
        if self._evt_qr:
            self._evt_qr.cancel()
            self._evt_qr = None
        if self._cap:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None
        self._frame_actual = None

    def _actualizar_video(self, dt):
        if self._cap is None or not self._cap.isOpened():
            return
        ret, frame = self._cap.read()
        if not ret or frame is None:
            return
        self._frame_actual = frame
        self._mostrar_frame(frame)

    def _mostrar_frame(self, frame_bgr):
        frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
        frame_rgb = cv2.flip(frame_rgb, 0)
        alto, ancho, _ = frame_rgb.shape
        buf = frame_rgb.tobytes()
        texture = Texture.create(size=(ancho, alto), colorfmt='rgb')
        texture.blit_buffer(buf, colorfmt='rgb', bufferfmt='ubyte')
        self.vista_camara.texture = texture

    def _revisar_qr(self, dt):
        if not self._escaneando or self._frame_actual is None:
            return
        texto_qr = self._buscar_qr_en_frame(self._frame_actual)
        if texto_qr is not None:
            self._detener_escaneo()
            self._procesar_texto_qr(texto_qr)

    def _buscar_qr_en_frame(self, frame_bgr):
        gris = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        data, bbox, _ = self._detector.detectAndDecode(gris)
        if data:
            return data.strip()
        return None

    def _procesar_texto_qr(self, texto_qr: str):
        try:
            datos = desencriptar_datos(texto_qr)
        except QRExpiradoError:
            beep("error")
            self.estado.text = "El QR ya expiro. Pide que generen uno nuevo."
            self.estado.color = (1, 0.3, 0.3, 1)
            self.btn_reintentar.disabled = False
            return
        except QRInvalidoError:
            beep("error")
            self.estado.text = "QR invalido. Verifica que sea el QR correcto."
            self.estado.color = (1, 0.3, 0.3, 1)
            self.btn_reintentar.disabled = False
            return

        beep("ok")
        self.estado.text = f"Conectado a: {datos.get('tienda', 'Desconocido')}"
        self.estado.color = (0.2, 0.9, 0.3, 1)
        app = App.get_running_app()
        app.guardar_datos_conexion(datos)


# ================= PANTALLA DE CONTEO =================

class PantallaConteo(Screen):
    INTERVALO_VIDEO_SEG = 1.0 / 30.0
    INTERVALO_BARRA_SEG = 0.12
    RESOLUCION_CAMARA = (1280, 720)
    COOLDOWN_LECTURA_SEG = 1.2

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.conn = None
        self.cursor = None
        self._cap = None
        self._escaneando = False
        self._frame_actual = None
        self._evt_video = None
        self._evt_barra = None
        self._ultimo_barra = ""
        self._lectura_bloqueada = False
        self._ultima_lectura_ts = 0
        self._analizando_frame = False

        # Layout vertical proporcional, sin scroll, ocupa 100% de la pantalla
        self.layout = BoxLayout(orientation="vertical", padding=dp(6), spacing=dp(4))

        # Header: 5%
        self.lbl_header = Label(
            text="Conteo de Inventario",
            size_hint=(1, 0.05),
            font_size=sp(18),
            bold=True,
            halign="center",
            valign="middle"
        )
        self.lbl_header.bind(size=self.lbl_header.setter('text_size'))

        # Tienda: 4%
        self.lbl_tienda = Label(
            text="",
            size_hint=(1, 0.04),
            font_size=sp(12),
            color=(0.6, 0.6, 0.6, 1),
            halign="center",
            valign="middle"
        )
        self.lbl_tienda.bind(size=self.lbl_tienda.setter('text_size'))

        # Camara: 22%
        self.vista_camara = Image(size_hint=(1, 0.22))

        # Instruccion: 4%
        self.lbl_instruccion = Label(
            text="Apunta la camara al codigo de barras",
            size_hint=(1, 0.04),
            font_size=sp(12),
            color=(0.5, 0.7, 1, 1),
            halign="center",
            valign="middle"
        )
        self.lbl_instruccion.bind(size=self.lbl_instruccion.setter('text_size'))

        # Entrada manual: 7%
        manual_box = BoxLayout(
            orientation="horizontal",
            size_hint=(1, 0.07),
            spacing=dp(4)
        )
        self.txt_manual = TextInput(
            multiline=False,
            font_size=sp(14),
            hint_text="O escribe el codigo manualmente...",
            size_hint=(0.7, 1)
        )
        self.txt_manual.bind(on_text_validate=self._buscar_manual)
        self.btn_buscar_manual = Button(
            text="Buscar",
            size_hint=(0.3, 1),
            font_size=sp(14)
        )
        self.btn_buscar_manual.bind(on_press=self._buscar_manual)
        manual_box.add_widget(self.txt_manual)
        manual_box.add_widget(self.btn_buscar_manual)

        # Datos del producto: 22%
        datos_box = BoxLayout(
            orientation="vertical",
            size_hint=(1, 0.22),
            spacing=dp(2)
        )
        self.lbl_codigo = Label(
            text="Codigo: -",
            font_size=sp(13),
            halign="left",
            valign="middle",
            size_hint=(1, 0.25)
        )
        self.lbl_codigo.bind(size=self.lbl_codigo.setter('text_size'))
        self.lbl_nombre = Label(
            text="Producto: -",
            font_size=sp(13),
            halign="left",
            valign="middle",
            size_hint=(1, 0.25)
        )
        self.lbl_nombre.bind(size=self.lbl_nombre.setter('text_size'))
        self.lbl_stock = Label(
            text="Stock actual: -",
            font_size=sp(13),
            halign="left",
            valign="middle",
            color=(0.2, 0.8, 0.2, 1),
            size_hint=(1, 0.25)
        )
        self.lbl_stock.bind(size=self.lbl_stock.setter('text_size'))
        self.lbl_precio = Label(
            text="Precio: -",
            font_size=sp(13),
            halign="left",
            valign="middle",
            size_hint=(1, 0.25)
        )
        self.lbl_precio.bind(size=self.lbl_precio.setter('text_size'))
        datos_box.add_widget(self.lbl_codigo)
        datos_box.add_widget(self.lbl_nombre)
        datos_box.add_widget(self.lbl_stock)
        datos_box.add_widget(self.lbl_precio)

        # Input cantidad: 7%
        input_box = GridLayout(
            cols=2,
            size_hint=(1, 0.07),
            spacing=dp(4)
        )
        input_box.add_widget(Label(
            text="Cantidad:",
            font_size=sp(14),
            halign="right",
            valign="middle"
        ))
        self.txt_cantidad = TextInput(
            multiline=False,
            input_filter=filtro_entero,
            font_size=sp(16),
            hint_text="0 (usa - para restar)",
            size_hint=(1, 1)
        )
        input_box.add_widget(self.txt_cantidad)

        # Botones: 7% + 6% + 6% = 19%
        self.btn_guardar = Button(
            text="GUARDAR CONTEO",
            size_hint=(1, 0.07),
            font_size=sp(16),
            background_color=(0.2, 0.7, 0.3, 1)
        )
        self.btn_guardar.bind(on_press=self._guardar_conteo)

        self.btn_nuevo = Button(
            text="NUEVO PRODUCTO (escanear otro)",
            size_hint=(1, 0.06),
            font_size=sp(12)
        )
        self.btn_nuevo.bind(on_press=self._nuevo_producto)

        self.btn_cerrar = Button(
            text="Cerrar sesion",
            size_hint=(1, 0.06),
            font_size=sp(12)
        )
        self.btn_cerrar.bind(on_press=self._cerrar_sesion)

        # Suma de proporciones: 5+4+22+4+7+22+7+7+6+6 = 90% (deja margen)
        self.layout.add_widget(self.lbl_header)
        self.layout.add_widget(self.lbl_tienda)
        self.layout.add_widget(self.vista_camara)
        self.layout.add_widget(self.lbl_instruccion)
        self.layout.add_widget(manual_box)
        self.layout.add_widget(datos_box)
        self.layout.add_widget(input_box)
        self.layout.add_widget(self.btn_guardar)
        self.layout.add_widget(self.btn_nuevo)
        self.layout.add_widget(self.btn_cerrar)
        self.add_widget(self.layout)

    def on_enter(self):
        app = App.get_running_app()
        datos = app.datos_conexion or {}
        self.lbl_tienda.text = f"Tienda: {datos.get('tienda', '---')}"
        self._conectar_db()
        self._iniciar_camara()

    def on_leave(self):
        self._detener_camara()
        self._desconectar_db()

    # ---------- DB ----------
    def _conectar_db(self):
        app = App.get_running_app()
        datos = app.datos_conexion
        if not datos:
            return
        try:
            self.conn = pg8000.connect(
                host=datos["host"],
                port=datos.get("port", 5432),
                database=datos["base"],
                user=datos["usuario"],
                password=datos["clave"],
                timeout=10,
            )
            self.cursor = self.conn.cursor()
        except Exception as e:
            mostrar_popup("Error DB", str(e))
            self.conn = None
            self.cursor = None

    def _desconectar_db(self):
        if self.cursor:
            try:
                self.cursor.close()
            except Exception:
                pass
            self.cursor = None
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    # ---------- CAMARA ----------
    def _iniciar_camara(self):
        self._detener_camara()
        self._escaneando = True
        self._lectura_bloqueada = False
        self._analizando_frame = False
        self._ultimo_barra = ""
        self._ultima_lectura_ts = 0
        self._cap = abrir_camara(0)
        self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.RESOLUCION_CAMARA[0])
        self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.RESOLUCION_CAMARA[1])

        if not self._cap.isOpened():
            self.lbl_instruccion.text = "No se pudo abrir la camara"
            self.lbl_instruccion.color = (1, 0.3, 0.3, 1)
            return

        self._evt_video = Clock.schedule_interval(self._actualizar_video, self.INTERVALO_VIDEO_SEG)
        self._evt_barra = Clock.schedule_interval(self._revisar_barra, self.INTERVALO_BARRA_SEG)

    def _detener_camara(self):
        self._escaneando = False
        if self._evt_video:
            self._evt_video.cancel()
            self._evt_video = None
        if self._evt_barra:
            self._evt_barra.cancel()
            self._evt_barra = None
        if self._cap:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None
        self._frame_actual = None

    def _actualizar_video(self, dt):
        if self._cap is None or not self._cap.isOpened():
            return
        ret, frame = self._cap.read()
        if not ret or frame is None:
            return
        self._frame_actual = frame
        self._mostrar_frame(frame)

    def _mostrar_frame(self, frame_bgr):
        frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
        frame_rgb = cv2.flip(frame_rgb, 0)
        alto, ancho, _ = frame_rgb.shape
        buf = frame_rgb.tobytes()
        texture = Texture.create(size=(ancho, alto), colorfmt='rgb')
        texture.blit_buffer(buf, colorfmt='rgb', bufferfmt='ubyte')
        self.vista_camara.texture = texture

    def _revisar_barra(self, dt):
        # No seguir leyendo mientras hay un producto pendiente de guardar
        # (antes esta bandera se seteaba pero nunca se consultaba, y la
        # camara podia pisar el producto en pantalla con otro codigo
        # mientras el usuario estaba escribiendo la cantidad).
        if self._lectura_bloqueada:
            return
        if self._analizando_frame:
            return
        if not self._escaneando or self._frame_actual is None:
            return

        # El analisis (varias escalas + filtros) es pesado: se corre en un
        # hilo aparte para no congelar la UI de Kivy en cada intervalo.
        self._analizando_frame = True
        frame_copia = self._frame_actual.copy()
        hilo = threading.Thread(
            target=self._hilo_buscar_codigo,
            args=(frame_copia,),
            daemon=True
        )
        hilo.start()

    def _hilo_buscar_codigo(self, frame_copia):
        try:
            texto = self._buscar_codigo_en_frame(frame_copia)
        except Exception:
            texto = None
        Clock.schedule_once(lambda dt: self._procesar_resultado_barra(texto))

    def _procesar_resultado_barra(self, texto):
        self._analizando_frame = False

        if self._lectura_bloqueada:
            return
        if texto is None:
            return

        ahora = time.time()
        if texto == self._ultimo_barra and (ahora - self._ultima_lectura_ts) < self.COOLDOWN_LECTURA_SEG:
            return

        self._ultimo_barra = texto
        self._ultima_lectura_ts = ahora
        beep("ok")
        self._buscar_producto(texto)

    def _rotar_imagen(self, imagen, angulo):
        alto, ancho = imagen.shape[:2]
        centro = (ancho // 2, alto // 2)
        matriz = cv2.getRotationMatrix2D(centro, angulo, 1.0)
        return cv2.warpAffine(imagen, matriz, (ancho, alto), borderMode=cv2.BORDER_REPLICATE)

    def _buscar_codigo_en_frame(self, frame_bgr):
        variantes = []

        # Angulos para cubrir codigos fotografiados inclinados o sobre
        # superficies curvas (ej. un lapiz/marcador cilindrico), donde
        # el codigo no queda perfectamente horizontal.
        for escala in (0.75, 1.0):
            img = frame_bgr if escala == 1.0 else cv2.resize(frame_bgr, None, fx=escala, fy=escala)
            gris = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            for angulo in (0, -8, 8):
                base = gris if angulo == 0 else self._rotar_imagen(gris, angulo)
                variantes.append(base)

                adapt = cv2.adaptiveThreshold(base, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                               cv2.THRESH_BINARY, 11, 2)
                variantes.append(adapt)

                blur = cv2.GaussianBlur(base, (5, 5), 0)
                _, otsu = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                variantes.append(otsu)

        for img in variantes:
            pil_img = PILImage.fromarray(img)
            resultados = zbar_decode(pil_img)
            if resultados:
                return resultados[0].data.decode("utf-8").strip()

        return None

    def _buscar_producto(self, barra: str):
        if not self.cursor:
            mostrar_popup("Error", "Sin conexion a la base de datos.")
            return

        self._ultimo_barra = barra
        self.btn_nuevo.disabled = False
        self._lectura_bloqueada = True

        try:
            self.cursor.execute(
                "SELECT nombre, stock, venta FROM public.productos WHERE barra = %s LIMIT 1",
                (barra,)
            )
            fila = self.cursor.fetchone()
        except Exception as e:
            mostrar_popup("Error", f"Error al buscar: {e}")
            return

        if fila is None:
            self.lbl_codigo.text = f"Codigo: {barra}"
            self.lbl_nombre.text = "Producto: NO ENCONTRADO"
            self.lbl_stock.text = "Stock actual: -"
            self.lbl_precio.text = "Precio: -"
            self.lbl_nombre.color = (1, 0.3, 0.3, 1)
            self.lbl_instruccion.text = "Producto no encontrado. Pulsa NUEVO PRODUCTO."
            self.lbl_instruccion.color = (1, 0.5, 0.2, 1)
            return

        nombre, stock, venta = fila
        self.lbl_codigo.text = f"Codigo: {barra}"
        self.lbl_nombre.text = f"Producto: {nombre}"
        self.lbl_stock.text = f"Stock actual: {stock}"
        self.lbl_precio.text = f"Precio: ${venta}"
        self.lbl_nombre.color = (1, 1, 1, 1)

        self.lbl_instruccion.text = "Ingresa cantidad y presiona GUARDAR"
        self.lbl_instruccion.color = (1, 0.8, 0.2, 1)
        self.txt_cantidad.focus = True

    def _buscar_manual(self, *args):
        barra = self.txt_manual.text.strip()
        if not barra:
            mostrar_popup("Atencion", "Escribe un codigo primero.")
            return
        self.txt_manual.text = ""
        self._buscar_producto(barra)

    def _guardar_conteo(self, *args):
        if not self.cursor or not self.conn:
            mostrar_popup("Error", "Sin conexion a la base de datos.")
            return

        cantidad_str = self.txt_cantidad.text.strip()
        if not cantidad_str:
            mostrar_popup("Error", "Ingresa una cantidad.")
            return

        try:
            cantidad = int(cantidad_str)
        except ValueError:
            mostrar_popup("Error", "Cantidad invalida.")
            return

        if cantidad == 0:
            mostrar_popup("Error", "La cantidad no puede ser 0.")
            return

        barra = self._ultimo_barra
        if not barra:
            mostrar_popup("Error", "Escanea o busca un producto primero.")
            return

        app = App.get_running_app()
        datos = app.datos_conexion or {}
        usuario = datos.get("usuario", "movil")
        tienda = datos.get("tienda", "")

        try:
            self.cursor.execute(
                """
                UPDATE public.productos
                SET stock = stock + %s,
                    fecha = %s,
                    lahora = %s,
                    usuario = %s,
                    tienda = %s
                WHERE barra = %s
                """,
                (cantidad, date.today(), datetime.now().time(), usuario, tienda, barra)
            )
            self.conn.commit()

            self.cursor.execute(
                "SELECT stock FROM public.productos WHERE barra = %s LIMIT 1",
                (barra,)
            )
            nuevo_stock = self.cursor.fetchone()[0]
            self.lbl_stock.text = f"Stock actual: {nuevo_stock}"

            beep("guardar")
            signo = "+" if cantidad > 0 else ""
            mostrar_popup("OK", f"Guardado!\n{barra}\n{signo}{cantidad} unidades")
            self.txt_cantidad.text = ""
            self._lectura_bloqueada = False
            self.lbl_instruccion.text = "Apunta la camara al codigo de barras"
            self.lbl_instruccion.color = (0.5, 0.7, 1, 1)
            self._ultimo_barra = ""

        except Exception as e:
            self.conn.rollback()
            beep("error")
            mostrar_popup("Error", f"No se pudo guardar: {e}")

    def _nuevo_producto(self, *args):
        self._lectura_bloqueada = False
        self._ultimo_barra = ""
        self.lbl_codigo.text = "Codigo: -"
        self.lbl_nombre.text = "Producto: -"
        self.lbl_stock.text = "Stock actual: -"
        self.lbl_precio.text = "Precio: -"
        self.txt_cantidad.text = ""
        self.lbl_instruccion.text = "Apunta la camara al codigo de barras"
        self.lbl_instruccion.color = (0.5, 0.7, 1, 1)

    def _cerrar_sesion(self, *args):
        app = App.get_running_app()
        app.borrar_datos_conexion()
        self._detener_camara()
        self._desconectar_db()
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current = "escaneo"


# ================= APP PRINCIPAL =================

class InventarioMovilApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.datos_conexion = None
        self._pantalla_escaneo = None
        self._pantalla_conteo = None

    def build(self):
        Window.bind(on_request_close=self._on_request_close)

        sm = ScreenManager(transition=SlideTransition())
        self._pantalla_escaneo = PantallaEscaneo(name="escaneo")
        self._pantalla_conteo = PantallaConteo(name="conteo")
        sm.add_widget(self._pantalla_escaneo)
        sm.add_widget(self._pantalla_conteo)
        return sm

    def _on_request_close(self, *args):
        print("[APP] Cerrando aplicacion...")
        self._liberar_recursos()
        return False  # deja que Kivy cierre la ventana normalmente

    def on_stop(self):
        print("[APP] on_stop llamado.")
        self._liberar_recursos()
        super().on_stop()
        # Red de seguridad: en Windows, un hilo interno del backend de
        # camara (DirectShow/COM) a veces no termina solo y deja el
        # proceso colgado aunque Kivy ya cerro todo correctamente (se ve
        # en el log que on_stop se ejecuto sin errores). Forzamos el
        # cierre real del proceso medio segundo despues, dando tiempo a
        # que la salida normal ocurra primero si puede.
        threading.Timer(0.5, lambda: os._exit(0)).start()

    def _liberar_recursos(self):
        if self._pantalla_escaneo:
            self._pantalla_escaneo._detener_escaneo()
        if self._pantalla_conteo:
            self._pantalla_conteo._detener_camara()
            self._pantalla_conteo._desconectar_db()
        try:
            cv2.destroyAllWindows()
        except Exception:
            pass

    def guardar_datos_conexion(self, datos: dict):
        self.datos_conexion = datos
        print("[APP] Datos guardados:", datos)
        self.root.transition = SlideTransition(direction="left")
        self.root.current = "conteo"

    def borrar_datos_conexion(self):
        self.datos_conexion = None
        print("[APP] Datos borrados.")


if __name__ == "__main__":
    InventarioMovilApp().run()

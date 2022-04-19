import os
import signal
import argparse

from flask import Flask, render_template, send_file, redirect, request, send_from_directory, url_for, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.serving import run_simple

from updog.utils.path import is_valid_subpath, is_valid_upload_path, get_parent_directory, process_files
from updog.utils.output import error, info, warn, success
from updog import version as VERSION


def read_write_directory(directory):
    if os.path.exists(directory):
        if os.access(directory, os.W_OK and os.R_OK):
            return directory
        else:
            error('Error en permisos de lectura/escritura en salida')
    else:
        error('El directorio especificado no existe')


def parse_arguments():
    parser = argparse.ArgumentParser(prog='CompartirIgualdad')
    cwd = os.getcwd()
    parser.add_argument('-d', '--directory', metavar='DIRECTORY', type=read_write_directory, default=cwd,
                        help='Directorio Root\n'
                             '[Default=.]')
    parser.add_argument('-p', '--port', type=int, default=8080,
                        help='Puerto funcionando [Default=8080]')
    parser.add_argument('--password', type=str, default='', help='Use contraseña para ingresar. (No hace falta usuario)')
    parser.add_argument('--ssl', action='store_true', help='Use conexion encriptada')
    parser.add_argument('--version', action='version', version='%(prog)s v'+VERSION)

    args = parser.parse_args()

    # Normalizando los patch
    args.directory = os.path.abspath(args.directory)

    return args


def main():
    args = parse_arguments()

    app = Flask(__name__)
    auth = HTTPBasicAuth()

    global base_directory
    base_directory = args.directory

    # Solicitudes del archivo favicon
    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'static'),
                                   'images/favicon.ico', mimetype='image/vnd.microsoft.icon')

    ######################################################
    # Navegación de archivos y funcionalidad de descarga #
    ######################################################
    @app.route('/', defaults={'path': None})
    @app.route('/<path:path>')
    @auth.login_required
    def home(path):
        # Si hay un parámetro de ruta y es válido
        if path and is_valid_subpath(path, base_directory):
            # Quitar el final '/'
            path = os.path.normpath(path)
            requested_path = os.path.join(base_directory, path)

            # si es carpeta
            if os.path.isdir(requested_path):
                back = get_parent_directory(requested_path, base_directory)
                is_subdirectory = True

            # si es archivo
            elif os.path.isfile(requested_path):

                # Comprobando si las vistas estan configuradas
                if request.args.get('view') is None:
                    send_as_attachment = True
                else:
                    send_as_attachment = False

                # Chequeamos las extensiones
                (filename, extension) = os.path.splitext(requested_path)
                if extension == '':
                    mimetype = 'text/plain'
                else:
                    mimetype = None

                try:
                    return send_file(requested_path, mimetype=mimetype, as_attachment=send_as_attachment)
                except PermissionError:
                    abort(403, 'Permiso de lectura denegado: ' + requested_path)

        else:
            # Configuraci0n de inicio raiz - root
            is_subdirectory = False
            requested_path = base_directory
            back = ''

        if os.path.exists(requested_path):
            # Lectura de archivos
            try:
                directory_files = process_files(os.scandir(requested_path), base_directory)
            except PermissionError:
                abort(403, 'Permiso de lectura denegado: ' + requested_path)

            return render_template('home.html', files=directory_files, back=back,
                                   directory=requested_path, is_subdirectory=is_subdirectory, version=VERSION)
        else:
            return redirect('/')

    ######################################
    # Funcionalidad de carga de archivos #
    ######################################
    @app.route('/upload', methods=['POST'])
    @auth.login_required
    def upload():
        if request.method == 'POST':

            # Ninguna parte del archivo: debe verificar antes de acceder a los archivos ['archivo']
            if 'file' not in request.files:
                return redirect(request.referrer)

            path = request.form['path']
            # Impedir la carga de archivos en rutas fuera del directorio base
            if not is_valid_upload_path(path, base_directory):
                return redirect(request.referrer)

            for file in request.files.getlist('file'):

                # Sin nombre de archivo adjunto
                if file.filename == '':
                    return redirect(request.referrer)

                # Suponiendo que todo esté bien, procese y guarde el archivo
                # TODO:
                # - Agregar soporte para sobrescribir
                if file:
                    filename = secure_filename(file.filename)
                    full_path = os.path.join(path, filename)
                    try:
                        file.save(full_path)
                    except PermissionError:
                        abort(403, 'Permiso de escritura denegado: ' + full_path)

            return redirect(request.referrer)

    # La función de contraseña no tiene nombre de usuario
    users = {
        '': generate_password_hash(args.password)
    }

    @auth.verify_password
    def verify_password(username, password):
        if args.password:
            if username in users:
                return check_password_hash(users.get(username), password)
            return False
        else:
            return True

    # Informar a la usuaria/o antes de que el servidor suba/arranque
    success('Servicio funcioando {}...'.format(args.directory, args.port))

    def handler(signal, frame):
        print()
        error('Terminando!')
    signal.signal(signal.SIGINT, handler)

    ssl_context = None
    if args.ssl:
        ssl_context = 'adhoc'

    run_simple("0.0.0.0", int(args.port), app, ssl_context=ssl_context)


if __name__ == '__main__':
    main()

1. Crear el entorno virtual
Primero, navega a la carpeta del proyecto donde deseas crear el entorno virtual y ejecuta el siguiente comando:

En sistemas Unix (Linux/macOS):
bash
´´´
python3 -m venv venv
En Windows:
bash
´´´
python -m venv venv
Esto creará un directorio llamado venv que contendrá el entorno virtual.

2. Activar el entorno virtual
En sistemas Unix (Linux/macOS):
bash
´´´
source venv/bin/activate
En Windows:
bash
´´´
venv\Scripts\activate
Después de activar el entorno, deberías ver que el nombre del entorno virtual aparece al principio de tu línea de comandos, indicando que estás trabajando dentro del entorno virtual.

3. Cerrar entorno virtual
deactivate

4. Guardar las dependencias en un archivo requirements.txt
Para guardar todas las dependencias instaladas en el entorno en un archivo requirements.txt (esto es útil si necesitas compartir el entorno o recrearlo):

bash
´´´
pip freeze > requirements.txt
´´´	
5. Para recrear el entorno virtual en otro lugar
Si en el futuro necesitas recrear el entorno virtual en otra máquina o en un directorio diferente, puedes usar el archivo requirements.txt para instalar todas las dependencias con:

bash
´´´
pip install -r requirements.txt
´´´	
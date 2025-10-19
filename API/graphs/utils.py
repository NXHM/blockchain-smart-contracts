import re

def sanitize_filename(name):
    """
    Reemplaza caracteres inválidos en un string para que pueda ser usado
    como un nombre de archivo válido.
    """
    # Reemplazar la barra inclinada con un guion para legibilidad
    name = name.replace('/', '_')
    # Eliminar caracteres no válidos restantes
    return re.sub(r'[\\*?:"<>|]', "", name)

# server

Pequeño servidor web. Sirve los contenidos del directorio definido en la variable `SERVED_DIR` (por defecto, `'./web'`).

## Ejemplo de uso

Considerando los contenidos actuales de la carpeta `web/`, al servirla usando

```
python server.py 127.2.3.4 8765
```

al navegar a `http://127.2.3.4:8555/site`, se recibiría el contenido de `web/site/index.html`.

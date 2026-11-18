<p align="center">
  <img src="assets/logo.svg" width="160" alt="logo de kubejail">
</p>

<h1 align="center">kubejail</h1>

<p align="center">
  <b>Una shell que solo puede llegar a un clúster de Kubernetes.</b><br>
  Lo impone el aislamiento de red, no la configuración.
</p>

<p align="center">
  <a href="README.md">English</a>
</p>

---

Tu kubeconfig conoce todos los clústeres que gestionas. También los conoce
cualquier cosa que ejecute `kubectl` en tu nombre: un script, un comando
copiado, un agente de IA. Un contexto equivocado y el `delete` cae en
producción.

`kubejail` abre una shell desde la que `kubectl` (el binario original) solo
puede conectar directamente al API server de **un** clúster, elegido al iniciar
la sesión. Cambiar `KUBECONFIG`, pasar `--server` o tener credenciales válidas
de otro clúster no abre ninguna otra ruta.

```console
$ kubejail enter acme-staging -n payments
[acme-staging] $ kubectl get pods
[acme-staging] $ kubectl --server https://10.0.0.12:6443 get pods
Unable to connect to the server: dial tcp 10.0.0.12:6443: connect: network is unreachable
[acme-staging] $ exit
```

## Instalación

```bash
curl -fsSL https://raw.githubusercontent.com/joseEnrique/kubejail/main/install.sh | sh
```

El script detecta Linux o macOS (x86_64 o arm64), descarga el binario de la
última [versión publicada](https://github.com/joseEnrique/kubejail/releases),
comprueba su SHA-256 y lo instala en `/usr/local/bin` si se puede escribir, o
en `~/.local/bin`. `KUBEJAIL_VERSION` (por ejemplo `v0.1.0`) y
`KUBEJAIL_INSTALL_DIR` cambian esos valores. Los binarios de Linux son
estáticos.

O desde el código:

```bash
cargo install --git https://github.com/joseEnrique/kubejail
```

Requisitos:

- **Linux:** [Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`)
  con espacios de nombres de usuario disponibles, kernel ≥ 5.11 y `kubectl` en
  el `PATH`. `KUBEJAIL_BWRAP` permite indicar otro binario de `bwrap`.
- **macOS (experimental, ver más abajo):** `kubectl` en el `PATH`. Usa
  `/usr/bin/sandbox-exec`, que viene con el sistema.

## Uso

```
kubejail enter <contexto> [-n <namespace>] [--kubeconfig <ruta>] [-- <comando>...]
```

- `<contexto>`: un contexto de `$KUBECONFIG` / `~/.kube/config`, o del fichero
  indicado con `--kubeconfig`.
- `-n`: namespace por defecto de la sesión (si se omite, el del contexto o
  `default`). Los permisos siguen siendo los del RBAC del clúster.
- `-- <comando>`: ejecuta un comando en la jaula en vez de la shell interactiva
  y devuelve su código de salida.
- El prompt muestra solo el contexto, que es lo que se impone.
- Dentro está `k` como atajo de `kubectl`. Tus alias y funciones de shell no
  se trasladan a la jaula.
- Cada sesión es independiente: se pueden tener varias abiertas a la vez, cada
  una fijada a su clúster. Para ir a otro clúster se abre otra sesión.

La jaula no ve tu HOME, así que los manifiestos entran por la entrada estándar:

```bash
kubejail enter acme-staging -n payments -- kubectl apply -f - < manifiesto.yaml
```

## Con agentes de IA

Dale al agente `kubejail`, no `kubectl`. Puede seguir equivocándose, pero solo
dentro del clúster que elegiste. Por ejemplo, en su fichero de instrucciones
(`CLAUDE.md`, `AGENTS.md`…):

```markdown
Para cualquier operación contra un clúster Kubernetes usa `kubejail`, nunca
`kubectl` directamente:

    kubejail enter <contexto> -n <namespace> -- kubectl <args>

El contexto y el namespace los indica el usuario. Si no los ha dicho, pregunta.
Si `kubejail` falla, informa del error; no recurras a `kubectl` directo.
```

Conviene añadir en el agente una regla de permisos que deniegue `kubectl`
directo.

> [!IMPORTANT]
> kubejail limita **a qué clúster** llega una sesión, no **qué hace allí**.
> Una sesión fijada a producción con credenciales de administrador puede
> romper producción. Para limitar las acciones, usa RBAC.

## Cómo funciona

1. **Configuración.** Se resuelve el contexto con `kube::config` y se genera un
   kubeconfig temporal con ese único contexto. `server` apunta a
   `https://127.0.0.1:6443` (loopback de la jaula) y se conservan la CA, el
   nombre TLS del servidor original (`tls-server-name`) y el certificado de
   cliente. Los ficheros de certificados se leen con rutas relativas al
   kubeconfig que los declara. El kubeconfig original solo se lee.
2. **Jaula.** `bwrap --unshare-all` crea un espacio de red con solo loopback,
   un HOME temporal en tmpfs y un entorno vacío salvo `HOME`, `PATH`,
   `KUBECONFIG`, `PS1`, `TERM` y poco más. Del host solo se ven `/usr`, una
   lista corta de `/etc`, `kubectl`, el kubeconfig temporal y el socket Unix de
   la sesión, todo en solo lectura. No se heredan descriptores aparte de la
   terminal, y un filtro seccomp bloquea la inyección de teclas en la terminal
   (`TIOCSTI`).
3. **Reenvío.** Dentro de la jaula, un proceso escucha en `127.0.0.1:6443` y
   conecta cada conexión al socket Unix. En el host, otro proceso acepta en ese
   socket y conecta siempre al endpoint resuelto al arrancar; nunca interpreta
   lo que envía el cliente. Se reenvían bytes sin terminar TLS: `kubectl`
   verifica el certificado original y el API server ve el certificado del
   operador.
4. **Ciclo de vida.** Cada sesión tiene un directorio privado (`0700`) en
   `$XDG_RUNTIME_DIR` (o el directorio temporal). La shell solo se abre cuando
   el endpoint responde y ambos extremos del reenvío están escuchando; si algo
   falla se devuelve un error sin abrir shell. Al salir, o con SIGTERM/SIGHUP,
   se eliminan procesos, socket y configuración.

## Alcance y límites

- **Qué garantiza:** los procesos locales de la shell solo tienen una ruta de
  red directa: el API server elegido. **Qué no:** lo que ocurre a través de ese
  API server. `kubectl exec`, `port-forward`, `proxy` o `debug` actúan dentro
  del clúster y se rigen por su red y su RBAC.
- Linux (x86_64 y aarch64) y, de forma experimental, macOS. Endpoints HTTPS
  directos, con certificados de cliente (como `kind`) o con plugins de
  credenciales `exec` (EKS, GKE, AKS). Se rechazan con un error explícito
  `auth-provider`, tokens estáticos y autenticación básica, `proxy-url`,
  `insecure-skip-tls-verify`, la suplantación (`as`) y los plugins que exigen
  interacción o devuelven certificados en vez de token.
- Con un plugin `exec`, el plugin se ejecuta en el host (necesita red y tus
  credenciales de nube) al abrir la sesión y de nuevo antes de que caduque el
  token. La jaula solo recibe el token vigente, en un fichero de solo lectura;
  nunca ve el plugin ni las credenciales de nube. Si el plugin falla al
  arrancar no se abre la shell; si falla una renovación se avisa por la salida
  de error y se reintenta.
- Las variables de proxy del host (`HTTPS_PROXY`) no se usan: el endpoint debe
  ser alcanzable directamente.
- La dirección del endpoint se resuelve una vez al arrancar; si cambia la IP
  del API server hay que abrir otra sesión.
- La jaula ve `/usr` del host. Si hay credenciales guardadas ahí, serán
  legibles (aunque sin red para usarlas).
- Los complementos de `kubectl` instalados en el HOME del operador no están
  disponibles dentro.

## macOS (experimental)

macOS no tiene espacios de red, así que el mecanismo es distinto y más débil:
la shell comparte la red del host y un perfil del sandbox del sistema
(Seatbelt, mediante `sandbox-exec`) deniega toda operación de red salvo
conectar al puerto de loopback de la sesión, donde escucha el reenvío fijado al
endpoint. El mismo perfil deja el sistema en solo lectura, oculta `/Users`,
`/Volumes` y los temporales ajenos, y bloquea la comunicación con otros
procesos del sistema (servicios Mach), salvo una lista corta.

**Estado de la verificación:** `scripts/selftest.sh` (API server falso) pasa
en un Mac con Apple Silicon. La prueba con dos clústeres `kind` y el `kubectl`
real todavía no se ha ejecutado en macOS, así que el aislamiento entre
clústeres reales no está verificado ahí. La comprobación rápida solo necesita
el binario (sin Rust ni Docker):

```bash
scripts/selftest.sh ./kubejail              # API server falso
scripts/selftest.sh ./kubejail mi-contexto  # además, kubectl real
```

Diferencias con Linux a tener en cuenta:

- `sandbox-exec` está marcado como obsoleto por Apple, aunque sigue presente.
- El perfil parte de "permitir todo" y deniega red, ficheros y servicios Mach;
  en Linux la jaula parte de vacío. Es más fácil que quede un hueco.
- No hay espacio de procesos: un proceso lanzado en segundo plano puede
  sobrevivir a la sesión (sigue en el sandbox y sin reenvío, es decir, sin red).
- No se filtra la inyección de teclas en la terminal (`TIOCSTI`).
- Los procesos de la jaula pueden enviar señales a otros procesos del usuario.
- `kubectl` se copia al directorio de la sesión, porque puede estar bajo
  `/Users`.

## Pruebas

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                                         # unitarias + jaula (necesita bwrap)
cargo test --test kind -- --ignored --nocapture    # dos clústeres kind (docker, kind, kubectl)
```

- `tests/jail.rs` usa un servidor TCP local como API server falso. Comprueba
  que la jaula solo alcanza el endpoint elegido, el entorno mínimo, los fallos
  de arranque (Bubblewrap, endpoint inalcanzable, configuración no admitida) y
  la limpieza. Si `bwrap` no funciona, estas pruebas se saltan con un aviso.
- `tests/macos.rs` es el equivalente de `tests/jail.rs` para macOS.
- `tests/kind.rs` crea dos clústeres `kind` con el mismo namespace y
  Deployment. Desde la jaula de A escala A con el `kubectl` original; intenta
  llegar a B con el kubeconfig de B y con `--server` más sus credenciales (los
  mismos comandos funcionan en el host como control) y exige un error de
  conectividad; después abre la jaula de B en paralelo.

## Licencia

[MIT](LICENSE)

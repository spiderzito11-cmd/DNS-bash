#!/bin/bash

#  USO EDUCATIVO: usar solo contra dominios/equipos propios o con
#  autorizacion por escrito. Dominios de practica legales:
#    - zonetransfer.me   (DNS, transferencia de zona permitida)
#    - scanme.nmap.org   (escaneos Nmap permitidos de forma limitada)
# =====================================================================

OUTDIR="resultados"     # Aqui se guardan informes y escaneos (no se sube a GitHub)
mkdir -p "$OUTDIR"

# Lista de subdominios "tipicos" que suelen alojar datos sensibles
SENSIBLES=(www mail smtp pop imap webmail owa autodiscover ftp sftp ssh vpn remote
           admin panel cpanel intranet portal dev test staging db sql mysql
           git gitlab jenkins backup ns1 ns2)

# ---------------------------------------------------------------------
# 0. Comprobacion de dependencias
# ---------------------------------------------------------------------
for herramienta in dig nmap; do
    if ! command -v "$herramienta" >/dev/null 2>&1; then
        echo "Falta '$herramienta'. Instalalo con: sudo apt install bind9-dnsutils nmap"
        exit 1
    fi
done

# ---------------------------------------------------------------------
# FUNCIONES DE APOYO
# ---------------------------------------------------------------------
validar_dominio() {
    local re='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    [[ "$1" =~ $re ]]
}

validar_objetivo() {      # IP o nombre de host (debe contener un punto)
    local re='^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'
    [[ "$1" =~ $re && "$1" == *.* ]]
}

resolver_a() {            # devuelve solo las IPv4 de un nombre
    dig +short +time=2 +tries=1 A "$1" 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

registrar() {             # $1=tipo de maquina  $2=host  $3=ip
    printf "%-40s %-36s %s\n" "$1" "$2" "$3" >> "$INFORME"
    echo "$3|$2|$1" >> "$FICHERO_IPS"
}

pausa() {
    read -p "Pulsa Enter para continuar..." _
}

# ---------------------------------------------------------------------
# FASE 1 - REGISTRO DE MAQUINAS CON DATOS SENSIBLES (DNS)
# ---------------------------------------------------------------------
recon_sensible() {
    local d="$1" ns mx ip sub tipo salida txt nslist
    INFORME="$OUTDIR/${d}_informe.txt"
    FICHERO_IPS="$OUTDIR/${d}_ips.txt"
    : > "$INFORME"
    : > "$FICHERO_IPS"

    echo -e "INFORME DNS de $d  -  $(date '+%Y-%m-%d %H:%M')\n" >> "$INFORME"
    printf "%-40s %-36s %s\n" "TIPO DE MAQUINA" "HOST" "IP" >> "$INFORME"
    printf "%0.s-" {1..90} >> "$INFORME"; echo >> "$INFORME"

    # 1) Servidor principal (registro A)
    for ip in $(resolver_a "$d"); do
        registrar "Servidor principal (A)" "$d" "$ip"
    done

    # 2) Servidores DNS (registro NS)
    nslist=$(dig +short NS "$d" 2>/dev/null)
    for ns in $nslist; do
        ns="${ns%.}"
        for ip in $(resolver_a "$ns"); do
            registrar "Servidor DNS (NS)" "$ns" "$ip"
        done
    done

    # 3) Servidores de correo (registro MX)
    for mx in $(dig +short MX "$d" 2>/dev/null | awk '{print $2}'); do
        mx="${mx%.}"
        for ip in $(resolver_a "$mx"); do
            registrar "Servidor de correo (MX) [SENSIBLE]" "$mx" "$ip"
        done
    done

    # 4) Registro TXT / SPF: revela servidores autorizados a enviar correo
    txt=$(dig +short TXT "$d" 2>/dev/null)
    #    (los rangos CIDR distintos de /32 se omiten para no escanear redes enteras)
    for ip in $(echo "$txt" | grep -oE 'ip4:[0-9.]+(/[0-9]+)?' | sed 's/ip4://' | grep -vE '/([0-9]|[12][0-9]|3[01])$' | sed 's#/32##'); do
        registrar "Servidor autorizado en SPF" "(registro TXT)" "$ip"
    done

    # 5) Subdominios habituales con datos sensibles
    for sub in "${SENSIBLES[@]}"; do
        for ip in $(resolver_a "${sub}.${d}"); do
            case "$sub" in
                ftp|sftp)                     tipo="Transferencia de ficheros [SENSIBLE]" ;;
                db|sql|mysql)                 tipo="Base de datos [SENSIBLE]" ;;
                admin|panel|cpanel)           tipo="Panel de administracion [SENSIBLE]" ;;
                vpn|remote|ssh)               tipo="Acceso remoto [SENSIBLE]" ;;
                git|gitlab|jenkins|backup)    tipo="Codigo / copias de seguridad [SENSIBLE]" ;;
                mail|smtp|pop|imap|webmail|owa|autodiscover) tipo="Correo [SENSIBLE]" ;;
                dev|test|staging|intranet)    tipo="Entorno interno / pruebas" ;;
                ns1|ns2)                      tipo="Servidor DNS" ;;
                *)                            tipo="Web / portal" ;;
            esac
            registrar "$tipo" "${sub}.${d}" "$ip"
        done
    done

    # 6) Transferencia de zona (AXFR) contra cada servidor NS
    {
        echo -e "\n--- Registros TXT ---"
        echo "${txt:-(sin registros TXT)}"
        echo -e "\n--- Transferencia de zona (AXFR) ---"
    } >> "$INFORME"
    for ns in $nslist; do
        ns="${ns%.}"
        salida=$(dig axfr "$d" @"$ns" +time=5 +tries=1 2>&1)
        if echo "$salida" | grep -q "XFR size"; then
            echo "[!] $ns PERMITE la transferencia de zona (VULNERABLE)" >> "$INFORME"
            echo "$salida" > "$OUTDIR/${d}_axfr_${ns}.txt"
        else
            echo "[OK] $ns deniega la transferencia de zona" >> "$INFORME"
        fi
    done

    # Unificar el listado: una linea por IP (junta hosts y tipos de maquina)
    awk -F'|' '
        !($1 in h) { ord[++n]=$1; h[$1]=$2; t[$1]=$3; next }
        { if (index(h[$1], $2)==0) h[$1]=h[$1] ", " $2
          if (index(t[$1], $3)==0) t[$1]=t[$1] " + " $3 }
        END { for (i=1;i<=n;i++) print ord[i] "|" h[ord[i]] "|" t[ord[i]] }
    ' "$FICHERO_IPS" > "$FICHERO_IPS.tmp" && mv "$FICHERO_IPS.tmp" "$FICHERO_IPS"

    cat "$INFORME"
    echo -e "\n[+] Informe guardado en: $INFORME"
    echo "[+] Maquinas registradas (para Nmap) en: $FICHERO_IPS"
}

# ---------------------------------------------------------------------
# FASE 2 - NMAP + NSE
# ---------------------------------------------------------------------
elegir_objetivo() {       # deja el resultado en la variable OBJETIVO
    OBJETIVO=""
    local f="$OUTDIR/${dominio}_ips.txt" i=0 sel ip host tipo
    local -a lista=()

    if [[ -s "$f" ]]; then
        echo "Maquinas registradas para $dominio:"
        while IFS='|' read -r ip host tipo; do
            lista+=("$ip")
            i=$((i+1))
            printf "%3d) %-16s %-32s %s\n" "$i" "$ip" "$host" "$tipo"
        done < "$f"
    else
        echo "No hay registro para $dominio (ejecuta antes la opcion 5 del menu principal)."
    fi

    read -p "Numero de la lista, o escribe una IP/host (0 = volver): " sel
    if [[ "$sel" == "0" || -z "$sel" ]]; then
        return 1
    elif [[ "$sel" =~ ^[0-9]+$ && "$sel" -ge 1 && "$sel" -le "${#lista[@]}" ]]; then
        OBJETIVO="${lista[$((sel-1))]}"
    elif validar_objetivo "$sel"; then
        OBJETIVO="$sel"
    else
        echo "Objetivo no valido."
        return 1
    fi
    return 0
}

nmap_estado() {           # Estado de la maquina (host discovery)
    echo -e "\n[*] Comprobando el estado de $1 ...\n"
    nmap -sn -PE -PS22,80,443 "$1" | tee -a "$OUTDIR/nmap_estado_$1.txt"
    echo -e "\nSi aparece 'Host seems down' pero crees que esta activo, el ICMP puede estar filtrado:"
    echo "usa la opcion 2 (lleva -Pn y no depende del ping)."
}

nmap_servicios() {        # Puertos abiertos + servicio + version
    echo -e "\n[*] Buscando puertos y servicios en $1 ...\n"
    nmap -Pn -sV --open -T4 --top-ports 1000 "$1" -oN "$OUTDIR/nmap_servicios_$1.txt"
}

# Devuelve la lista de scripts NSE adecuada segun el SERVICIO y el PUERTO
scripts_para() {          # $1=puerto  $2=servicio
    local puerto="$1" servicio="$2" s

    # Si Nmap no identifica el servicio, nos apoyamos en el puerto
    if [[ -z "$servicio" || "$servicio" == "unknown" || "$servicio" == "tcpwrapped" ]]; then
        case "$puerto" in
            21)            servicio="ftp" ;;
            22)            servicio="ssh" ;;
            23)            servicio="telnet" ;;
            25|465|587)    servicio="smtp" ;;
            53)            servicio="domain" ;;
            80|8000|8080)  servicio="http" ;;
            443|8443)      servicio="ssl|http" ;;
            110|995)       servicio="pop3" ;;
            143|993)       servicio="imap" ;;
            111)           servicio="rpcbind" ;;
            139|445)       servicio="microsoft-ds" ;;
            389|636)       servicio="ldap" ;;
            1433)          servicio="ms-sql-s" ;;
            2049)          servicio="nfs" ;;
            3306)          servicio="mysql" ;;
            3389)          servicio="ms-wbt-server" ;;
            5432)          servicio="postgresql" ;;
            5900)          servicio="vnc" ;;
            6379)          servicio="redis" ;;
            27017)         servicio="mongodb" ;;
        esac
    fi

    case "$servicio" in
        *ftp*)                  echo "ftp-anon,ftp-syst,ftp-bounce" ;;
        *ssh*)                  echo "ssh-hostkey,ssh-auth-methods,ssh2-enum-algos" ;;
        *telnet*)               echo "telnet-encryption,telnet-ntlm-info" ;;
        *smtp*|*submission*)    echo "smtp-commands,smtp-open-relay,smtp-ntlm-info" ;;
        domain*)                echo "dns-nsid,dns-recursion,dns-zone-transfer" ;;
        *imap*)                 echo "imap-capabilities,imap-ntlm-info" ;;
        *pop3*)                 echo "pop3-capabilities,pop3-ntlm-info" ;;
        *http*)
            s="http-title,http-headers,http-methods,http-server-header,http-enum,http-robots.txt"
            if [[ "$servicio" == *ssl* || "$servicio" == *https* || "$puerto" == 443 || "$puerto" == 8443 ]]; then
                s+=",ssl-cert,ssl-enum-ciphers,ssl-heartbleed"
            fi
            echo "$s" ;;
        microsoft-ds|netbios-ssn|*smb*)
                                echo "smb-os-discovery,smb-security-mode,smb-protocols,smb2-security-mode,smb-vuln-ms17-010" ;;
        *mysql*)                echo "mysql-info,mysql-empty-password" ;;
        ms-sql*)                echo "ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info" ;;
        *postgres*)             echo "banner" ;;
        ms-wbt-server|*rdp*)    echo "rdp-ntlm-info,rdp-enum-encryption" ;;
        *vnc*)                  echo "vnc-info,vnc-title" ;;
        *redis*)                echo "redis-info" ;;
        *mongo*)                echo "mongodb-info,mongodb-databases" ;;
        rpcbind|sunrpc|nfs*)    echo "rpcinfo,nfs-showmount,nfs-ls" ;;
        *ldap*)                 echo "ldap-rootdse" ;;
        *snmp*)                 echo "snmp-info" ;;
        *ssl*|*tls*)            echo "ssl-cert,ssl-enum-ciphers" ;;
        *)                      echo "banner" ;;
    esac
}

nmap_nse_auto() {         # Detecta servicios y lanza el NSE correspondiente a cada uno
    local objetivo="$1"
    local gnmap="$OUTDIR/nmap_nse_${objetivo}.gnmap"
    local informe="$OUTDIR/nmap_nse_${objetivo}.txt"
    local puerto estado proto servicio version scripts lineas

    echo -e "\n[*] Fase 1: descubriendo puertos abiertos y servicios en $objetivo ..."
    nmap -Pn -sV --open -T4 --top-ports 1000 "$objetivo" -oG "$gnmap" >/dev/null

    lineas=$(grep "Ports:" "$gnmap" | sed -e 's/.*Ports: //' -e 's/\tIgnored State.*//' | sed 's/, /\n/g')
    if [[ -z "$lineas" ]]; then
        echo "[-] No se han encontrado puertos TCP abiertos (o el host no responde)."
        return
    fi

    : > "$informe"
    echo "[*] Fase 2: lanzando el NSE adecuado para cada servicio ..."
    while IFS='/' read -r puerto estado proto _ servicio _ version; do
        puerto="${puerto// /}"
        [[ "$estado" != "open" ]] && continue
        scripts=$(scripts_para "$puerto" "$servicio")
        echo -e "\n=====> Puerto $puerto/$proto | servicio: ${servicio:-desconocido} | $version"
        echo "       NSE: $scripts"
        nmap -Pn -sV -p "$puerto" --script "$scripts" \
             --script-args "dns-zone-transfer.domain=$dominio" "$objetivo" | tee -a "$informe"
    done <<< "$lineas"

    echo -e "\n[+] Resultados guardados en: $informe"
}

nmap_nse_manual() {       # El usuario elige scripts y puertos
    local objetivo="$1" scr pts
    read -p "Script(s) NSE separados por coma (ej: http-title,ssl-cert): " scr
    read -p "Puerto(s) (ej: 80,443): " pts
    if [[ ! "$scr" =~ ^[a-zA-Z0-9,._*-]+$ || ! "$pts" =~ ^[0-9,-]+$ ]]; then
        echo "Entrada no valida."
        return
    fi
    nmap -Pn -sV -p "$pts" --script "$scr" "$objetivo" | tee -a "$OUTDIR/nmap_manual_${objetivo}.txt"
}

menu_nmap() {
    local op
    while true;
    do
        echo "------------- MENU NMAP -------------"
        echo "1. Estado de la maquina"
        echo "2. Puertos y servicios"
        echo "3. NSE automatico segun servicio y puerto"
        echo "4. NSE manual"
        echo "--------------"
        echo "0. Volver al menu principal"
        read -p "¿Que opcion eliges? " op

        case $op in
            0)
                return
                ;;
            1|2|3|4)
                elegir_objetivo || continue
                case $op in
                    1) nmap_estado "$OBJETIVO" ;;
                    2) nmap_servicios "$OBJETIVO" ;;
                    3) nmap_nse_auto "$OBJETIVO" ;;
                    4) nmap_nse_manual "$OBJETIVO" ;;
                esac
                pausa
                ;;
            *)
                echo "Error en tu seleccion, por favor vuelve a intentarlo"
                ;;
        esac
    done
}

# =====================================================================
#  PROGRAMA PRINCIPAL
# =====================================================================
echo "=================== AVISO ==================="
echo "Esta herramienta es solo para fines educativos."
echo "Usala unicamente sobre dominios y equipos propios o con autorizacion."
read -p "¿Confirmas que tienes autorizacion? (s/N): " confirma
if [[ ! "$confirma" =~ ^[sS]$ ]]; then
    echo "Saliendo de la herramienta...."
    exit 1
fi

dominio=""

#Tendras un while con el que siempre tendremos la
#opcion de trabajar con los elementos de menu
while true;
do
#Mensajes al usuario
echo "----------- o -----------"
echo -e "Bienvenid@ a la herramienta de consulta de dominio.\n Esto es un ejemplo de lo que debes escribir ---> google.es"
read -p "Escribe el dominio (Enter = mantener '${dominio:-ninguno}') :" entrada
[[ -n "$entrada" ]] && dominio="$entrada"

if ! validar_dominio "$dominio"; then
    echo "Dominio no valido. Ejemplo: google.es"
    dominio=""
    continue
fi

echo "Opciones disponible en la herramienta"
echo "1. Consulta de IP"
echo "2. Consulta de correo electronico"
echo "3. Consulta de Nombre de servidor"
echo "4. Consulta de registros TXT (SPF / DMARC)"
echo "5. Registro de maquinas con datos sensibles (+ prueba AXFR)"
echo "6. Nmap + NSE sobre las maquinas registradas"
echo "7. Actualizar la herramienta desde GitHub"
echo "--------------"
echo "0. Salir de la herramienta"

read -p "¿Que opcion eliges? " opcion

case $opcion in
    1)
    echo -e "Obteniendo resultado....\n"
    echo "la IP es :"
    dig +short $dominio A
    dig +short $dominio AAAA
    ;;
    2)
    echo -e "Obteniendo resultado....\n"
    echo "Los servidores de correo (MX) son :"
    dig +short $dominio MX
    ;;
    3)
    echo -e "Obteniendo resultado....\n"
    echo "Los servidores de nombre (NS) son :"
    dig +short $dominio NS
    ;;
    4)
    echo -e "Obteniendo resultado....\n"
    echo "Registros TXT :"
    dig +short $dominio TXT
    echo -e "\nDMARC :"
    dig +short _dmarc.$dominio TXT
    ;;
    5)
    echo -e "Obteniendo resultado....\n"
    recon_sensible "$dominio"
    ;;
    6)
    menu_nmap
    ;;
    7)
    echo "Buscando actualizaciones en GitHub...."
    git -C "$(dirname "$(readlink -f "$0")")" pull
    ;;
    0)
    echo "Saliendo de la herramienta...."
    exit 0
    ;;
    *)
    echo "Error en tu seleccion, por favor vuelve a intentarlo"
    ;;
esac
done

#!/usr/bin/env bash
#
# HashSage - terminal hash & encoding identifier, with John/Hashcat syntax
#            generation and optional cracking. Built for Kali / Parrot OS.
#
# Usage:
#   ./hashsage.sh <hash_or_string>                 identify only
#   ./hashsage.sh <hash_or_string> --syntax         identify + show commands
#   ./hashsage.sh <hash_or_string> --crack          identify + attempt crack
#   ./hashsage.sh --decode <string>                 try to decode an encoding
#   ./hashsage.sh --learn                           teach it a new hash format
#   ./hashsage.sh --list-wordlists                  show detected wordlists
#   ./hashsage.sh --help
#
# What this does NOT do, on purpose:
#   - It does not scrape the internet for hash signatures or silently
#     "update its database" from the web. A --learn mode lets YOU teach it
#     a format you've identified, saved locally to ~/.hashsage_db.tsv.
#   - It does not fabricate or invent a "best of all CTF/HTB/THM" wordlist.
#     For wordlists it only ever touches two real, named sources: rockyou.txt
#     (detected locally, since it ships with Kali) and two specific files
#     from the public SecLists GitHub repo (danielmiessler/SecLists), which
#     it will download on demand - with your confirmation first - if they
#     aren't already installed locally. Nothing else is fetched from anywhere.
#
# Only run this against hashes/data you are authorized to analyze.

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
LEARNED_DB="${HOME}/.hashsage_db.tsv"   # name<TAB>regex<TAB>hashcat_mode<TAB>john_format<TAB>notes<TAB>confidence

# Common wordlist locations to probe, in priority order.
ROCKYOU_CANDIDATES=(
    "/usr/share/wordlists/rockyou.txt"
    "/usr/share/wordlists/rockyou.txt.gz"
    "${HOME}/rockyou.txt"
)
SECLISTS_CANDIDATES=(
    "/usr/share/seclists"
    "/usr/share/wordlists/seclists"
    "${HOME}/SecLists"
    "${HOME}/seclists"
)

# ---------------------------------------------------------------------------
# Colors (fall back cleanly if not a terminal)
#
# NOTE: these MUST use $'...' (ANSI-C quoting), not plain '...' quoting.
# A plain single-quoted '\033[1m' stores the literal 6 characters
# backslash-0-3-3-[-1-m, not the real ESC control byte - that only "worked"
# before in printf("%b", ...) because %b reinterprets backslash escapes at
# print time. Dropped straight into a `cat <<EOF` heredoc (like usage()
# does), that literal text prints as-is, which is exactly the garbled
# "\033[1mHashSage\033[0m" you saw. $'...' fixes it at the source so every
# printer (printf, cat, echo) gets the real byte.
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'; C_RED=$'\033[0;31m'; C_CYAN=$'\033[0;36m'
    C_BLUE=$'\033[1;34m'; C_NEON=$'\033[1;38;5;46m'
else
    C_RESET=''; C_BOLD=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_CYAN=''
    C_BLUE=''; C_NEON=''
fi

info()  { printf "%b[*]%b %s\n" "$C_CYAN" "$C_RESET" "$1"; }
ok()    { printf "%b[+]%b %s\n" "$C_GREEN" "$C_RESET" "$1"; }
warn()  { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_RESET" "$1"; }
err()   { printf "%b[!]%b %s\n" "$C_RED" "$C_RESET" "$1" >&2; }

# ---------------------------------------------------------------------------
# Startup banner
# Block letters are a verified 5x7 dot-matrix font (not freehand ASCII art),
# built and checked letter-by-letter before being hardcoded here.
# ---------------------------------------------------------------------------
TOOL_VERSION="0.1"
TOOL_AUTHOR="KracKØ9"
TOOL_GITHUB="https://github.com/Rapmonster2013"

print_banner() {
    [[ -t 1 ]] || return 0   # skip decorative banner on piped/non-tty output
    printf '%b' "$C_BLUE"
    cat <<'BANNER'
#   #   ###    ####  #   #   ####   ###    ###   #####
#   #  #   #  #      #   #  #      #   #  #   #  #
#   #  #   #  #      #   #  #      #   #  #      #
#####  #####   ###   #####   ###   #####  # ###  ####
#   #  #   #      #  #   #      #  #   #  #   #  #
#   #  #   #      #  #   #      #  #   #  #   #  #
#   #  #   #  ####   #   #  ####   #   #   ####  #####
BANNER
    printf '%b\n' "$C_RESET"
    printf '%bHashSage v%s%b\n' "$C_NEON" "$TOOL_VERSION" "$C_RESET"
    printf '%bAuthor: %s%b\n' "$C_NEON" "$TOOL_AUTHOR" "$C_RESET"
    printf '%bGitHub: %s%b\n' "$C_NEON" "$TOOL_GITHUB" "$C_RESET"
    echo
}

# ---------------------------------------------------------------------------
# Arrow-key menu.
#   arrow_menu "Prompt text" "Option 1" "Option 2" ...
#   idx="$ARROW_MENU_RESULT"     # 0-based index of the chosen option
#
# IMPORTANT: this does NOT print its result to stdout for $(...) capture.
# Command substitution runs in a subshell with stdout redirected to a pipe,
# which makes `[[ -t 1 ]]` false even on a real interactive terminal - that
# would silently disable the arrow-key UI for every caller that did
# `idx="$(arrow_menu ...)"`. Instead, all interactive I/O goes straight to
# /dev/tty (bypassing stdin/stdout entirely) and the answer comes back via
# the ARROW_MENU_RESULT global. Falls back to a plain numbered prompt when
# there's no controlling terminal at all (cron, CI, fully piped/scripted
# runs), so the tool never hangs waiting for keys that can't arrive.
# ---------------------------------------------------------------------------
arrow_menu() {
    local prompt="$1"; shift
    local -a options=("$@")
    local n=${#options[@]}
    local selected=0
    ARROW_MENU_RESULT=0

    if ! exec 9<>/dev/tty 2>/dev/null; then
        # No controlling terminal - plain numbered prompt on whatever stdin we have.
        {
            echo "$prompt"
            local i
            for i in "${!options[@]}"; do
                echo "  $((i+1))) ${options[$i]}"
            done
        } >&2
        local choice
        read -rp "Choose [1-$n] (default 1): " choice
        [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= n )) || choice=1
        ARROW_MENU_RESULT=$((choice - 1))
        return 0
    fi

    local draw_lines=$((n + 2))   # prompt + options + blank hint line
    local key seq

    draw_menu() {
        echo "$prompt" >&9
        local i
        for i in "${!options[@]}"; do
            if [[ $i -eq $selected ]]; then
                printf "  \033[7m> %s\033[0m\n" "${options[$i]}" >&9
            else
                printf "    %s\n" "${options[$i]}" >&9
            fi
        done
        printf "  (Use arrow keys, Enter to select)\n" >&9
    }

    tput civis >&9 2>/dev/null
    draw_menu
    while true; do
        IFS= read -rsn1 key <&9
        if [[ "$key" == $'\x1b' ]]; then
            IFS= read -rsn2 -t 0.1 seq <&9
            case "$seq" in
                '[A') ((selected--)); (( selected < 0 )) && selected=$((n - 1)) ;;
                '[B') ((selected++)); (( selected >= n )) && selected=0 ;;
            esac
        elif [[ -z "$key" ]]; then
            break  # Enter pressed
        elif [[ "$key" == "k" ]]; then
            ((selected--)); (( selected < 0 )) && selected=$((n - 1))
        elif [[ "$key" == "j" ]]; then
            ((selected++)); (( selected >= n )) && selected=0
        fi
        tput cuu "$draw_lines" >&9 2>/dev/null
        draw_menu
    done
    tput cnorm >&9 2>/dev/null
    exec 9<&-
    ARROW_MENU_RESULT=$selected
}

# ---------------------------------------------------------------------------
# Signature database - parallel arrays (NOT delimited strings).
# Several regexes use "|" for alternation, which would collide with a "|"
# field separator, so each field lives in its own array indexed by position.
# Ordered most-specific-first.
#
# CONFIDENCE is a rough "how sure can we be from shape alone" score, not a
# measured statistic:
#   100 = format has a unique, self-describing prefix (bcrypt's $2a$, the
#         $1$/$5$/$6$ crypt markers, krb5tgs$, etc.) - nothing else looks
#         like this.
#    90 = fixed-length raw hex that, among the formats THIS tool knows
#         about, only matches one algorithm - but plenty of real-world
#         hash/MAC/checksum algorithms share these exact output lengths
#         (e.g. 64 hex chars could be SHA-256, but also Keccak-256,
#         BLAKE2s, RIPEMD-256...), so it's a good guess, not a certainty.
#    55 = short raw hex that's also just a plausible generic/truncated value.
#    50 = genuinely ambiguous between two formats of identical shape in
#         this very database (classic case: MD5 vs NTLM, both 32 hex
#         chars) - context (where you got it) is what actually decides.
# ---------------------------------------------------------------------------
HASH_NAMES=()
HASH_REGEXES=()
HASH_MODES=()
HASH_FORMATS=()
HASH_NOTES=()
HASH_CONFIDENCE=()

add_hash_sig() {
    HASH_NAMES+=("$1"); HASH_REGEXES+=("$2"); HASH_MODES+=("$3")
    HASH_FORMATS+=("$4"); HASH_NOTES+=("$5"); HASH_CONFIDENCE+=("$6")
}

add_hash_sig 'bcrypt' \
    '^\$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' \
    '3200' 'bcrypt' 'Adaptive & salted, slow by design.' 100

add_hash_sig 'Argon2' \
    '^\$argon2(id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$' \
    'varies' 'argon2' "Check 'hashcat --help' for exact mode on your build." 100

add_hash_sig 'sha512crypt ($6$, Unix)' \
    '^\$6\$' '1800' 'sha512crypt' 'Modern Unix /etc/shadow default.' 100

add_hash_sig 'sha256crypt ($5$, Unix)' \
    '^\$5\$' '7400' 'sha256crypt' 'Unix /etc/shadow style.' 100

add_hash_sig 'md5crypt ($1$, Unix)' \
    '^\$1\$' '500' 'md5crypt' 'Old Unix crypt format.' 100

add_hash_sig 'phpass / WordPress ($P$ or $H$)' \
    '^\$[PH]\$[./A-Za-z0-9]{31}$' '400' 'phpass' 'WordPress / phpBB3 style.' 100

add_hash_sig 'bcrypt-sha256 (Django)' \
    '^bcrypt_sha256\$' 'varies' 'dynamic' 'Django bcrypt+sha256 wrapper.' 100

add_hash_sig 'Kerberos TGS-REP (Kerberoasting)' \
    '^\$krb5tgs\$23\$' '13100' 'krb5tgs' 'Impacket GetUserSPNs.py -request output.' 100

add_hash_sig 'Kerberos AS-REP (ASREPRoast)' \
    '^\$krb5asrep\$23\$' '18200' 'krb5asrep' 'Impacket GetNPUsers.py output.' 100

add_hash_sig 'NetNTLMv2' \
    '^[^:]+::[^:]+:[A-Fa-f0-9]{16}:[A-Fa-f0-9]+:[A-Fa-f0-9]+$' \
    '5600' 'netntlmv2' 'Captured via Responder/ntlmrelayx.' 100

add_hash_sig 'WPA/WPA2 (hashcat 22000)' \
    '^WPA\*' '22000' 'n/a (hashcat only)' 'hcxpcapngtool .22000 output.' 100

add_hash_sig 'MySQL 4.1+ (*HASH)' \
    '^\*[A-Fa-f0-9]{40}$' '300' 'mysql-sha1' '—' 100

add_hash_sig 'MySQL old (pre-4.1)' \
    '^[A-Fa-f0-9]{16}$' '200' 'mysql' 'Could also be a truncated/short hex value - verify source.' 55

add_hash_sig 'SHA-512 (raw)' '^[A-Fa-f0-9]{128}$' '1700' 'raw-sha512' '—' 90
add_hash_sig 'SHA-384 (raw)' '^[A-Fa-f0-9]{96}$'  '10800' 'raw-sha384' '—' 90
add_hash_sig 'SHA-256 (raw)' '^[A-Fa-f0-9]{64}$'  '1400' 'raw-sha256' '—' 90
add_hash_sig 'SHA-224 (raw)' '^[A-Fa-f0-9]{56}$'  '1300' 'raw-sha224' '—' 90
add_hash_sig 'SHA-1 (raw)'   '^[A-Fa-f0-9]{40}$'  '100'  'raw-sha1'   '—' 90

add_hash_sig 'NTLM' '^[A-Fa-f0-9]{32}$' '1000' 'NT' \
    'AMBIGUOUS with raw MD5 (identical shape). Source context decides: Windows SAM/AD dump = NTLM.' 50

add_hash_sig 'MD5 (raw)' '^[A-Fa-f0-9]{32}$' '0' 'raw-md5' \
    'AMBIGUOUS with NTLM (identical shape).' 50

ENC_NAMES=()
ENC_REGEXES=()
ENC_HOWTOS=()

add_enc_sig() {
    ENC_NAMES+=("$1"); ENC_REGEXES+=("$2"); ENC_HOWTOS+=("$3")
}

add_enc_sig 'Base64' \
    '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$' \
    'base64_decode'

add_enc_sig 'Hexadecimal' \
    '^(0x)?[A-Fa-f0-9]+$' \
    'hex_decode'

add_enc_sig 'URL-encoding' \
    '%[0-9A-Fa-f]{2}' \
    'url_decode'

add_enc_sig 'Binary (0/1 string)' \
    '^[01]{8}([[:space:]]?[01]{8})*$' \
    'binary_decode'

add_enc_sig 'HTML entity encoding' \
    '&#?[A-Za-z0-9]+;' \
    'html_decode'

# How-to text is generated from these keys (see print_encoding_matches)
# so no shell-quoting gymnastics are needed above.
enc_howto_text() {
    local key="$1" value="$2"
    local qvalue
    qvalue="$(printf '%q' "$value")"   # shell-quote so the value survives as ONE argv token
    case "$key" in
        base64_decode)  printf "Decode: echo '%s' | base64 -d" "$value" ;;
        hex_decode)     printf "Decode: echo '%s' | xxd -r -p    (strip any 0x prefix first)" "$value" ;;
        url_decode)     printf 'Decode: python3 -c "import urllib.parse as u,sys;print(u.unquote(sys.argv[1]))" %s' "$qvalue" ;;
        binary_decode)  printf 'Decode: python3 -c "import sys;print(bytes(int(b,2) for b in sys.argv[1].split()).decode())" %s' "$qvalue" ;;
        html_decode)    printf 'Decode: python3 -c "import html,sys;print(html.unescape(sys.argv[1]))" %s' "$qvalue" ;;
        *)              printf "Decode manually - no canned command for this one." ;;
    esac
}

# ---------------------------------------------------------------------------
# Hash / encoding identification
# Both functions fill global arrays MATCH_IDX (indices into the source
# arrays) and, for learned hashes, MATCH_LEARNED (parallel 6-tuples), since
# bash can't return structured data cleanly from a function.
# ---------------------------------------------------------------------------
MATCH_HASH_IDX=()          # indices into HASH_NAMES/REGEXES/MODES/FORMATS/NOTES/CONFIDENCE
MATCH_HASH_LEARNED=()      # each element: "name\tmode\tformat\tnote\tconfidence" for a learned match
MATCH_ENC_IDX=()           # indices into ENC_NAMES/REGEXES/HOWTOS

identify_hash() {
    local input="$1"
    MATCH_HASH_IDX=()
    MATCH_HASH_LEARNED=()
    local i

    for i in "${!HASH_NAMES[@]}"; do
        if printf '%s' "$input" | grep -Pq "${HASH_REGEXES[$i]}" 2>/dev/null; then
            MATCH_HASH_IDX+=("$i")
        fi
    done

    if [[ -f "$LEARNED_DB" ]]; then
        local name regex mode fmt note conf
        # conf is an OPTIONAL 6th TSV field, so a DB saved before this field
        # existed just reads as empty here - default that to 100% ("you told
        # it this format explicitly, so trust it fully" unless you set your
        # own confidence when learning it).
        while IFS=$'\t' read -r name regex mode fmt note conf; do
            [[ -z "$name" ]] && continue
            conf="${conf:-100}"
            if printf '%s' "$input" | grep -Pq "$regex" 2>/dev/null; then
                MATCH_HASH_LEARNED+=("$(printf '%s\t%s\t%s\t%s [learned]\t%s' "$name" "$mode" "$fmt" "$note" "$conf")")
            fi
        done < "$LEARNED_DB"
    fi
}

identify_encoding() {
    local input="$1"
    MATCH_ENC_IDX=()
    local i
    for i in "${!ENC_NAMES[@]}"; do
        if printf '%s' "$input" | grep -Pq "${ENC_REGEXES[$i]}" 2>/dev/null; then
            MATCH_ENC_IDX+=("$i")
        fi
    done
}

# ---------------------------------------------------------------------------
# Wordlist detection, download & selection
# ---------------------------------------------------------------------------
find_rockyou() {
    local c
    for c in "${ROCKYOU_CANDIDATES[@]}"; do
        [[ -f "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

find_seclists_dir() {
    local c
    for c in "${SECLISTS_CANDIDATES[@]}"; do
        [[ -d "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

# Where downloaded wordlists are cached so a second run reuses them instead
# of re-downloading. These are the real files from the real public SecLists
# GitHub repo (danielmiessler/SecLists) - same two lists already offered
# above when SecLists is installed locally, just fetched on demand when it
# isn't. Verified these exact paths exist in the repo before hardcoding them.
WORDLIST_CACHE_DIR="${HOME}/.hashsage_wordlists"
SECLISTS_TOP1M_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
SECLISTS_DARKWEB_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt"

# download_wordlist URL DEST_PATH LABEL
# Downloads to a .part file and moves it into place only on success, so a
# cancelled/failed download never leaves a half-written file that looks valid.
download_wordlist() {
    local url="$1" dest="$2" label="$3"

    if [[ -f "$dest" && -s "$dest" ]]; then
        echo "$dest"
        return 0
    fi

    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        err "Neither curl nor wget is installed - can't download $label."
        echo "    Install one: sudo apt install curl" >&2
        return 1
    fi

    mkdir -p "$WORDLIST_CACHE_DIR" 2>/dev/null

    {
        echo
        info "About to download: $label"
        echo "    From: $url"
        echo "    To:   $dest"
    } >&2
    read -rp "Proceed with download? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
        err "Download cancelled."
        return 1
    fi

    local tmp="${dest}.part"
    info "Downloading $label ..." >&2
    if command -v curl >/dev/null 2>&1; then
        if ! curl -fL --progress-bar -o "$tmp" "$url"; then
            err "Download failed (curl). Check your network, or get it manually:"
            echo "    curl -fL -o '$dest' '$url'" >&2
            rm -f "$tmp"
            return 1
        fi
    else
        if ! wget -q --show-progress -O "$tmp" "$url"; then
            err "Download failed (wget). Check your network, or get it manually:"
            echo "    wget -O '$dest' '$url'" >&2
            rm -f "$tmp"
            return 1
        fi
    fi

    if [[ ! -s "$tmp" ]]; then
        err "Downloaded file is empty - something went wrong. Not keeping it."
        rm -f "$tmp"
        return 1
    fi

    mv "$tmp" "$dest"
    ok "Downloaded $label -> $dest ($(wc -l < "$dest" 2>/dev/null || echo '?') lines)" >&2
    echo "$dest"
}

list_wordlists() {
    info "Scanning known wordlist locations..."
    local found_any=0

    if ry="$(find_rockyou)"; then
        if [[ "$ry" == *.gz ]]; then
            warn "Found compressed rockyou: $ry  (run: gunzip -k '$ry')"
        else
            ok "rockyou.txt: $ry  ($(wc -l < "$ry" 2>/dev/null || echo '?') lines)"
        fi
        found_any=1
    fi

    if sl="$(find_seclists_dir)"; then
        ok "SecLists found at: $sl"
        info "  Popular lists inside it for password work:"
        echo "    - $sl/Passwords/Leaked-Databases/rockyou.txt"
        echo "    - $sl/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
        echo "    - $sl/Passwords/darkweb2017-top10000.txt"
        found_any=1
    else
        info "SecLists not found locally, but HashSage can download the two lists"
        info "below on demand (via --crack's wordlist picker, or --download-wordlists)."
        found_any=1
    fi

    if [[ -d "$WORDLIST_CACHE_DIR" ]]; then
        local f
        for f in "$WORDLIST_CACHE_DIR"/*; do
            [[ -f "$f" ]] || continue
            ok "Cached download: $f  ($(wc -l < "$f" 2>/dev/null || echo '?') lines)"
        done
    fi

    if [[ "$found_any" -eq 0 ]]; then
        warn "No wordlists detected on this machine."
        echo "  Get rockyou.txt (ships with Kali, gzipped):"
        echo "    sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz"
        echo "  Get SecLists (the real, actively maintained community collection):"
        echo "    sudo apt install seclists    # Kali/Parrot package, installs to /usr/share/seclists"
        echo "    # or: git clone https://github.com/danielmiessler/SecLists.git ~/SecLists"
    fi
}

# Interactive wordlist picker (arrow keys), used by --crack when no
# --wordlist was given explicitly. Echoes the chosen path to stdout.
#
# The two SecLists entries are ALWAYS offered, even when SecLists isn't
# installed locally: if missing, picking one downloads it (or reuses an
# already-cached download) instead of just failing. rockyou.txt is NOT
# auto-downloaded here - it ships with Kali already and isn't reliably
# hosted as a small standalone raw file, so if it's missing we just point
# you at `sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz`.
pick_wordlist() {
    local ry sl
    ry="$(find_rockyou || true)"
    sl="$(find_seclists_dir || true)"

    local -a labels=()
    local -a paths=()
    local -a kinds=()   # "path" | "download"

    if [[ -n "$ry" && "$ry" != *.gz ]]; then
        labels+=("rockyou.txt  ($ry)  [recommended: broadest real-world coverage]")
        paths+=("$ry"); kinds+=("path")
    fi

    if [[ -n "$sl" ]]; then
        labels+=("SecLists top-1M  ($sl/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt)")
        paths+=("$sl/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"); kinds+=("path")
        labels+=("SecLists darkweb-top10k  ($sl/Passwords/darkweb2017-top10000.txt)  [fast first pass]")
        paths+=("$sl/Passwords/darkweb2017-top10000.txt"); kinds+=("path")
    else
        local cached_top1m="$WORDLIST_CACHE_DIR/seclists-top1M.txt"
        local cached_darkweb="$WORDLIST_CACHE_DIR/seclists-darkweb-top10k.txt"
        if [[ -s "$cached_top1m" ]]; then
            labels+=("SecLists top-1M  (cached: $cached_top1m)")
        else
            labels+=("SecLists top-1M  [not installed - will download from GitHub, ~8 MB]")
        fi
        paths+=("$cached_top1m"); kinds+=("download_top1m")

        if [[ -s "$cached_darkweb" ]]; then
            labels+=("SecLists darkweb-top10k  (cached: $cached_darkweb)")
        else
            labels+=("SecLists darkweb-top10k  [not installed - will download from GitHub, ~100 KB]")
        fi
        paths+=("$cached_darkweb"); kinds+=("download_darkweb")
    fi

    labels+=("Enter a custom path")
    paths+=(""); kinds+=("custom")

    arrow_menu "No --wordlist given. Pick one:" "${labels[@]}"
    local idx="$ARROW_MENU_RESULT"
    local kind="${kinds[$idx]}"

    case "$kind" in
        download_top1m)
            download_wordlist "$SECLISTS_TOP1M_URL" "${paths[$idx]}" "SecLists top-1M" || return 1
            ;;
        download_darkweb)
            download_wordlist "$SECLISTS_DARKWEB_URL" "${paths[$idx]}" "SecLists darkweb-top10k" || return 1
            ;;
        custom)
            local custom_path
            read -rp "Enter wordlist path: " custom_path
            echo "$custom_path"
            ;;
        *)
            echo "${paths[$idx]}"
            ;;
    esac
}

# --download-wordlists: fetch both SecLists files up front (same cache
# filenames pick_wordlist uses), so a later --crack run finds them already
# cached and never needs to prompt or wait.
do_download_wordlists() {
    local cached_top1m="$WORDLIST_CACHE_DIR/seclists-top1M.txt"
    local cached_darkweb="$WORDLIST_CACHE_DIR/seclists-darkweb-top10k.txt"
    local rc=0

    if sl="$(find_seclists_dir)"; then
        ok "SecLists is already installed locally at $sl - nothing to download."
        return 0
    fi

    download_wordlist "$SECLISTS_TOP1M_URL" "$cached_top1m" "SecLists top-1M" >/dev/null || rc=1
    download_wordlist "$SECLISTS_DARKWEB_URL" "$cached_darkweb" "SecLists darkweb-top10k" >/dev/null || rc=1
    return $rc
}

# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------
# Builds one flat array of tuples "name\tmode\tformat\tnote\tconfidence"
# combining built-in matches (by index) and learned matches, so downstream
# printing only has to deal with one shape. Sorted by confidence descending
# so the most-likely match is always shown (and auto-picked) first.
collect_hash_tuples() {
    HASH_TUPLES=()
    local i
    for i in "${MATCH_HASH_IDX[@]}"; do
        HASH_TUPLES+=("$(printf '%s\t%s\t%s\t%s\t%s' \
            "${HASH_NAMES[$i]}" "${HASH_MODES[$i]}" "${HASH_FORMATS[$i]}" "${HASH_NOTES[$i]}" "${HASH_CONFIDENCE[$i]}")")
    done
    HASH_TUPLES+=("${MATCH_HASH_LEARNED[@]}")

    if [[ ${#HASH_TUPLES[@]} -gt 1 ]]; then
        local sorted
        sorted="$(printf '%s\n' "${HASH_TUPLES[@]}" | sort -t$'\t' -k5,5 -rn)"
        mapfile -t HASH_TUPLES <<< "$sorted"
    fi
}

print_hash_matches() {
    local input="$1"
    echo
    echo "Input : $input"
    echo "Length: ${#input} chars"
    echo

    collect_hash_tuples
    if [[ ${#HASH_TUPLES[@]} -eq 0 ]]; then
        warn "No known hash signature matched."
        echo "    Teach HashSage once you know the type:"
        echo "    ./${SCRIPT_NAME} --learn"
        return 1
    fi

    ok "${#HASH_TUPLES[@]} possible hash match(es):"
    echo
    local i=1 tuple name mode fmt note conf
    for tuple in "${HASH_TUPLES[@]}"; do
        IFS=$'\t' read -r name mode fmt note conf <<< "$tuple"
        printf "  %d. %b%s%b  %b[%s%% confidence]%b\n" \
            "$i" "$C_BOLD" "$name" "$C_RESET" "$C_CYAN" "$conf" "$C_RESET"
        [[ -n "$note" && "$note" != "—" ]] && echo "     Note: $note"
        echo "     Hashcat mode : -m $mode"
        echo "     John format  : --format=$fmt"
        echo
        ((i++))
    done
    return 0
}

print_encoding_matches() {
    local input="$1"
    if [[ ${#MATCH_ENC_IDX[@]} -eq 0 ]]; then
        return 1
    fi

    ok "${#MATCH_ENC_IDX[@]} possible encoding match(es) (these are reversible, not crackable):"
    echo
    local i
    for i in "${MATCH_ENC_IDX[@]}"; do
        printf "  - %b%s%b\n" "$C_BOLD" "${ENC_NAMES[$i]}" "$C_RESET"
        echo "    $(enc_howto_text "${ENC_HOWTOS[$i]}" "$input")"
        echo
    done
    return 0
}

print_syntax() {
    local hash_file="$1" wordlist="$2" rule_file="$3"

    echo "======================================================================"
    echo "SUGGESTED COMMANDS"
    local wl_display="${wordlist:-<wordlist.txt>}"
    if [[ -z "$wordlist" ]]; then
        warn "Replace <wordlist.txt> with a real path, or re-run with --crack to pick one interactively."
    fi
    echo "======================================================================"

    collect_hash_tuples
    local tuple name mode fmt note conf
    for tuple in "${HASH_TUPLES[@]}"; do
        IFS=$'\t' read -r name mode fmt note conf <<< "$tuple"
        [[ "$mode" == "varies" || "$mode" == "n/a"* ]] && continue
        echo
        echo "--- $name ($conf% confidence) ---"
        echo "# Hashcat"
        local rule_part=""
        [[ -n "$rule_file" ]] && rule_part=" -r $rule_file"
        echo "hashcat -m $mode -a 0 $hash_file $wl_display$rule_part"
        echo "hashcat -m $mode --show $hash_file"
        echo
        echo "# John the Ripper"
        local jrule_part=""
        [[ -n "$rule_file" ]] && jrule_part=" --rules=${rule_file%.*}"
        echo "john --format=$fmt --wordlist=$wl_display $hash_file$jrule_part"
        echo "john --format=$fmt --show $hash_file"
    done
    echo
    echo "Tip: if a plain dictionary attack fails, add a rule set, e.g."
    echo "     hashcat -m <mode> -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule"
}

# ---------------------------------------------------------------------------
# Cracking
# ---------------------------------------------------------------------------
do_crack() {
    local input="$1" hash_file="$2" wordlist="$3" rule_file="$4" tool="$5"

    collect_hash_tuples
    if [[ ${#HASH_TUPLES[@]} -eq 0 ]]; then
        err "Can't auto-crack: no identified hash type. Use --learn first."
        return 1
    fi

    local name mode fmt note conf
    if [[ ${#HASH_TUPLES[@]} -eq 1 ]]; then
        IFS=$'\t' read -r name mode fmt note conf <<< "${HASH_TUPLES[0]}"
    else
        # More than one possible interpretation (e.g. MD5 vs NTLM look
        # identical) - this used to silently crack as the first match,
        # which fails confusingly if that guess is wrong. Ask instead.
        # (HASH_TUPLES is already sorted highest-confidence-first, so the
        # top option in the menu is the best guess.)
        local -a labels=()
        local t tname tmode tconf
        for t in "${HASH_TUPLES[@]}"; do
            IFS=$'\t' read -r tname tmode _ _ tconf <<< "$t"
            labels+=("$tname  (hashcat -m $tmode, ${tconf}% confidence)")
        done
        info "This hash is ambiguous - which type is it actually?"
        arrow_menu "Pick the correct interpretation to crack:" "${labels[@]}"
        IFS=$'\t' read -r name mode fmt note conf <<< "${HASH_TUPLES[$ARROW_MENU_RESULT]}"
    fi

    if ! command -v "$tool" >/dev/null 2>&1; then
        err "'$tool' is not installed or not on PATH."
        echo "    Install it, e.g.: sudo apt install $tool"
        return 1
    fi

    if [[ -z "$wordlist" ]]; then
        wordlist="$(pick_wordlist)" || return 1
    fi
    if [[ ! -f "$wordlist" ]]; then
        err "Wordlist not found: $wordlist"
        return 1
    fi

    if [[ -z "$hash_file" ]]; then
        hash_file="$(mktemp /tmp/hashsage_target.XXXXXX)"
        echo "$input" > "$hash_file"
        info "Wrote hash to $hash_file"
    fi

    info "Target : $name"
    local cmd=()
    if [[ "$tool" == "hashcat" ]]; then
        if [[ "$mode" == "varies" || "$mode" == "n/a"* ]]; then
            err "$name doesn't map to a simple hashcat mode (got: $mode). Run 'hashcat --help' and pick manually."
            return 1
        fi
        cmd=(hashcat -m "$mode" -a 0 "$hash_file" "$wordlist")
        [[ -n "$rule_file" ]] && cmd+=(-r "$rule_file")
    else
        cmd=(john "--format=$fmt" "--wordlist=$wordlist" "$hash_file")
        [[ -n "$rule_file" ]] && cmd+=("--rules=${rule_file%.*}")
    fi

    info "Running: ${cmd[*]}"
    echo
    "${cmd[@]}"
    local rc=$?

    echo
    info "Checking result..."
    if [[ "$tool" == "hashcat" ]]; then
        hashcat -m "$mode" --show "$hash_file"
    else
        john "--format=$fmt" --show "$hash_file"
    fi
    return $rc
}

# ---------------------------------------------------------------------------
# --learn mode (interactive, so you don't have to remember flag syntax)
# ---------------------------------------------------------------------------
do_learn() {
    echo "Teach HashSage a new hash format."
    echo "(Saved locally to $LEARNED_DB - nothing is sent anywhere.)"
    echo
    read -rp "Name (e.g. 'MyCustomHash'): " name
    read -rp "Regex to match it (e.g. '^XYZ-[0-9]{8}\$'): " regex
    read -rp "Hashcat -m mode (or 'varies'/'n/a' if none): " mode
    read -rp "John --format value (or 'n/a'): " fmt
    read -rp "Notes (optional): " notes
    read -rp "Confidence % (how sure is this ID - default 100): " conf
    conf="${conf:-100}"

    if [[ -z "$name" || -z "$regex" || -z "$mode" || -z "$fmt" ]]; then
        err "Name, regex, hashcat mode, and john format are all required."
        return 1
    fi
    if ! [[ "$conf" =~ ^[0-9]+$ ]] || (( conf < 0 || conf > 100 )); then
        warn "Confidence should be 0-100, got '$conf' - defaulting to 100."
        conf=100
    fi

    # sanity-check the regex compiles for grep -P
    if ! echo "test" | grep -Pq "$regex" 2>/dev/null && [[ $? -gt 1 ]]; then
        err "That regex doesn't look valid for grep -P. Not saved."
        return 1
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$regex" "$mode" "$fmt" "$notes" "$conf" >> "$LEARNED_DB"
    ok "Learned '$name' ($conf% confidence) and saved to $LEARNED_DB"
}

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
check_deps() {
    if ! command -v grep >/dev/null 2>&1 || ! grep -P '' <<< "" >/dev/null 2>&1; then
        err "This script needs GNU grep with PCRE support (grep -P)."
        echo "    On Debian/Kali/Parrot this is the default grep package - try: sudo apt install grep"
        exit 1
    fi
}

usage() {
    cat <<EOF
${C_BOLD}HashSage${C_RESET} - hash & encoding identifier, John/Hashcat syntax helper

Usage:
  ./${SCRIPT_NAME} <string>                  Identify as hash and/or encoding
  ./${SCRIPT_NAME} <string> --syntax         Also print John/Hashcat commands
  ./${SCRIPT_NAME} <string> --crack          Attempt an actual crack
      --tool hashcat|john                    Cracker to use (default: hashcat)
      --wordlist PATH                        Wordlist to use (optional - skips the
                                              interactive picker below if given)
      --rules PATH                           Optional rule file
      --hash-file PATH                       File containing the hash (else a temp file is made)

  If you DON'T pass --wordlist, HashSage detects rockyou.txt / SecLists on
  your machine and lets you pick with arrow keys + Enter (or a numbered
  prompt if there's no interactive terminal). If SecLists isn't installed,
  the two SecLists options are still offered - picking one downloads it
  from the official SecLists GitHub repo (with a confirmation prompt first)
  and caches it under ~/.hashsage/wordlists/ for every future run. If a
  hash is ambiguous (e.g. MD5 vs NTLM look identical), you'll also get an
  arrow-key prompt to pick which interpretation to actually crack against.
  ./${SCRIPT_NAME} --file PATH               Read the string from a file (first line)
  ./${SCRIPT_NAME} --learn                   Interactively add a new hash signature
  ./${SCRIPT_NAME} --list-wordlists          Show detected/cached rockyou/SecLists paths
  ./${SCRIPT_NAME} --download-wordlists      Pre-fetch both SecLists files now (skips
                                              the picker's download prompt later)
  ./${SCRIPT_NAME} --help                    This message

Examples:
  ./${SCRIPT_NAME} 5f4dcc3b5aa765d61d8327deb882cf99 --syntax
  ./${SCRIPT_NAME} '\$2a\$12\$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW' --syntax
  ./${SCRIPT_NAME} 5f4dcc3b5aa765d61d8327deb882cf99 --crack --tool hashcat
  ./${SCRIPT_NAME} dGVzdA== --syntax          (detects Base64, shows decode command)

Only use this against data you are authorized to analyze.
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    print_banner
    check_deps

    local input="" do_syntax=0 do_crack_flag=0 tool="hashcat"
    local wordlist="" rule_file="" hash_file="" file_arg=""

    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    case "$1" in
        --help|-h) usage; exit 0 ;;
        --list-wordlists) list_wordlists; exit 0 ;;
        --download-wordlists) do_download_wordlists; exit $? ;;
        --learn) do_learn; exit $? ;;
    esac

    # First non-flag arg is the input string, unless --file is used.
    if [[ "$1" != --* ]]; then
        input="$1"
        shift
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --syntax) do_syntax=1; shift ;;
            --crack) do_crack_flag=1; shift ;;
            --tool) tool="$2"; shift 2 ;;
            --wordlist) wordlist="$2"; shift 2 ;;
            --rules) rule_file="$2"; shift 2 ;;
            --hash-file) hash_file="$2"; shift 2 ;;
            --file) file_arg="$2"; shift 2 ;;
            *) err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    if [[ -n "$file_arg" ]]; then
        [[ -f "$file_arg" ]] || { err "File not found: $file_arg"; exit 1; }
        input="$(head -n1 "$file_arg")"
    fi

    if [[ -z "$input" ]]; then
        err "No input string given."
        usage
        exit 1
    fi

    # Run both identifications (results land in MATCH_HASH_IDX, MATCH_HASH_LEARNED, MATCH_ENC_IDX)
    identify_hash "$input"
    identify_encoding "$input"

    print_hash_matches "$input"
    echo
    print_encoding_matches "$input"

    collect_hash_tuples
    if [[ "$do_syntax" -eq 1 && ${#HASH_TUPLES[@]} -gt 0 ]]; then
        echo
        print_syntax "${hash_file:-hashes.txt}" "$wordlist" "$rule_file"
    fi

    if [[ "$do_crack_flag" -eq 1 ]]; then
        echo
        do_crack "$input" "$hash_file" "$wordlist" "$rule_file" "$tool"
    fi
}

main "$@"

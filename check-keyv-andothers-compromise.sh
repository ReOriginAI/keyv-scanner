#!/usr/bin/env bash
set -u

MODE="best-effort"
ROOT="/"
ROOT_SET=0
IOC_SOURCE="https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv"
IOC_SHA256="27a11ac94f9fbfe8435c8e3371e0f0c8d1abfe8f92e44e8a1a070748cccdb7c9"
IOC_SNAPSHOT="2026-08-05T00:45:00Z"

usage() {
  cat <<'USAGE'
Usage: check-keyv-package-compromise.sh [--best-effort|--strict] [SCAN_ROOT]

Scans readable npm package manifests, lockfiles, and installed packages below
SCAN_ROOT (default: /) for every malicious package/version pair embedded from:
  https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv

The IOC CSV is embedded in this script; the scan does not require network access.

Options:
  --best-effort  Finish despite permission/read/format coverage gaps and return 0
                 when no compromised or risky reference is found. This is the
                 default. Coverage gaps are still reported prominently.
  --strict       Return 2 when any path or relevant file could not be fully checked.
  -h, --help     Show this help.

Exit status:
  0  No compromised/risky reference found in the data that was readable
  1  Malicious version or unsafe/unverifiable declaration found
  2  Strict mode only: scan completed with coverage gaps
  3  Invalid invocation, missing dependency, corrupt embedded IOC data,
     or fatal scanner error
USAGE
}

while (($#)); do
  case "$1" in
    --best-effort)
      MODE="best-effort"
      ;;
    --strict)
      MODE="strict"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while (($#)); do
        if ((ROOT_SET)); then
          echo "ERROR: only one scan root may be specified." >&2
          usage >&2
          exit 3
        fi
        ROOT="$1"
        ROOT_SET=1
        shift
      done
      break
      ;;
    -*)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 3
      ;;
    *)
      if ((ROOT_SET)); then
        echo "ERROR: only one scan root may be specified." >&2
        usage >&2
        exit 3
      fi
      ROOT="$1"
      ROOT_SET=1
      ;;
  esac
  shift
done

find_node() {
  local candidate=""
  local sudo_home=""

  if [[ -n "${NODE_BIN:-}" ]]; then
    if [[ "$NODE_BIN" != /* ]]; then
      echo "ERROR: NODE_BIN must be an absolute path: $NODE_BIN" >&2
      return 1
    fi
    if [[ ! -x "$NODE_BIN" ]]; then
      echo "ERROR: NODE_BIN is not executable: $NODE_BIN" >&2
      return 1
    fi
    printf '%s\n' "$NODE_BIN"
    return 0
  fi

  if candidate="$(command -v node 2>/dev/null)" && [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  if candidate="$(command -v nodejs 2>/dev/null)" && [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  for candidate in /usr/local/bin/node /usr/bin/node /bin/node \
                   /usr/local/bin/nodejs /usr/bin/nodejs /bin/nodejs; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    if command -v getent >/dev/null 2>&1; then
      sudo_home="$(getent passwd "$SUDO_USER" 2>/dev/null | awk -F: 'NR == 1 { print $6 }')"
    fi
    if [[ -z "$sudo_home" ]]; then
      sudo_home="${SUDO_HOME:-/home/$SUDO_USER}"
    fi

    for candidate in \
      "$sudo_home/.volta/bin/node" \
      "$sudo_home/.local/bin/node" \
      "$sudo_home"/.nvm/versions/node/*/bin/node \
      "$sudo_home"/.local/share/fnm/node-versions/*/installation/bin/node \
      "$sudo_home"/.asdf/installs/nodejs/*/bin/node; do
      if [[ -x "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done
  fi

  return 1
}

if ! NODE="$(find_node)"; then
  cat >&2 <<'ERROR'
ERROR: Node.js is required, but no usable node executable was found.

When Node.js is installed only for your login user (for example through nvm), run:
  NODE_BIN="$(command -v node)" sudo --preserve-env=NODE_BIN ./check-keyv-package-compromise.sh /

On sudo configurations that reject --preserve-env, run:
  sudo env NODE_BIN="$(command -v node)" ./check-keyv-package-compromise.sh /
ERROR
  exit 3
fi

if ! "$NODE" --version >/dev/null 2>&1; then
  echo "ERROR: the selected Node.js executable cannot run: $NODE" >&2
  exit 3
fi

if [[ ! -d "$ROOT" ]]; then
  echo "ERROR: scan root is not a directory: $ROOT" >&2
  exit 3
fi

TMP_DIR="$(mktemp -d)" || exit 3
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
FILE_LIST="$TMP_DIR/files.nul"
FIND_ERRORS="$TMP_DIR/find-errors.log"
IOC_FILE="$TMP_DIR/keyv-packages.csv"

cat >"$IOC_FILE" <<'KEYV_PACKAGES_CSV'
Package,Malicious Versions
@adminide-stack/clock-tik-browser,12.0.24
@adminide-stack/yantra-mobile,12.0.33
@arv-bedrock/auth,"1.1.7, 1.1.8"
@arv-bedrock/auth-admin,"1.0.2, 1.0.3"
@arv-bedrock/auth-sso,"1.6.1, 1.6.2"
@arv-bedrock/auth-sso-backend,"1.7.1, 1.7.2"
@arv-bedrock/logger,"1.7.1, 1.7.2"
@cacheable/memory,2.2.1
@cacheable/net,2.1.1
@cacheable/node-cache,3.1.2
@cacheable/utils,2.5.1
@deliveroo/determinator,0.2.1
@deliveroo/reevent,1.0.1
@hubsync/web-sdk-react,"6.3.7, 6.3.8, 6.3.9, 6.3.10, 6.3.11, 6.3.12, 6.3.13, 6.3.14, 6.3.15, 6.3.16, 6.3.17, 6.3.18, 6.3.19, 6.3.20, 6.3.21, 6.3.22, 6.3.23, 6.3.24, 6.3.25, 6.3.26, 6.3.27, 6.3.28, 6.3.29, 6.3.30, 6.3.31, 6.3.32, 6.3.33"
@nebula.js/cli,7.1.2
@nebula.js/cli-build,7.1.2
@nebula.js/cli-sense,7.1.2
@nebula.js/locale,0.6.2
@nebula.js/nucleus,0.5.1
@nebula.js/sn-action-button,2.3.1
@nebula.js/sn-animator,2.13.1
@nebula.js/sn-distributionplot,1.0.7
@nebula.js/sn-layout-container,4.4.1
@nebula.js/sn-line-chart,2.7.1
@nebula.js/sn-listbox,0.19.3
@nebula.js/sn-map,0.12.7
@nebula.js/sn-nav-menu,0.14.2
@nebula.js/sn-org-chart,1.7.1
@nebula.js/sn-shape,1.5.1
@nebula.js/sn-slider,0.20.1
@nebula.js/sn-tabbed-container,2.4.1
@nebula.js/snapshooter,0.6.1
@nebula.js/stardust,7.1.2
@nebula.js/test-utils,0.6.1
@nebula.js/theme,0.6.1
@onereach/authorizer-helper,"0.0.11, 0.0.12, 0.0.13"
@onereach/bandwidth-steps-voice-bxml,"0.1.1, 0.1.2, 0.1.3"
@onereach/billing-dto,"27.2.1, 27.2.2, 27.2.3"
@onereach/billing-shared,"27.2.1, 27.2.2, 27.2.3"
@onereach/cb-schema-translator,"1.3.1, 1.3.2, 1.3.3"
@onereach/channel-transformer,"0.0.66, 0.0.67, 0.0.68"
@onereach/channel-transformers,"0.0.5, 0.0.6, 0.0.7"
@onereach/ckeditor5-build-classic,"30.0.1, 30.0.2, 30.0.3"
@onereach/condition-builder,"1.0.8, 1.0.9, 1.0.10"
@onereach/content-builder,"0.0.18, 0.0.19, 0.0.20"
@onereach/content-builder-template-compiler,"0.0.3, 0.0.4, 0.0.5"
@onereach/expression-components,"9.1.1, 9.1.2, 9.1.3"
@onereach/font-icons,"27.0.2, 27.0.3, 27.0.4"
@onereach/get-version-data,"3.1.2, 3.1.3, 3.1.4"
@onereach/idw-apps,"0.1.3, 0.1.4, 0.1.5"
@onereach/idw-contracts,"0.1.2, 0.1.3, 0.1.4"
@onereach/idw-init-account-resources,"1.0.1, 1.0.2, 1.0.3"
@onereach/idw-sdk,"0.1.2, 0.1.3, 0.1.4"
@onereach/idw-ui-components,"0.1.2, 0.1.3, 0.1.4"
@onereach/lambda-invocation,"1.2.1, 1.2.2, 1.2.3"
@onereach/messengers-infobip-sdk,"0.1.1, 0.1.2, 0.1.3"
@onereach/or-browser,"0.0.48, 0.0.49, 0.0.50"
@onereach/or-browser-next,"0.0.11, 0.0.12, 0.0.13"
@onereach/or-content-builder-renderer,"0.0.2, 0.0.3, 0.0.4"
@onereach/or-file-uploader-next,"0.0.8, 0.0.9, 0.0.10"
@onereach/or-pro,"1.13.1, 1.13.2, 1.13.3"
@onereach/or-sdk-agent-cli,"0.0.6, 0.0.7, 0.0.8"
@onereach/orest-cli,"2.4.1, 2.4.2, 2.4.3"
@onereach/orest-input-cli,"1.18.1, 1.18.2, 1.18.3"
@onereach/orest-jest-presets,"0.0.3, 0.0.4, 0.0.5"
@onereach/orest-vue-demi-vue2,"0.0.4, 0.0.5, 0.0.6"
@onereach/orest-vue-demi-vue3,"0.0.4, 0.0.5, 0.0.6"
@onereach/orest-vue3,"0.0.4, 0.0.5, 0.0.6"
@onereach/phonenumber-interpreter,"0.0.18, 0.0.19, 0.0.20"
@onereach/pnpm-audit-junit,"1.0.3, 1.0.4, 1.0.5"
@onereach/postcss-scoped-selector,"1.2.1, 1.2.2, 1.2.3"
@onereach/regex-helper,"0.5.16, 0.5.17, 0.5.18"
@onereach/regular-expressions,"0.5.23, 0.5.24, 0.5.25"
@onereach/regular-expressions-test,"0.0.4, 0.0.5, 0.0.6"
@onereach/rwc-client,"6.4.7, 6.4.8, 6.4.9"
@onereach/salesforce-miaw-client,"0.0.3, 0.0.4, 0.0.5"
@onereach/si-a-button,"0.0.3, 0.0.4, 0.0.5"
@onereach/si-alert,"0.4.11, 0.4.12, 0.4.13"
@onereach/si-checkbox,"0.6.5, 0.6.6, 0.6.7"
@onereach/si-checkbox-group,"0.3.5, 0.3.6, 0.3.7"
@onereach/si-code,"0.6.4, 0.6.5, 0.6.6"
@onereach/si-collapsible-group,"0.6.4, 0.6.5, 0.6.6"
@onereach/si-copyable-text,"0.4.11, 0.4.12, 0.4.13"
@onereach/si-datepicker,"0.4.5, 0.4.6, 0.4.7"
@onereach/si-divider,"0.4.11, 0.4.12, 0.4.13"
@onereach/si-dropdown-advanced,"0.4.5, 0.4.6, 0.4.7"
@onereach/si-dropdown-simple,"0.4.5, 0.4.6, 0.4.7"
@onereach/si-header,"0.4.11, 0.4.12, 0.4.13, 0.4.14"
@onereach/si-list,"0.7.4, 0.7.5, 0.7.6"
@onereach/si-merge-tag-input,"0.4.5, 0.4.6, 0.4.7"
@onereach/si-radio-group,"0.3.5, 0.3.6, 0.3.7"
@onereach/si-root,"0.9.4, 0.9.5, 0.9.6"
@onereach/si-select,"0.1.3, 0.1.4, 0.1.5"
@onereach/si-step-chooser,"0.4.4, 0.4.5, 0.4.6"
@onereach/si-switch,"0.4.5, 0.4.6, 0.4.7"
@onereach/si-text-message,"0.4.5, 0.4.6, 0.4.7"
@onereach/si-textinput,"0.5.5, 0.5.6, 0.5.7"
@onereach/si-validated-timestring-input,"0.3.5, 0.3.6, 0.3.7"
@onereach/slack-helpers,"1.0.3, 1.0.4, 1.0.5"
@onereach/ssml-editor,"2.0.12, 2.0.13, 2.0.14"
@onereach/step-components,"0.1.37, 0.1.38, 0.1.39"
@onereach/step-conversation,"1.0.41, 1.0.42, 1.0.43"
@onereach/step-run-snowflake-query,"0.1.1, 0.1.2, 0.1.3"
@onereach/step-voice,"7.0.32, 7.0.33, 7.0.34"
@onereach/styles,"27.0.2, 27.0.3, 27.0.4"
@onereach/time-interpreter,"1.0.30, 1.0.31, 1.0.32"
@onereach/ts-memoize,"1.0.2, 1.0.3, 1.0.4"
@onereach/types-contacts-api,"9.0.8, 9.0.9, 9.0.10"
@onereach/ui-components,"27.0.2, 27.0.3, 27.0.4"
@onereach/ui-components-common,"27.0.2, 27.0.3, 27.0.4"
@onereach/ui-components-vue2,"27.0.2, 27.0.3, 27.0.4"
@onereach/v-event-calendar,"0.1.22, 0.1.23, 0.1.24"
@onereach/webform,"0.3.13, 0.3.14, 0.3.15"
@or-sdk/account-settings,"1.3.6, 1.3.7, 1.3.8"
@or-sdk/accounts,"2.3.5, 2.3.6, 2.3.7"
@or-sdk/adapters,"0.3.6, 0.3.7, 0.3.8"
@or-sdk/agents,"4.21.3, 4.21.4, 4.21.5"
@or-sdk/api-tokens,"1.4.2, 1.4.3, 1.4.4"
@or-sdk/api-tokens-lambda,"1.4.2, 1.4.3, 1.4.4"
@or-sdk/apps,"1.2.6, 1.2.7, 1.2.8"
@or-sdk/auth,"0.38.1, 0.38.2, 0.38.3"
@or-sdk/authorizer,"0.26.7, 0.26.8, 0.26.9"
@or-sdk/base,"0.44.4, 0.44.5, 0.44.6"
@or-sdk/billing,"27.2.1, 27.2.2, 27.2.3"
@or-sdk/billing-internal,"27.2.1, 27.2.2, 27.2.3"
@or-sdk/bot-templates,"2.2.5, 2.2.6, 2.2.7"
@or-sdk/bots,"1.7.1, 1.7.2, 1.7.3"
@or-sdk/card-templates,"2.2.5, 2.2.6, 2.2.7"
@or-sdk/cards,"1.2.5, 1.2.6, 1.2.7"
@or-sdk/ccp,"10.15.4, 10.15.5, 10.15.6"
@or-sdk/chat,"0.3.1, 0.3.2, 0.3.3"
@or-sdk/contacts,"4.7.5, 4.7.6, 4.7.7"
@or-sdk/content-request,"0.2.6, 0.2.7, 0.2.8"
@or-sdk/data-hub,"0.26.5, 0.26.6, 0.26.7"
@or-sdk/data-hub-svc,"2.3.5, 2.3.6, 2.3.7"
@or-sdk/deployer,"1.7.5, 1.7.6, 1.7.7"
@or-sdk/deployments,"2.1.5, 2.1.6, 2.1.7"
@or-sdk/discovery,"1.12.1, 1.12.2, 1.12.3"
@or-sdk/druid,"1.4.7, 1.4.8, 1.4.9"
@or-sdk/event-manager,"1.1.5, 1.1.6, 1.1.7"
@or-sdk/files,"3.11.6, 3.11.7, 3.11.8"
@or-sdk/files-sync-node,"0.1.8, 0.1.9, 0.1.10"
@or-sdk/flow-templates,"2.1.5, 2.1.6, 2.1.7"
@or-sdk/flows,"2.7.8, 2.7.9, 2.7.10"
@or-sdk/graph,"1.10.5, 1.10.6, 1.10.7"
@or-sdk/hitl,"0.41.1, 0.41.2, 0.41.3"
@or-sdk/identifiers,"0.27.6, 0.27.7, 0.27.8"
@or-sdk/idw,"9.0.4, 9.0.5, 9.0.6"
@or-sdk/idw-public,"1.6.6, 1.6.7, 1.6.8"
@or-sdk/idw-skill,"1.4.1, 1.4.2, 1.4.3"
@or-sdk/invitations,"1.4.8, 1.4.9, 1.4.10"
@or-sdk/key-value-storage,"0.28.6, 0.28.7, 0.28.8"
@or-sdk/keys,"1.2.6, 1.2.7, 1.2.8"
@or-sdk/knowledge-models,"0.25.5, 0.25.6, 0.25.7"
@or-sdk/library,"0.5.6, 0.5.7, 0.5.8"
@or-sdk/library-categories,"0.2.6, 0.2.7, 0.2.8"
@or-sdk/library-source,"0.4.5, 0.4.6, 0.4.7"
@or-sdk/library-types-v1,"9.0.1, 9.0.2, 9.0.3"
@or-sdk/library-types-v2,"9.0.1, 9.0.2, 9.0.3"
@or-sdk/lookup,"1.25.1, 1.25.2, 1.25.3"
@or-sdk/markdowner,"0.5.1, 0.5.2, 0.5.3"
@or-sdk/mcp-tools,"0.5.2, 0.5.3, 0.5.4"
@or-sdk/notifications,"1.7.5, 1.7.6, 1.7.7"
@or-sdk/password,"1.3.6, 1.3.7, 1.3.8"
@or-sdk/payments,"3.2.5, 3.2.6, 3.2.7"
@or-sdk/permissions,"2.8.1, 2.8.2, 2.8.3"
@or-sdk/permissions-cli,"1.4.1, 1.4.2, 1.4.3"
@or-sdk/permissions-lambda,"2.5.1, 2.5.2, 2.5.3"
@or-sdk/pgsql,"1.5.1, 1.5.2, 1.5.3"
@or-sdk/providers,"0.3.6, 0.3.7, 0.3.8"
@or-sdk/qna,"3.4.2, 3.4.3, 3.4.4"
@or-sdk/queue-manager,"1.4.6, 1.4.7, 1.4.8"
@or-sdk/sdk-api,"0.29.2, 0.29.3, 0.29.4"
@or-sdk/settings,"0.25.6, 0.25.7, 0.25.8"
@or-sdk/sku-builder,"2.5.1, 2.5.2, 2.5.3"
@or-sdk/source,"2.1.5, 2.1.6, 2.1.7"
@or-sdk/source-api,"1.1.1, 1.1.2, 1.1.3"
@or-sdk/step-templates,"2.2.5, 2.2.6, 2.2.7"
@or-sdk/store,"2.1.5, 2.1.6, 2.1.7"
@or-sdk/tables,"0.28.5, 0.28.6, 0.28.7"
@or-sdk/tags,"1.1.5, 1.1.6, 1.1.7"
@or-sdk/tickets,"1.9.5, 1.9.6, 1.9.7"
@or-sdk/transcripts,"1.2.5, 1.2.6, 1.2.7"
@or-sdk/users,"3.8.1, 3.8.2, 3.8.3"
@or-sdk/view-templates,"2.2.5, 2.2.6, 2.2.7"
@or-sdk/views,"3.1.5, 3.1.6, 3.1.7"
@or-sdk/web-search,"0.6.1, 0.6.2, 0.6.3"
@ornikar/apollo-link-timeout,"1.4.2, 1.4.3, 1.4.4, 1.4.5, 1.4.6, 1.4.7, 1.4.8, 1.4.9, 1.4.10, 1.4.11"
@ornikar/babel-preset-base,"6.0.3, 6.0.4, 6.0.5, 6.0.6, 6.0.7, 6.0.8, 6.0.9, 6.0.10, 6.0.11, 6.0.12, 6.0.13, 6.0.14"
@ornikar/babel-preset-kitt-universal,"8.0.3, 8.0.4, 8.0.5, 8.0.6, 8.0.7, 8.0.8, 8.0.9, 8.0.10, 8.0.11, 8.0.12"
@ornikar/babel-preset-react,"6.1.4, 6.1.5, 6.1.6, 6.1.7, 6.1.8, 6.1.9, 6.1.10, 6.1.11, 6.1.12, 6.1.13, 6.1.14"
@ornikar/browserslist-config,"8.0.3, 8.0.4, 8.0.5, 8.0.6, 8.0.7, 8.0.8, 8.0.9, 8.0.10, 8.0.11"
@ornikar/commitlint-config,"8.3.2, 8.3.3, 8.3.4, 8.3.5, 8.3.6, 8.3.7, 8.3.8, 8.3.9, 8.3.10, 8.3.11, 8.3.12"
@ornikar/eslint-config,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10, 24.0.11, 24.0.12"
@ornikar/eslint-config-babel,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10, 24.0.11, 24.0.12"
@ornikar/eslint-config-babel-use,"13.2.1, 13.2.2, 13.2.3, 13.2.4, 13.2.5, 13.2.6, 13.2.7, 13.2.8, 13.2.9, 13.2.10, 13.2.11, 13.2.12"
@ornikar/eslint-config-formatjs,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10"
@ornikar/eslint-config-node,"12.2.1, 12.2.2, 12.2.3, 12.2.4, 12.2.5, 12.2.6, 12.2.7, 12.2.8, 12.2.9, 12.2.10"
@ornikar/eslint-config-react,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10, 24.0.11"
@ornikar/eslint-config-typescript,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10"
@ornikar/eslint-config-typescript-nestjs,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10, 24.0.11"
@ornikar/eslint-config-typescript-react,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10, 24.0.11"
@ornikar/eslint-plugin-neverthrow,"1.3.1, 1.3.2, 1.3.3, 1.3.4, 1.3.5, 1.3.6, 1.3.7, 1.3.8, 1.3.9, 1.3.10, 1.3.11, 1.3.12"
@ornikar/eslint-plugin-ornikar,"24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5, 24.0.6, 24.0.7, 24.0.8, 24.0.9, 24.0.10, 24.0.11"
@ornikar/graphql-config,"1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.1.6, 1.1.7, 1.1.8, 1.1.9, 1.1.10, 1.1.11"
@ornikar/intl-config,"10.0.2, 10.0.3, 10.0.4, 10.0.5, 10.0.6, 10.0.7, 10.0.8, 10.0.9, 10.0.10"
@ornikar/jest-config,"13.0.3, 13.0.4, 13.0.5, 13.0.6, 13.0.7, 13.0.8, 13.0.9, 13.0.10, 13.0.11, 13.0.12, 13.0.13"
@ornikar/jest-config-react,"18.0.2, 18.0.3, 18.0.4, 18.0.5, 18.0.6, 18.0.7, 18.0.8, 18.0.9, 18.0.10, 18.0.11"
@ornikar/jest-config-react-native,"17.0.2, 17.0.3, 17.0.4, 17.0.5, 17.0.6, 17.0.7, 17.0.8, 17.0.9, 17.0.10, 17.0.11, 17.0.12"
@ornikar/jest-config-react-native-web,"12.0.3, 12.0.4, 12.0.5, 12.0.6, 12.0.7, 12.0.8, 12.0.9, 12.0.10, 12.0.11, 12.0.12, 12.0.13"
@ornikar/kitt2,"1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10, 1.0.11"
@ornikar/lerna-config,"11.0.1, 11.0.2, 11.0.3, 11.0.4, 11.0.5, 11.0.6, 11.0.7, 11.0.8, 11.0.9, 11.0.10, 11.0.11"
@ornikar/monorepo-config,"14.3.2, 14.3.3, 14.3.4, 14.3.5, 14.3.6, 14.3.7, 14.3.8, 14.3.9, 14.3.10, 14.3.11, 14.3.12, 14.3.13"
@ornikar/postcss-config,"9.1.2, 9.1.3, 9.1.4, 9.1.5, 9.1.6, 9.1.7, 9.1.8, 9.1.9, 9.1.10, 9.1.11, 9.1.12"
@ornikar/prettier-config,"9.0.3, 9.0.4, 9.0.5, 9.0.6, 9.0.7, 9.0.8, 9.0.9, 9.0.10, 9.0.11"
@ornikar/prismic-components,"0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8, 0.0.9, 0.0.10, 0.0.11, 0.0.12"
@ornikar/react-modern-calendar-datepicker,"3.2.1, 3.2.2, 3.2.3, 3.2.4, 3.2.5, 3.2.6, 3.2.7, 3.2.8, 3.2.9, 3.2.10, 3.2.11"
@ornikar/react-native-svg-transformer,"1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10, 1.0.11, 1.0.12, 1.0.13"
@ornikar/renovate-config,"9.0.2, 9.0.3, 9.0.4, 9.0.5, 9.0.6, 9.0.7, 9.0.8, 9.0.9, 9.0.10, 9.0.11, 9.0.12, 9.0.13"
@ornikar/repo-config,"15.3.3, 15.3.4, 15.3.5, 15.3.6, 15.3.7, 15.3.8, 15.3.9, 15.3.10, 15.3.11, 15.3.12, 15.3.13"
@ornikar/repo-config-react,"13.0.8, 13.0.9, 13.0.10, 13.0.11, 13.0.12, 13.0.13, 13.0.14, 13.0.15, 13.0.16, 13.0.17, 13.0.18, 13.0.19"
@ornikar/repo-config-react-legacy-css,"15.1.2, 15.1.3, 15.1.4, 15.1.5, 15.1.6, 15.1.7, 15.1.8, 15.1.9, 15.1.10, 15.1.11, 15.1.12, 15.1.13"
@ornikar/rollup-config,"11.1.2, 11.1.3, 11.1.4, 11.1.5, 11.1.6, 11.1.7, 11.1.8, 11.1.9, 11.1.10, 11.1.11, 11.1.12, 11.1.13"
@ornikar/rollup-plugin-postcss,"2.0.5, 2.0.6, 2.0.7, 2.0.8, 2.0.9, 2.0.10, 2.0.11, 2.0.12, 2.0.13, 2.0.14, 2.0.15"
@ornikar/slate-react-fork,"1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10, 1.0.11"
@ornikar/storybook-config,"12.1.2, 12.1.3, 12.1.4, 12.1.5, 12.1.6, 12.1.7, 12.1.8, 12.1.9, 12.1.10"
@ornikar/stylelint-config,"14.0.3, 14.0.4, 14.0.5, 14.0.6, 14.0.7, 14.0.8, 14.0.9, 14.0.10, 14.0.11, 14.0.12, 14.0.13"
@ornikar/typed-css-modules-loader,"0.8.2, 0.8.3, 0.8.4, 0.8.5, 0.8.6, 0.8.7, 0.8.8, 0.8.9, 0.8.10, 0.8.11, 0.8.12"
@ornikar/webpack-config,"12.0.2, 12.0.3, 12.0.4, 12.0.5, 12.0.6, 12.0.7, 12.0.8, 12.0.9, 12.0.10, 12.0.11, 12.0.12"
@picsart/ai-sdk,3.32.2
@picsart/gen-ai,2.55.11
@qlik/api,2.14.2
@qlik/browserslist-config,3.0.2
@qlik/carbon-core,2.1.1
@qlik/carboncopy,1.1.6
@qlik/design-tokens,1.3.13
@qlik/dts-bundler,2.0.3
@qlik/embed-react,2.5.3
@qlik/embed-runtime,1.6.4
@qlik/embed-svelte,1.1.4
@qlik/embed-web-components,1.7.3
@qlik/eslint-config,2.0.20
@qlik/eslint-config-base,0.1.1
@qlik/eslint-config-react,0.1.1
@qlik/eslint-config-svelte,0.1.1
@qlik/eslint-config-vue,0.1.1
@qlik/nebula-table-utils,2.6.9
@qlik/oxfmt-config,0.1.6
@qlik/oxlint-config,0.7.2
@qlik/prettier-config,1.0.3
@qlik/react-native-simple-grid,1.5.5
@qlik/runtime-module-loader,1.5.1
@qlik/sdk,0.28.1
@qlik/sprout-design-docs,1.0.2
@qlik/sprout-gesture,0.0.13
@qlik/sprout-icons,0.12.3
@qlik/sprout-react,6.45.3
@qlik/sprout-react-table,0.16.7
@qlik/tsconfig,1.0.3
@servicetitan/acquisition-functions,"5.22.1, 5.22.2, 5.22.3, 5.22.4, 5.22.5, 5.22.6, 5.22.7"
@servicetitan/admin-layout,"2.4.3, 2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9"
@servicetitan/admin-sql-table,"1.0.14, 1.0.15, 1.0.16, 1.0.17, 1.0.18, 1.0.19, 1.0.20"
@servicetitan/ajax-handlers,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/anvil-css-utilities,"14.5.4, 14.5.5, 14.5.6, 14.5.7, 14.5.8, 14.5.9, 14.5.10"
@servicetitan/anvil-fonts,"14.5.4, 14.5.5, 14.5.6, 14.5.7, 14.5.8, 14.5.9, 14.5.10"
@servicetitan/anvil-icon,"0.5.1, 0.5.2, 0.5.3, 0.5.4, 0.5.5, 0.5.6, 0.5.7"
@servicetitan/anvil-icons,"14.5.4, 14.5.5, 14.5.6, 14.5.7, 14.5.8, 14.5.9, 14.5.10"
@servicetitan/anvil-react,"0.11.3, 0.11.4, 0.11.5, 0.11.6, 0.11.7, 0.11.8, 0.11.9"
@servicetitan/anvil-themes,"14.5.4, 14.5.5, 14.5.6, 14.5.7, 14.5.8, 14.5.9, 14.5.10"
@servicetitan/anvil-token,"0.4.1, 0.4.2, 0.4.3, 0.4.4, 0.4.5, 0.4.6, 0.4.7"
@servicetitan/anvil2,"3.9.1, 3.9.2, 3.9.3, 3.9.4, 3.9.5, 3.9.6, 3.9.7"
@servicetitan/anvil2-codemods,"0.11.2, 0.11.3, 0.11.4, 0.11.5, 0.11.6, 0.11.7, 0.11.8"
@servicetitan/anvil2-ext-atlas,"4.0.2, 4.0.3, 4.0.4, 4.0.5, 4.0.6, 4.0.7, 4.0.8"
@servicetitan/anvil2-ext-charts,"0.2.4, 0.2.5, 0.2.6, 0.2.7, 0.2.8, 0.2.9, 0.2.10"
@servicetitan/anvil2-ext-common,"0.7.1, 0.7.2, 0.7.3, 0.7.4, 0.7.5, 0.7.6, 0.7.7"
@servicetitan/anvil2-ext-mwv,"0.0.5, 0.0.6, 0.0.7, 0.0.8, 0.0.9, 0.0.10, 0.0.11"
@servicetitan/anvil2-illustrations,"1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7, 1.0.8"
@servicetitan/anvil2-mcp,"0.0.9, 0.0.10, 0.0.11, 0.0.12, 0.0.13, 0.0.14, 0.0.15"
@servicetitan/assist-ui,"2.1.1, 2.1.2, 2.1.3, 2.1.4, 2.1.5, 2.1.6, 2.1.7"
@servicetitan/assist-utils,"1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.1.6, 1.1.7, 1.1.8"
@servicetitan/carto-charts-core,"0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8"
@servicetitan/carto-charts-react,"0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8"
@servicetitan/carto-charts-rn,"0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8"
@servicetitan/carto-react-kit,"0.8.4, 0.8.5, 0.8.6, 0.8.7, 0.8.8, 0.8.9, 0.8.10"
@servicetitan/carto-rn-kit,"0.0.10, 0.0.11, 0.0.12, 0.0.13, 0.0.14, 0.0.15, 0.0.16"
@servicetitan/carto-tokens,"0.3.1, 0.3.2, 0.3.3, 0.3.4, 0.3.5, 0.3.6, 0.3.7"
@servicetitan/component-usage,"28.5.1, 28.5.2, 28.5.3, 28.5.4, 28.5.5, 28.5.6, 28.5.7"
@servicetitan/confirm,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/confirm-navigation,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/contentful,"0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8, 0.0.9"
@servicetitan/contentful-proxy,"1.1.12, 1.1.13, 1.1.14, 1.1.15, 1.1.16, 1.1.17, 1.1.18"
@servicetitan/cp-api,"1.115.1, 1.115.2, 1.115.3, 1.115.4, 1.115.5, 1.115.6, 1.115.7"
@servicetitan/cp-mfe,"1.115.1, 1.115.2, 1.115.3, 1.115.4, 1.115.5, 1.115.6, 1.115.7"
@servicetitan/cp-mfe-dev,"1.115.1, 1.115.2, 1.115.3, 1.115.4, 1.115.5, 1.115.6, 1.115.7"
@servicetitan/cp-react-hooks,"1.115.1, 1.115.2, 1.115.3, 1.115.4, 1.115.5, 1.115.6, 1.115.7"
@servicetitan/cp-ui,"1.115.1, 1.115.2, 1.115.3, 1.115.4, 1.115.5, 1.115.6, 1.115.7"
@servicetitan/culture,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/data-query,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/datadog-rum,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/datetime-utils,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/design-system,"14.5.4, 14.5.5, 14.5.6, 14.5.7, 14.5.8, 14.5.9, 14.5.10"
@servicetitan/docs-anvil-uikit-contrib,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/docs-uikit,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/document-title,"2.4.1, 2.4.2, 2.4.3, 2.4.4, 2.4.5, 2.4.6, 2.4.7"
@servicetitan/dte-pdf-editor,"1.76.1, 1.76.2, 1.76.3, 1.76.4, 1.76.5, 1.76.6, 1.76.7"
@servicetitan/dte-unlayer,"0.150.1, 0.150.2, 0.150.3, 0.150.4, 0.150.5, 0.150.6, 0.150.7"
@servicetitan/eh-module-communication,"0.2.1, 0.2.2, 0.2.3, 0.2.4, 0.2.5, 0.2.6, 0.2.7"
@servicetitan/error-boundary,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/eslint-config,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/eslint-plugin,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/eslint-plugin-decorators-declare,"12.8.15, 12.8.16, 12.8.17, 12.8.18, 12.8.19, 12.8.20, 12.8.21"
@servicetitan/eslint-plugin-folder-schema,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/eslint-plugin-mobx-6,"12.8.15, 12.8.16, 12.8.17, 12.8.18, 12.8.19, 12.8.20"
@servicetitan/eslint-plugin-processors-stub,"12.8.15, 12.8.16, 12.8.17, 12.8.18, 12.8.19, 12.8.20, 12.8.21"
@servicetitan/examples,"1.2.5, 1.2.6, 1.2.7, 1.2.8, 1.2.9, 1.2.10, 1.2.11"
@servicetitan/feature-spotlight,"3.9.1, 3.9.2, 3.9.3, 3.9.4, 3.9.5, 3.9.6, 3.9.7"
@servicetitan/folder-lint,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/forge,"0.5.1, 0.5.2, 0.5.3, 0.5.4, 0.5.5, 0.5.6, 0.5.7"
@servicetitan/form,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/form-state,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/grid,"0.0.63, 0.0.64, 0.0.65, 0.0.66, 0.0.67, 0.0.68, 0.0.69"
@servicetitan/hammer-icon,"1.2.1, 1.2.2, 1.2.3, 1.2.4, 1.2.5, 1.2.6, 1.2.7"
@servicetitan/hammer-react,"1.42.2, 1.42.3, 1.42.4, 1.42.5, 1.42.6, 1.42.7, 1.42.8"
@servicetitan/hammer-token,"3.1.1, 3.1.2, 3.1.3, 3.1.4, 3.1.5, 3.1.6, 3.1.7"
@servicetitan/hash-browser-router,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/help-center,"1.0.8, 1.0.9, 1.0.10, 1.0.11, 1.0.12, 1.0.13, 1.0.14"
@servicetitan/html-sketchapp,"4.2.8, 4.2.9, 4.2.10, 4.2.11, 4.2.12, 4.2.13, 4.2.14"
@servicetitan/install,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/intl,"7.2.1, 7.2.2, 7.2.3, 7.2.4, 7.2.5, 7.2.6, 7.2.7"
@servicetitan/json-render-react,"0.4.6, 0.4.7, 0.4.8, 0.4.9, 0.4.10, 0.4.11, 0.4.12"
@servicetitan/kendo-theme,"0.0.27, 0.0.28, 0.0.29, 0.0.30, 0.0.31, 0.0.32, 0.0.33"
@servicetitan/ko-bridge,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/launchdarkly-service,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/lazy-module,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/ld-type-generator,"0.2.1, 0.2.2, 0.2.3, 0.2.4, 0.2.5, 0.2.6, 0.2.7"
@servicetitan/line-item-editor,"1.5.1, 1.5.2, 1.5.3, 1.5.4, 1.5.5, 1.5.6, 1.5.7"
@servicetitan/link-item,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/log-service,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/marketing-direct-mail-components,"20.1.1, 20.1.2, 20.1.3, 20.1.4, 20.1.5, 20.1.6, 20.1.7"
@servicetitan/marketing-email-components,"20.2.3, 20.2.4, 20.2.5, 20.2.6, 20.2.7, 20.2.8, 20.2.9"
@servicetitan/marketing-form,"0.1.2, 0.1.3, 0.1.4, 0.1.5, 0.1.6, 0.1.7, 0.1.8"
@servicetitan/marketing-global-route,"1.14.1, 1.14.2, 1.14.3, 1.14.4, 1.14.5, 1.14.6, 1.14.7"
@servicetitan/marketing-integration-widgets,"1.0.40, 1.0.41, 1.0.42, 1.0.43, 1.0.44, 1.0.45, 1.0.46"
@servicetitan/marketing-route,"1.2.1, 1.2.2, 1.2.3, 1.2.4, 1.2.5, 1.2.6, 1.2.7"
@servicetitan/marketing-ui,"9.3.1, 9.3.2, 9.3.3, 9.3.4, 9.3.5, 9.3.6, 9.3.7"
@servicetitan/marketing-widgets,"1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7"
@servicetitan/measure-sheet-data,"2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7"
@servicetitan/mfe-quick-actions,"0.5.49, 0.5.50, 0.5.51, 0.5.52, 0.5.53, 0.5.54, 0.5.55"
@servicetitan/micro-frontend,"0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8, 0.0.9, 0.0.10"
@servicetitan/microfront,"0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8"
@servicetitan/microfront-auth,"0.0.5, 0.0.6, 0.0.7, 0.0.8, 0.0.9, 0.0.10, 0.0.11"
@servicetitan/microfront-tests,"0.0.11, 0.0.12, 0.0.13, 0.0.14, 0.0.15, 0.0.16, 0.0.17"
@servicetitan/microfront-utils,"1.4.1, 1.4.2, 1.4.3, 1.4.4, 1.4.5, 1.4.6, 1.4.7"
@servicetitan/modularpayments-webfields,"1.0.53, 1.0.54, 1.0.55, 1.0.56, 1.0.57, 1.0.58, 1.0.59"
@servicetitan/moneyout-api-client,"1.29.1, 1.29.2, 1.29.3, 1.29.4, 1.29.5, 1.29.6, 1.29.7"
@servicetitan/mpa-components,"2.5.1, 2.5.2, 2.5.3, 2.5.4, 2.5.5, 2.5.6, 2.5.7"
@servicetitan/navigation,"14.1.1, 14.1.2, 14.1.3, 14.1.4, 14.1.5, 14.1.6, 14.1.7"
@servicetitan/notifications,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/onboarding-ui,"18.5.1, 18.5.2, 18.5.3, 18.5.4, 18.5.5, 18.5.6, 18.5.7"
@servicetitan/quick-actions,"1.15.2, 1.15.3, 1.15.4, 1.15.5, 1.15.6, 1.15.7, 1.15.8"
@servicetitan/react-hooks,"7.7.1, 7.7.2, 7.7.3, 7.7.4, 7.7.5, 7.7.6, 7.7.7"
@servicetitan/react-ioc,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/responsive,"6.1.1, 6.1.2, 6.1.3, 6.1.4, 6.1.5, 6.1.6, 6.1.7"
@servicetitan/restrict-imports,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/schema-comparison,"0.1.3, 0.1.4, 0.1.5, 0.1.6, 0.1.7, 0.1.8, 0.1.9"
@servicetitan/skeleton,"9.2.4, 9.2.5, 9.2.6, 9.2.7, 9.2.8, 9.2.9, 9.2.10"
@servicetitan/standalone-core-feature-gates,"1.11.4, 1.11.5, 1.11.6, 1.11.7, 1.11.8, 1.11.9, 1.11.10"
@servicetitan/standalone-feature-flags,"2.3.2, 2.3.3, 2.3.4, 2.3.5, 2.3.6, 2.3.7, 2.3.8"
@servicetitan/standalone-root,"1.11.3, 1.11.4, 1.11.5, 1.11.6, 1.11.7, 1.11.8, 1.11.9"
@servicetitan/standalone-tm-api,"1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.1.6, 1.1.7"
@servicetitan/standalone-ui,"2.2.4, 2.2.5, 2.2.6, 2.2.7, 2.2.8, 2.2.9, 2.2.10"
@servicetitan/startup,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/startup-jest,"2.2.1, 2.2.2, 2.2.3, 2.2.4, 2.2.5, 2.2.6, 2.2.7"
@servicetitan/startup-mfe-compat,"0.5.1, 0.5.2, 0.5.3, 0.5.4, 0.5.5, 0.5.6, 0.5.7"
@servicetitan/startup-utils,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/stylelint-config,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/suppress-warnings,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/table,"41.3.1, 41.3.2, 41.3.3, 41.3.4, 41.3.5, 41.3.6, 41.3.7"
@servicetitan/tanstack-query-mobx,"6.2.1, 6.2.2, 6.2.3, 6.2.4, 6.2.5, 6.2.6, 6.2.7"
@servicetitan/temporal-lite,"3.4.1, 3.4.2, 3.4.3, 3.4.4, 3.4.5, 3.4.6, 3.4.7"
@servicetitan/testing-library,"6.6.1, 6.6.2, 6.6.3, 6.6.4, 6.6.5, 6.6.6, 6.6.7"
@servicetitan/thoughtspot-theme,"1.7.1, 1.7.2, 1.7.3, 1.7.4, 1.7.5, 1.7.6, 1.7.7"
@servicetitan/time-zones,"3.8.1, 3.8.2, 3.8.3, 3.8.4, 3.8.5, 3.8.6, 3.8.7"
@servicetitan/titan-chat-ui,"7.1.3, 7.1.4, 7.1.5, 7.1.6, 7.1.7, 7.1.8, 7.1.9"
@servicetitan/titan-chat-ui-anvil2,"9.0.1, 9.0.2, 9.0.3, 9.0.4, 9.0.5, 9.0.6, 9.0.7"
@servicetitan/titan-chat-ui-common,"9.0.1, 9.0.2, 9.0.3, 9.0.4, 9.0.5, 9.0.6, 9.0.7"
@servicetitan/titan-chat-ui-cypress,"2.1.3, 2.1.4, 2.1.5, 2.1.6, 2.1.7, 2.1.8, 2.1.9"
@servicetitan/titan-chatbot-api,"9.0.1, 9.0.2, 9.0.3, 9.0.4, 9.0.5, 9.0.6, 9.0.7"
@servicetitan/titan-chatbot-client,"2.1.3, 2.1.4, 2.1.5, 2.1.6, 2.1.7, 2.1.8, 2.1.9"
@servicetitan/titan-chatbot-ui,"7.1.3, 7.1.4, 7.1.5, 7.1.6, 7.1.7, 7.1.8, 7.1.9"
@servicetitan/titan-chatbot-ui-anvil2,"9.0.1, 9.0.2, 9.0.3, 9.0.4, 9.0.5, 9.0.6, 9.0.7"
@servicetitan/titan-chatbot-ui-cypress,"9.0.1, 9.0.2, 9.0.3, 9.0.4, 9.0.5, 9.0.6, 9.0.7"
@servicetitan/tokens,"12.9.1, 12.9.2, 12.9.3, 12.9.4, 12.9.5, 12.9.6, 12.9.7"
@servicetitan/toolbelt-shared-registry,"1.14.1, 1.14.2, 1.14.3, 1.14.4, 1.14.5, 1.14.6, 1.14.7"
@servicetitan/uikit-docs,"22.11.1, 22.11.2, 22.11.3, 22.11.4, 22.11.5, 22.11.6, 22.11.7"
@servicetitan/unit-tests,"0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7, 0.0.8"
@servicetitan/va-mfe-loader,"1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.1.6, 1.1.7"
@servicetitan/web-components,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7"
@servicetitan/widget-platform,"5.6.1, 5.6.2, 5.6.3, 5.6.4, 5.6.5, 5.6.6, 5.6.7"
@servicetitan/widget-platform-monolith,"5.6.1, 5.6.2, 5.6.3, 5.6.4, 5.6.5, 5.6.6, 5.6.7"
@thiennq/docs-viewer,"1.6.2, 1.6.3, 1.6.4"
@umacloud/cli-darwin-arm64,1.0.74
@umacloud/cli-darwin-x64,1.0.74
@umacloud/cli-linux-arm64,1.0.74
@umacloud/cli-linux-musl-arm64,1.0.74
@umacloud/cli-linux-musl-x64,1.0.74
@umacloud/cli-linux-x64,1.0.74
@umacloud/cli-win32-x64,1.0.74
@umacloud/knowledge,1.0.74
@workbench-stack/core,3.9.8
babel-plugin-linaria-css-to-undefined,"0.3.1, 0.3.2, 0.3.3, 0.3.4, 0.3.5, 0.3.6, 0.3.7, 0.3.8, 0.3.9, 0.3.10, 0.3.11, 0.3.12, 0.3.13, 0.3.14, 0.3.15, 0.3.16, 0.3.17"
cache-manager,7.2.10
cacheable,2.5.1
cacheable-request,13.0.20
conv-context-next,"1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10"
ecto,5.0.1
editable-contracts,"0.0.12, 0.0.13, 0.0.14, 0.0.15, 0.0.16, 0.0.17, 0.0.18, 0.0.19, 0.0.20, 0.0.21, 0.0.22, 0.0.23, 0.0.24, 0.0.25, 0.0.26, 0.0.27"
eslint-plugin-folder-schema,"1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10, 1.0.11, 1.0.12, 1.0.13, 1.0.14, 1.0.15, 1.0.16, 1.0.17, 1.0.18, 1.0.19, 1.0.20, 1.0.21"
example-js-project,"1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10, 1.0.11"
file-entry-cache,11.1.6
flat-cache,6.1.24
folder-lint,"1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10, 1.0.11, 1.0.12, 1.0.13, 1.0.14, 1.0.15, 1.0.16, 1.0.17, 1.0.18, 1.0.19, 1.0.20, 1.0.21"
frontend-orb,"4.4.1, 4.4.2, 4.4.3, 4.4.4, 4.4.5, 4.4.6, 4.4.7, 4.4.8, 4.4.9, 4.4.10, 4.4.11, 4.4.12, 4.4.13, 4.4.14, 4.4.15, 4.4.16, 4.4.17, 4.4.18"
hamus.js,0.4.1
http-metrics-middleware,2.2.2
keyv,6.0.0
native-frontend-orb,"1.1.4, 1.1.5, 1.1.6, 1.1.7, 1.1.8, 1.1.9, 1.1.10, 1.1.11, 1.1.12, 1.1.13, 1.1.14, 1.1.15, 1.1.16, 1.1.17, 1.1.18, 1.1.19"
picasso-plugin-hammer,2.11.6
picasso-plugin-q,2.11.6
picasso.js,2.11.6
pob-test-package-in-monorepo,"5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.2.10, 5.2.11, 5.2.12, 5.2.13, 5.2.14, 5.2.15, 5.2.16"
pob-test-typescript-package-in-monorepo,"4.2.1, 4.2.2, 4.2.3, 4.2.4, 4.2.5, 4.2.6, 4.2.7, 4.2.8, 4.2.9, 4.2.10, 4.2.11, 4.2.12, 4.2.13, 4.2.14, 4.2.15, 4.2.16, 4.2.17"
qlik-chart-modules,1.1.1
qlik-modifiers,0.10.1
qlik-object-conversion,0.17.2
rwc-client,"0.29.10, 0.29.11, 0.29.12, 0.29.13, 0.29.14, 0.29.15, 0.29.16, 0.29.17, 0.29.18, 0.29.19"
server-hemera-mongo,0.0.12
sn-listbox,0.3.3
tslint-folder-schema,"1.0.6, 1.0.7, 1.0.8, 1.0.9, 1.0.10, 1.0.11, 1.0.12, 1.0.13, 1.0.14, 1.0.15, 1.0.16, 1.0.17, 1.0.18, 1.0.19, 1.0.20, 1.0.21"
umadev,1.0.74
verdaccio-okta-oauth,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7, 38.1.8, 38.1.9, 38.1.10, 38.1.11, 38.1.12, 38.1.13, 38.1.14, 38.1.15, 38.1.16"
verdaccio-tarball-local-storage,"38.1.1, 38.1.2, 38.1.3, 38.1.4, 38.1.5, 38.1.6, 38.1.7, 38.1.8, 38.1.9, 38.1.10, 38.1.11, 38.1.12, 38.1.13, 38.1.14, 38.1.15, 38.1.16"
workbench-browser-server,0.0.2
KEYV_PACKAGES_CSV

verify_ioc_hash() {
  local actual=""
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$IOC_FILE" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$IOC_FILE" | awk '{print $1}')"
  else
    return 0
  fi

  if [[ "$actual" != "$IOC_SHA256" ]]; then
    echo "ERROR: embedded IOC CSV failed its SHA-256 integrity check." >&2
    echo "Expected: $IOC_SHA256" >&2
    echo "Actual:   $actual" >&2
    exit 3
  fi
}

verify_ioc_hash

echo "Using Node.js: $NODE ($("$NODE" --version 2>/dev/null))"
echo "Embedded IOC snapshot: $IOC_SNAPSHOT"
echo "IOC source: $IOC_SOURCE"
echo "Embedded IOC SHA-256: $IOC_SHA256"

# Do not descend into virtual kernel filesystems or VCS metadata. We do descend
# into node_modules and package-manager stores because every installed package
# manifest must be checked against the embedded IOC list.
find "$ROOT" \
  \( -type d \( \
       -path /proc -o -path /sys -o -path /dev -o -path /run -o \
       -path '*/.git' -o -path '*/.hg' -o -path '*/.svn' \
     \) -prune \) -o \
  \( -type f \( \
       -name package.json -o \
       -name package-lock.json -o -name npm-shrinkwrap.json -o \
       -name yarn.lock -o -name pnpm-lock.yaml -o \
       -name bun.lock -o -name bun.lockb \
     \) -print0 \) \
  >"$FILE_LIST" 2>"$FIND_ERRORS"
FIND_STATUS=$?

"$NODE" - "$IOC_FILE" "$FILE_LIST" <<'NODE'
'use strict';

const fs = require('fs');
const path = require('path');

const IOC_FILE = process.argv[2];
const FILE_LIST = process.argv[3];

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field.replace(/\r$/, ''));
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }

  if (quoted) throw new Error('unterminated quoted CSV field');
  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ''));
    rows.push(row);
  }
  return rows;
}

function loadIocs(file) {
  const rows = parseCsv(fs.readFileSync(file, 'utf8'));
  if (!rows.length || rows[0][0] !== 'Package' || rows[0][1] !== 'Malicious Versions') {
    throw new Error('unexpected IOC CSV header');
  }

  const result = new Map();
  for (let i = 1; i < rows.length; i++) {
    const [nameRaw, versionsRaw] = rows[i];
    const name = String(nameRaw || '').trim();
    const versions = String(versionsRaw || '')
      .split(',')
      .map(v => v.trim())
      .filter(Boolean);

    if (!name && versions.length === 0) continue;
    if (!name || versions.length === 0) {
      throw new Error(`invalid IOC CSV row ${i + 1}`);
    }
    if (result.has(name)) {
      throw new Error(`duplicate IOC package row: ${name}`);
    }
    result.set(name, new Set(versions));
  }
  return result;
}

let IOCs;
try {
  IOCs = loadIocs(IOC_FILE);
} catch (err) {
  console.error(`ERROR: failed to load embedded IOC CSV: ${err.message}`);
  process.exit(3);
}

const pairCount = [...IOCs.values()].reduce((sum, versions) => sum + versions.size, 0);
const input = fs.readFileSync(FILE_LIST).toString('utf8');
const files = input.split('\0').filter(Boolean);

const confirmed = new Map();
const risky = new Map();
const incomplete = [];
let scanned = 0;

function add(map, file, detail) {
  map.set(`${file}\0${detail}`, { file, detail });
}

function addIncomplete(file, detail) {
  incomplete.push(`${file}: ${detail}`);
}

function parseVersion(value) {
  const m = String(value).trim().replace(/^v/, '').match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-[0-9A-Za-z.-]+)?$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2] || 0), Number(m[3] || 0)];
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

function expandXRange(token) {
  const raw = token.replace(/^v/, '');
  const parts = raw.split('.');
  const isX = p => p === undefined || /^(?:x|\*)$/i.test(p);
  if (isX(parts[0])) return { low: [0, 0, 0], high: null };
  const major = Number(parts[0]);
  if (!Number.isInteger(major)) return null;
  if (isX(parts[1])) return { low: [major, 0, 0], high: [major + 1, 0, 0] };
  const minor = Number(parts[1]);
  if (!Number.isInteger(minor)) return null;
  if (isX(parts[2])) return { low: [major, minor, 0], high: [major, minor + 1, 0] };
  const patch = Number(parts[2]);
  if (!Number.isInteger(patch)) return null;
  return { exact: [major, minor, patch] };
}

function comparatorMatches(target, token) {
  token = token.trim();
  if (!token || token === '*') return true;

  const opMatch = token.match(/^(<=|>=|<|>|=|~|\^)?\s*(.+)$/);
  if (!opMatch) return null;
  const op = opMatch[1] || '';
  const raw = opMatch[2].trim();

  if (/^(?:latest|next|beta|alpha|canary|dev)$/i.test(raw)) return null;
  const xr = expandXRange(raw);
  if (!xr) return null;

  if (!op) {
    if (xr.exact) return cmp(target, xr.exact) === 0;
    return cmp(target, xr.low) >= 0 && (!xr.high || cmp(target, xr.high) < 0);
  }

  const v = xr.exact || xr.low;
  if (op === '=') return cmp(target, v) === 0;
  if (op === '<') return cmp(target, v) < 0;
  if (op === '<=') return cmp(target, v) <= 0;
  if (op === '>') return cmp(target, v) > 0;
  if (op === '>=') return cmp(target, v) >= 0;

  if (op === '~') {
    const specified = raw.replace(/^v/, '').split('.').length;
    const high = specified <= 1 ? [v[0] + 1, 0, 0] : [v[0], v[1] + 1, 0];
    return cmp(target, v) >= 0 && cmp(target, high) < 0;
  }

  if (op === '^') {
    let high;
    if (v[0] > 0) high = [v[0] + 1, 0, 0];
    else if (v[1] > 0) high = [0, v[1] + 1, 0];
    else high = [0, 0, v[2] + 1];
    return cmp(target, v) >= 0 && cmp(target, high) < 0;
  }

  return null;
}

function clauseMayMatch(target, clause) {
  clause = clause.trim();
  if (!clause) return true;

  const hyphen = clause.match(/^\s*([^\s]+)\s+-\s+([^\s]+)\s*$/);
  if (hyphen) {
    const lo = parseVersion(hyphen[1]);
    const hi = parseVersion(hyphen[2]);
    return lo && hi ? cmp(target, lo) >= 0 && cmp(target, hi) <= 0 : null;
  }

  const tokens = clause.replace(/,/g, ' ').split(/\s+/).filter(Boolean);
  let unknown = false;
  for (const token of tokens) {
    const result = comparatorMatches(target, token);
    if (result === false) return false;
    if (result === null) unknown = true;
  }
  return unknown ? null : true;
}

function summarizeVersions(versions) {
  if (!versions.length) return '';
  if (versions.length <= 4) return versions.join(', ');
  return `${versions.slice(0, 4).join(', ')} and ${versions.length - 4} more`;
}

function evaluateSpec(packageName, spec) {
  const badVersions = IOCs.get(packageName);
  if (!badVersions || typeof spec !== 'string') {
    return { may: false, unknown: false, packageName, matched: [] };
  }

  let s = spec.trim();
  if (!s) return { may: true, unknown: true, packageName, matched: [] };

  if (s.startsWith('workspace:')) {
    s = s.slice('workspace:'.length);
    if (!s || s === '^' || s === '~') {
      return { may: true, unknown: true, packageName, matched: [] };
    }
  }

  if (/^(?:file:|link:|portal:|patch:|git(?:\+|:)|https?:|github:|bitbucket:|gitlab:|\$)/i.test(s)) {
    return { may: true, unknown: true, packageName, matched: [] };
  }

  let sawUnknown = false;
  const matched = [];
  for (const badVersion of badVersions) {
    const target = parseVersion(badVersion);
    if (!target) {
      sawUnknown = true;
      continue;
    }
    let versionUnknown = false;
    let versionMatched = false;
    for (const clause of s.split('||')) {
      const result = clauseMayMatch(target, clause);
      if (result === true) {
        versionMatched = true;
        break;
      }
      if (result === null) versionUnknown = true;
    }
    if (versionMatched) matched.push(badVersion);
    else if (versionUnknown) sawUnknown = true;
  }

  return {
    may: matched.length > 0 || sawUnknown,
    unknown: matched.length === 0 && sawUnknown,
    packageName,
    matched
  };
}

function parseNpmAlias(spec) {
  if (typeof spec !== 'string' || !spec.startsWith('npm:')) return null;
  const rest = spec.slice(4);
  const splitAt = rest.lastIndexOf('@');
  if (splitAt <= 0) return null;
  return { packageName: rest.slice(0, splitAt), spec: rest.slice(splitAt + 1) };
}

function inspectDependencySpec(declaredName, spec, file, label) {
  let packageName = declaredName;
  let effectiveSpec = spec;
  const alias = parseNpmAlias(spec);
  if (alias && IOCs.has(alias.packageName)) {
    packageName = alias.packageName;
    effectiveSpec = alias.spec;
  } else if (!IOCs.has(packageName)) {
    return;
  }

  const result = evaluateSpec(packageName, effectiveSpec);
  if (!result.may) return;

  let detail;
  if (result.unknown) {
    detail = `${label} ${declaredName}=${JSON.stringify(spec)} references IOC package ${packageName} but cannot be proven safe`;
  } else {
    detail = `${label} ${declaredName}=${JSON.stringify(spec)} can select malicious ${packageName}@${summarizeVersions(result.matched)}`;
  }
  add(risky, file, detail);
}

function packageFromSelectorKey(key) {
  const candidate = String(key).trim();
  if (!candidate || candidate === '.') return null;

  // Supports npm override keys (pkg, pkg@range, parent>pkg), Yarn resolution
  // keys (**/pkg, parent/pkg), and scoped package names.
  const names = [...IOCs.keys()].sort((a, b) => b.length - a.length);
  for (const name of names) {
    let index = candidate.lastIndexOf(name);
    while (index !== -1) {
      const before = index === 0 ? '' : candidate[index - 1];
      const after = candidate.slice(index + name.length);
      const validBefore = index === 0 || before === '>' || before === '/';
      const validAfter = after === '' || after.startsWith('@');
      if (validBefore && validAfter) return name;
      index = candidate.lastIndexOf(name, index - 1);
    }
  }
  return null;
}

function inspectOverrideObject(obj, file, trail = []) {
  if (!obj || typeof obj !== 'object') return;
  for (const [key, value] of Object.entries(obj)) {
    const packageName = packageFromSelectorKey(key);
    if (packageName) {
      if (typeof value === 'string') {
        inspectDependencySpec(packageName, value, file, trail.concat(key).join('.'));
      } else if (value && typeof value === 'object' && typeof value['.'] === 'string') {
        inspectDependencySpec(packageName, value['.'], file, trail.concat(key, '.').join('.'));
      }
    }
    inspectOverrideObject(value, file, trail.concat(key));
  }
}

function isInNodeModules(file) {
  return file.replace(/\\/g, '/').includes('/node_modules/');
}

function checkExact(name, version, file, detail) {
  if (typeof name !== 'string' || typeof version !== 'string') return false;
  const versions = IOCs.get(name);
  if (!versions || !versions.has(version)) return false;
  add(confirmed, file, `${detail}: ${name}@${version}`);
  return true;
}

function inspectPackageJson(json, file) {
  if (!json || typeof json !== 'object') return;

  const installed = isInNodeModules(file);
  checkExact(json.name, json.version, file, installed ? 'installed malicious package' : 'package manifest declares malicious version');
  if (installed) return;

  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const section of sections) {
    const deps = json[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, spec] of Object.entries(deps)) {
      inspectDependencySpec(name, spec, file, section);
    }
  }

  inspectOverrideObject(json.overrides, file, ['overrides']);
  inspectOverrideObject(json.resolutions, file, ['resolutions']);
}

function inferPackageNameFromPathKey(key) {
  const normalized = String(key).replace(/\\/g, '/');
  const marker = 'node_modules/';
  const index = normalized.lastIndexOf(marker);
  if (index === -1) return null;
  const tail = normalized.slice(index + marker.length);
  const parts = tail.split('/').filter(Boolean);
  if (!parts.length) return null;
  const name = parts[0].startsWith('@') && parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0];
  return IOCs.has(name) ? name : null;
}

function inspectLockJson(node, trail, file, contextName = null, seen = new Set()) {
  if (!node || typeof node !== 'object' || seen.has(node)) return;
  seen.add(node);

  if (typeof node.name === 'string' && typeof node.version === 'string') {
    checkExact(node.name, node.version, file, `resolved malicious package in JSON lockfile (${trail.join(' > ') || 'root'})`);
  }
  if (contextName && typeof node.version === 'string') {
    checkExact(contextName, node.version, file, `resolved malicious package in JSON lockfile (${trail.join(' > ') || contextName})`);
  }

  for (const [key, value] of Object.entries(node)) {
    let childContext = inferPackageNameFromPathKey(key);
    if (!childContext && IOCs.has(key) && value && typeof value === 'object') {
      childContext = key;
    }
    inspectLockJson(value, trail.concat(key), file, childContext, seen);
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const packageAlternation = [...IOCs.keys()]
  .sort((a, b) => b.length - a.length)
  .map(escapeRegex)
  .join('|');
const directPairRegex = new RegExp(`(^|[^A-Za-z0-9._~@-])(${packageAlternation})@(?:npm:)?(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?)(?=$|[^0-9A-Za-z.+-])`, 'gm');
// pnpm lockfile v5 and older used /package/version-style keys.
const slashPairRegex = new RegExp(`(^|[\\s"'])/?(${packageAlternation})/(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?)(?=$|[\\s"':,)])`, 'gm');
const headerPackageRegex = new RegExp(`(?:^|["'\\s,])(${packageAlternation})@`, 'g');

function inspectTextLock(buffer, file, binaryLimited = false) {
  const text = buffer.toString('latin1');
  let match;
  directPairRegex.lastIndex = 0;
  while ((match = directPairRegex.exec(text)) !== null) {
    const name = match[2];
    const version = match[3];
    checkExact(name, version, file, binaryLimited ? 'binary lockfile signature contains malicious package' : 'lockfile contains malicious package');
  }

  slashPairRegex.lastIndex = 0;
  while ((match = slashPairRegex.exec(text)) !== null) {
    const name = match[2];
    const version = match[3];
    checkExact(name, version, file, binaryLimited ? 'binary lockfile signature contains malicious package' : 'legacy pnpm lock key contains malicious package');
  }

  if (!binaryLimited) {
    const lines = text.split(/\r?\n/);
    let activeNames = [];
    for (const line of lines) {
      if (/^\S/.test(line)) {
        activeNames = [];
        headerPackageRegex.lastIndex = 0;
        let headerMatch;
        while ((headerMatch = headerPackageRegex.exec(line)) !== null) {
          activeNames.push(headerMatch[1]);
        }
      }

      if (activeNames.length) {
        const versionMatch = line.match(/^\s+version\s*:?\s*["']?([^"'\s]+)["']?\s*$/);
        if (versionMatch) {
          for (const name of activeNames) {
            checkExact(name, versionMatch[1], file, 'Yarn lock block resolves malicious package');
          }
        }
      }
    }
  }

  if (binaryLimited) {
    addIncomplete(file, 'bun.lockb is binary; only exact package@version string signatures were checked');
  }
}

console.log(`Loaded ${IOCs.size} malicious package names and ${pairCount} exact package/version pairs from embedded IOC data.`);

for (const file of files) {
  scanned++;
  let buffer;
  try {
    buffer = fs.readFileSync(file);
  } catch (err) {
    addIncomplete(file, err.code || err.message);
    continue;
  }

  const base = path.basename(file);
  if (base === 'package.json' || base === 'package-lock.json' || base === 'npm-shrinkwrap.json') {
    try {
      const json = JSON.parse(buffer.toString('utf8'));
      if (base === 'package.json') {
        inspectPackageJson(json, file);
      } else {
        inspectLockJson(json, [], file);
        // Supplemental signature scan catches npm alias encodings such as
        // npm:package@version that do not always expose the target package name
        // as a separate JSON field.
        inspectTextLock(buffer, file, false);
      }
    } catch (err) {
      addIncomplete(file, `invalid/unreadable JSON (${err.message})`);
    }
  } else if (base === 'bun.lockb') {
    inspectTextLock(buffer, file, true);
  } else {
    inspectTextLock(buffer, file, false);
  }
}

console.log(`Scanned ${scanned} relevant manifest/lockfile(s).`);

if (confirmed.size) {
  console.log('\nCOMPROMISED PACKAGE VERSION(S) FOUND:');
  for (const { file, detail } of confirmed.values()) console.log(`  ${file}\n    ${detail}`);
}

if (risky.size) {
  console.log('\nUNSAFE OR UNVERIFIABLE PACKAGE DECLARATIONS:');
  for (const { file, detail } of risky.values()) console.log(`  ${file}\n    ${detail}`);
}

if (incomplete.length) {
  console.error('\nFiles that could not be fully checked:');
  for (const item of incomplete) console.error(`  ${item}`);
}

if (!confirmed.size && !risky.size) {
  if (incomplete.length) {
    console.log('\nNo embedded IOC package/version pair was found among fully readable data.');
  } else {
    console.log('No embedded IOC package/version pair was found.');
  }
}

if (confirmed.size || risky.size) process.exit(1);
if (incomplete.length) process.exit(2);
process.exit(0);
NODE
SCAN_STATUS=$?

COVERAGE_GAPS=0

if [[ -s "$FIND_ERRORS" ]]; then
  COVERAGE_GAPS=1
  echo >&2
  echo "Filesystem paths that could not be searched (scan continued):" >&2
  sed 's/^/  /' "$FIND_ERRORS" >&2
fi

if [[ $FIND_STATUS -ne 0 || $SCAN_STATUS -eq 2 ]]; then
  COVERAGE_GAPS=1
fi

# A detection always wins, even when other paths were unreadable.
if [[ $SCAN_STATUS -eq 1 ]]; then
  if ((COVERAGE_GAPS)); then
    echo >&2
    echo "WARNING: Findings were detected, and some paths/files also could not be fully checked." >&2
  fi
  exit 1
fi

# Any unexpected Node/scanner failure is fatal rather than being hidden by
# best-effort mode.
if [[ $SCAN_STATUS -ne 0 && $SCAN_STATUS -ne 2 ]]; then
  echo "ERROR: the manifest scanner failed with status $SCAN_STATUS." >&2
  exit 3
fi

if ((COVERAGE_GAPS)); then
  echo >&2
  if [[ "$MODE" == "strict" ]]; then
    echo "SCAN FINISHED WITH COVERAGE GAPS (STRICT MODE)." >&2
  else
    echo "BEST-EFFORT SCAN FINISHED WITH COVERAGE GAPS." >&2
  fi
  echo "No embedded IOC package/version pair was found in fully readable data," >&2
  echo "but unreadable or partially supported paths/files were not fully verified." >&2

  if [[ "$MODE" == "strict" ]]; then
    exit 2
  fi

  echo "Best-effort mode: returning success so coverage gaps do not stop the workflow." >&2
  exit 0
fi

echo "Scan finished with full readable coverage below: $ROOT"
exit 0

# shellcheck shell=bash
arrconf_diff() {
  local def="${REPO_ROOT}/arrconf/userconf.defaults.sh"
  local usr="${REPO_ROOT}/arrconf/userconf.sh"
  if [ ! -f "${def}" ]; then
    echo "Defaults not found at ${def}" >&2
    return 1
  fi
  if [ ! -f "${usr}" ]; then
    echo "No userconf.sh yet. Creating from defaults..."
    cp "${def}" "${usr}"
    echo "Edit ${usr} to override defaults."
    return 0
  fi
  echo "Comparing your overrides to new defaults:"
  diff -u "${def}" "${usr}" || true
}

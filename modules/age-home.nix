{
  config,
  options,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.age;

  ageBin = lib.getExe config.age.package;

  newGeneration = ''
    _agenix_generation="$(basename "$(readlink "${cfg.secretsDir}")" || echo 0)"
    (( ++_agenix_generation ))
    echo "[agenix] creating new generation in ${cfg.secretsMountPoint}/$_agenix_generation"
    mkdir -p "${cfg.secretsMountPoint}"
    chmod 0751 "${cfg.secretsMountPoint}"
    mkdir -p "${cfg.secretsMountPoint}/$_agenix_generation"
    chmod 0751 "${cfg.secretsMountPoint}/$_agenix_generation"
  '';

  setTruePath = secretType: ''
    ${
      if secretType.symlink then
        ''
          _truePath="${cfg.secretsMountPoint}/$_agenix_generation/${secretType.name}"
        ''
      else
        ''
          _truePath="${secretType.path}"
        ''
    }
  '';

  installSecret = secretType: ''
    ${setTruePath secretType}
    echo "decrypting '${secretType.file}' to '$_truePath'..."
    TMP_FILE="$_truePath.tmp"

    IDENTITIES=()
    # shellcheck disable=2043
    for identity in ${toString cfg.identityPaths}; do
      test -r "$identity" || continue
      IDENTITIES+=(-i)
      IDENTITIES+=("$identity")
    done

    test "''${#IDENTITIES[@]}" -eq 0 && echo "[agenix] WARNING: no readable identities found!"

    mkdir -p "$(dirname "$_truePath")"
    # shellcheck disable=SC2193,SC2050
    [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && mkdir -p "$(dirname "${secretType.path}")"
    (
      umask u=r,g=,o=
      test -f "${secretType.file}" || echo '[agenix] WARNING: encrypted file ${secretType.file} does not exist!'
      test -d "$(dirname "$TMP_FILE")" || echo "[agenix] WARNING: $(dirname "$TMP_FILE") does not exist!"
      LANG=${
        config.i18n.defaultLocale or "C"
      } ${ageBin} --decrypt "''${IDENTITIES[@]}" -o "$TMP_FILE" "${secretType.file}"
    )
    chmod ${secretType.mode} "$TMP_FILE"
    mv -f "$TMP_FILE" "$_truePath"

    ${optionalString secretType.symlink ''
      # shellcheck disable=SC2193,SC2050
      [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && ln -sfT "${cfg.secretsDir}/${secretType.name}" "${secretType.path}"
    ''}
  '';

  testIdentities = map (path: ''
    test -f ${path} || echo '[agenix] WARNING: config.age.identityPaths entry ${path} not present!'
  '') cfg.identityPaths;

  cleanupAndLink = ''
    _agenix_generation="$(basename "$(readlink "${cfg.secretsDir}")" || echo 0)"
    (( ++_agenix_generation ))
    echo "[agenix] symlinking new secrets to ${cfg.secretsDir} (generation $_agenix_generation)..."
    ln -sfT "${cfg.secretsMountPoint}/$_agenix_generation" "${cfg.secretsDir}"

    (( _agenix_generation > 1 )) && {
    echo "[agenix] removing old secrets (generation $(( _agenix_generation - 1 )))..."
    rm -rf "${cfg.secretsMountPoint}/$(( _agenix_generation - 1 ))"
    }
  '';

  installSecrets = builtins.concatStringsSep "\n" (
    [ "echo '[agenix] decrypting secrets...'" ]
    ++ testIdentities
    ++ (map installSecret (builtins.attrValues cfg.secrets))
    ++ [ cleanupAndLink ]
  );

  secretType = types.submodule (
    {
      config,
      name,
      ...
    }:
    {
      options = {
        name = mkOption {
          type = types.str;
          default = name;
          description = ''
            Name of the file used in ''${cfg.secretsDir}
          '';
        };
        file = mkOption {
          type = types.path;
          description = ''
            Age file the secret is loaded from.
          '';
        };
        path = mkOption {
          type = types.str;
          default = "${cfg.secretsDir}/${config.name}";
          description = ''
            Path where the decrypted secret is installed.
          '';
        };
        mode = mkOption {
          type = types.str;
          default = "0400";
          description = ''
            Permissions mode of the decrypted secret in a format understood by chmod.
          '';
        };
        symlink = mkEnableOption "symlinking secrets to their destination" // {
          default = true;
        };
      };
    }
  );

  mountingScript =
    let
      app = pkgs.writeShellApplication {
        name = "agenix-home-manager-mount-secrets";
        runtimeInputs = with pkgs; [ coreutils ];
        text = ''
          ${newGeneration}
          ${installSecrets}
          exit 0
        '';
      };
    in
    lib.getExe app;

  # Darwin-only wrapper: makes the home-manager launchd agent robust against
  # cold-boot ordering races on macOS. The strategy is "always try, retry
  # forever, exit non-zero on any failure so launchd reschedules us".
  #
  # Failure modes this handles:
  #   1. /nix/store not yet mounted when launchd fires the agent at login.
  #      The macOS nix store lives on a synthetic APFS volume that mounts
  #      asynchronously and re-mounts after the user session starts (via
  #      `nix-darwin` reactivation). wait4path blocks until /nix/store and
  #      our own script path resolve.
  #   2. ~/Library/Logs/agenix doesn't exist on first run, so launchd can't
  #      open StandardOutPath/StandardErrorPath and silently refuses to
  #      start the job.
  #   3. SSH identities not yet readable. On a FileVault-encrypted volume
  #      ~/.ssh/id_ed25519 can take a moment to become readable after login;
  #      we also start ssh-agent and ssh-add the identities so encrypted
  #      keys can be used for age decryption (age reads SSH identities via
  #      $SSH_AUTH_SOCK when the key on disk is passphrase-protected).
  #   4. Concurrent invocations from RunAtLoad + a manual `launchctl
  #      kickstart`. Two writers cannot share a generation directory.
  darwinWrapper = pkgs.writeShellApplication {
    name = "agenix-home-manager-mount-secrets-darwin";
    runtimeInputs = with pkgs; [ coreutils openssh ];
    text = ''
      set -u

      log_dir="${config.home.homeDirectory}/Library/Logs/agenix"
      mkdir -p "$log_dir" 2>/dev/null || true

      # 1. Wait for the nix store and our own script to actually exist.
      # wait4path is part of the macOS base system, so it's available even
      # before PATH is set up.
      if [ -x /bin/wait4path ]; then
        /bin/wait4path /nix/store >/dev/null 2>&1 || true
        /bin/wait4path "${mountingScript}" >/dev/null 2>&1 || true
      fi

      # 2. Serialize concurrent invocations using mkdir as a portable
      # atomic lock primitive (macOS has no flock(1)). Steal the lock if
      # the holder pid is gone (stale after a crash).
      lock_dir="$log_dir/.activate.lock"
      acquired=0
      for _ in $(seq 1 300); do
        if mkdir "$lock_dir" 2>/dev/null; then
          acquired=1
          break
        fi
        if [ -f "$lock_dir/pid" ]; then
          holder=$(cat "$lock_dir/pid" 2>/dev/null || echo "")
          if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
            rm -rf "$lock_dir" 2>/dev/null || true
            continue
          fi
        fi
        sleep 1
      done
      if [ "$acquired" != 1 ]; then
        echo "[agenix] could not acquire activation lock within 300s" >&2
        exit 1
      fi
      echo "$$" > "$lock_dir/pid" 2>/dev/null || true
      trap 'rm -rf "$lock_dir" 2>/dev/null || true' EXIT

      # 3. Wait for at least one identity to be readable. We exit non-zero
      # on timeout so launchd reschedules and tries again — this is the
      # "always try" property.
      identities=( ${toString cfg.identityPaths} )
      identity_ok=0
      for _ in $(seq 1 30); do
        for id in "''${identities[@]}"; do
          if [ -r "$id" ]; then
            identity_ok=1
            break 2
          fi
        done
        sleep 1
      done
      if [ "$identity_ok" != 1 ]; then
        echo "[agenix] no readable identity after 30s — will be retried by launchd" >&2
        exit 1
      fi

      # 4. Ensure an ssh-agent is available for passphrase-protected keys.
      # age can decrypt with ~/.ssh/id_ed25519 directly when the key is
      # plaintext, but if it's encrypted with a passphrase, age delegates
      # to ssh-agent via $SSH_AUTH_SOCK. We start a per-user agent socket
      # under the log dir, reuse it across runs, and try to add each
      # identity. Failures here are non-fatal: if the key is plaintext,
      # age will read it directly and the agent is unused; if the key is
      # encrypted and has no agent, we'll exit non-zero from age below
      # and launchd will retry.
      agent_env="$log_dir/ssh-agent.env"
      if [ -f "$agent_env" ]; then
        # shellcheck disable=SC1090
        . "$agent_env" >/dev/null 2>&1 || true
      fi
      if [ -z "''${SSH_AUTH_SOCK:-}" ] || ! ssh-add -l >/dev/null 2>&1; then
        if [ "''${SSH_AUTH_SOCK:-}" != "" ] && [ "$(ssh-add -l 2>&1)" = "Error connecting to agent: No such file or directory" ]; then
          unset SSH_AUTH_SOCK SSH_AGENT_PID
        fi
        if [ -z "''${SSH_AUTH_SOCK:-}" ]; then
          rm -f "$agent_env"
          ssh-agent -s > "$agent_env" 2>/dev/null || true
          # shellcheck disable=SC1090
          . "$agent_env" >/dev/null 2>&1 || true
        fi
      fi
      if [ -n "''${SSH_AUTH_SOCK:-}" ]; then
        for id in "''${identities[@]}"; do
          [ -r "$id" ] || continue
          ssh-add -l 2>/dev/null | grep -q "$(ssh-keygen -lf "$id" 2>/dev/null | awk '{print $2}')" && continue
          ssh-add "$id" </dev/null >/dev/null 2>&1 || true
        done
        export SSH_AUTH_SOCK
      fi

      # 5. Run the real mounting script. set -e in writeShellApplication
      # ensures any failure here propagates as a non-zero exit, which
      # triggers a launchd retry via KeepAlive.SuccessfulExit = false.
      "${mountingScript}"
    '';
  };

  darwinMountingScript = lib.getExe darwinWrapper;

  userDirectory =
    dir:
    let
      inherit (pkgs.stdenv.hostPlatform) isDarwin;
      baseDir =
        if isDarwin then "$(${lib.getExe pkgs.getconf} DARWIN_USER_TEMP_DIR)" else "\${XDG_RUNTIME_DIR}";
    in
    "${baseDir}/${dir}";

  userDirectoryDescription =
    dir:
    literalExpression ''
      "''${XDG_RUNTIME_DIR}"/''${dir} on linux or "$(getconf DARWIN_USER_TEMP_DIR)"/''${dir} on darwin.
    '';
in
{
  options.age = {
    package = mkPackageOption pkgs "age" { };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = ''
        Attrset of secrets.
      '';
    };

    identityPaths = mkOption {
      type = types.listOf types.path;
      default = [
        "${config.home.homeDirectory}/.ssh/id_ed25519"
        "${config.home.homeDirectory}/.ssh/id_rsa"
      ];
      defaultText = literalExpression ''
        [
          "''${config.home.homeDirectory}/.ssh/id_ed25519"
          "''${config.home.homeDirectory}/.ssh/id_rsa"
        ]
      '';
      description = ''
        Path to SSH keys to be used as identities in age decryption.
      '';
    };

    secretsDir = mkOption {
      type = types.str;
      default = userDirectory "agenix";
      defaultText = userDirectoryDescription "agenix";
      description = ''
        Folder where secrets are symlinked to
      '';
    };

    secretsMountPoint = mkOption {
      default = userDirectory "agenix.d";
      defaultText = userDirectoryDescription "agenix.d";
      description = ''
        Where secrets are created before they are symlinked to ''${cfg.secretsDir}
      '';
    };
  };

  config = mkIf (cfg.secrets != { }) {
    assertions = [
      {
        assertion = cfg.identityPaths != [ ];
        message = "age.identityPaths must be set.";
      }
    ];

    systemd.user.services.agenix = lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
      Unit = {
        Description = "agenix activation";
      };
      Service = {
        Type = "oneshot";
        ExecStart = mountingScript;
      };
      Install.WantedBy = [ "default.target" ];
    };

    launchd.agents.activate-agenix = lib.mkIf pkgs.stdenv.hostPlatform.isDarwin {
      enable = true;
      config = {
        ProgramArguments = [ darwinMountingScript ];
        # Oneshot semantics: do not relaunch on success, do relaunch on
        # non-zero exit so transient failures (FileVault not yet unlocked,
        # nix store not yet mounted, identity not yet readable) self-heal.
        KeepAlive = {
          SuccessfulExit = false;
        };
        RunAtLoad = true;
        ProcessType = "Background";
        # Default ExitTimeOut is 20s, which is far too short for cold boot
        # under load with many secrets. ThrottleInterval defaults to 10s,
        # which is fine but we set it explicitly so it's reviewable.
        ExitTimeOut = 300;
        ThrottleInterval = 10;
        StandardOutPath = "${config.home.homeDirectory}/Library/Logs/agenix/stdout";
        StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/agenix/stderr";
        EnvironmentVariables = {
          PATH = "/usr/bin:/bin:/usr/sbin:/sbin";
        };
      };
    };
  };
}

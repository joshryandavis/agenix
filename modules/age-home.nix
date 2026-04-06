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
  # cold-boot ordering races. Without this, the agent commonly fails on macOS
  # because: (1) /nix/store isn't mounted yet when launchd fires the job,
  # (2) ~/Library/Logs/agenix doesn't exist so launchd can't open the log
  # files and gives up before ExecStart runs, (3) two activation paths can
  # race (RunAtLoad + a manual `launchctl kickstart`) and corrupt the
  # generation directory, (4) SSH identities on a FileVault volume may not
  # be readable for the first few seconds after login.
  darwinWrapper = pkgs.writeShellApplication {
    name = "agenix-home-manager-mount-secrets-darwin";
    runtimeInputs = with pkgs; [ coreutils ];
    text = ''
      set -u

      log_dir="${config.home.homeDirectory}/Library/Logs/agenix"
      mkdir -p "$log_dir" 2>/dev/null || true

      # Wait for the nix store to be mounted before doing anything that
      # references a /nix/store path. wait4path is part of the macOS base
      # system, so we can rely on it being present even before PATH is set.
      if [ -x /bin/wait4path ]; then
        /bin/wait4path /nix/store >/dev/null 2>&1 || true
        /bin/wait4path "${mountingScript}" >/dev/null 2>&1 || true
      fi

      # Serialize concurrent invocations (RunAtLoad + manual kickstart)
      # so they cannot race on the generation directory. macOS does not
      # ship flock(1), so we use mkdir as a portable atomic lock primitive
      # and clean up on exit.
      lock_dir="$log_dir/.activate.lock"
      acquired=0
      for _ in $(seq 1 300); do
        if mkdir "$lock_dir" 2>/dev/null; then
          acquired=1
          break
        fi
        # Steal the lock if the holding pid is gone (stale after a crash).
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

      # Wait briefly for at least one identity to become readable. On a
      # FileVault-encrypted volume the SSH key may not be readable for a
      # second or two after login.
      identities=( ${toString cfg.identityPaths} )
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        for id in "''${identities[@]}"; do
          if [ -r "$id" ]; then
            break 2
          fi
        done
        sleep 1
      done

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

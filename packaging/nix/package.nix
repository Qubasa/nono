{
  lib,
  stdenv,
  rustPlatform,
  src,
  cmake,
  pkg-config,
  versionCheckHook,
}:

rustPlatform.buildRustPackage {
  pname = "nono";
  version = "0.62.0";

  inherit src;

  cargoLock.lockFile = "${src}/Cargo.lock";

  # aws-lc-sys (transitive via sigstore/rustls) builds its vendored C sources
  # with cmake. pkg-config locates host libraries for the same crates.
  nativeBuildInputs = [
    cmake
    pkg-config
  ];

  # Workspace tests need a Landlock-capable kernel and write to real paths,
  # so they do not run inside the Nix build sandbox.
  doCheck = false;

  doInstallCheck = true;
  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgram = "${placeholder "out"}/bin/nono";
  versionCheckProgramArg = "--version";

  meta = {
    description = "Kernel-enforced agent sandbox with capability-based isolation, secure key management, atomic rollback, and a cryptographic audit chain";
    homepage = "https://nono.sh/";
    changelog = "https://github.com/always-further/nono/releases/tag/v0.62.0";
    license = lib.licenses.asl20;
    sourceProvenance = [ lib.sourceTypes.fromSource ];
    mainProgram = "nono";
    platforms = lib.platforms.unix;
  };
}

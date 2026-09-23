{
  description = "Per-secret sharing and discovery with SOPS, age, and GitHub";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # Unstable no longer supports Intel macOS; use its maintained 26.05 branch.
  inputs.nixpkgs-intel-darwin.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  outputs = { self, nixpkgs, nixpkgs-intel-darwin }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
      forSystem = system:
        let
          source = if system == "x86_64-darwin" then nixpkgs-intel-darwin else nixpkgs;
          pkgs = import source { inherit system; };
          runtime = with pkgs; [ sops age ssh-to-age openssh git gh ];
          app = pkgs.python3Packages.buildPythonApplication {
            pname = "github-secrets";
            version = "0.1.0";
            pyproject = true;
            src = self;
            build-system = [ pkgs.python3Packages.setuptools ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            nativeCheckInputs = runtime;
            pythonImportsCheck = [ "github_secrets" ];
            checkPhase = ''
              runHook preCheck
              PYTHONPATH=src python -m unittest discover -s tests -v
              runHook postCheck
            '';
            postFixup = ''
              wrapProgram $out/bin/secrets --prefix PATH : ${pkgs.lib.makeBinPath runtime}
            '';
            meta = {
              description = "Discover and share individually encrypted secrets on GitHub";
              license = pkgs.lib.licenses.gpl3Only;
              mainProgram = "secrets";
            };
          };
        in { inherit pkgs runtime app; };
    in {
      packages = eachSystem (system: { default = (forSystem system).app; });
      apps = eachSystem (system: {
        default = { type = "app"; program = "${(forSystem system).app}/bin/secrets"; meta = (forSystem system).app.meta; };
      });
      checks = eachSystem (system: { default = (forSystem system).app; });
      devShells = eachSystem (system:
        let env = forSystem system; in {
          default = env.pkgs.mkShell { packages = env.runtime ++ [ env.pkgs.python3 ]; };
        });
    };
}

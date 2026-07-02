import Config

config :ca,
  enabled: [:issuer, :wallet, :verifier, :est, :cmp, :cmc, :ocsp, :tsp],
  issuer: 8107,
  wallet: 8108,
  verifier: 8109,
  est: 8047,
  cmp: 8829,
  cmc: 5318,
  mad: 8088,
  ocsp: 8020,
  tsp: 8021,
  ldap: 8389,
  logger_level: :info,
  key_backend: {:software, "synrc/ecc/secp384r1/se/ca.key"},
  # macOS T2/M-series Secure Enclave backend (auto-detected at startup if se.label exists):
  # key_backend: {:secure_enclave, "synrc.ca.secp384r1"},
  profiles: ["secp384r1", "secp256k1", "secp521r1"],
  logger: [
    {:handler, :default2, :logger_std_h,
     %{
       level: :info,
       id: :synrc,
       max_size: 2000,
       module: :logger_std_h,
       config: %{type: :file, file: ~c"ca.log"},
       formatter:
         {:logger_formatter, %{template: [:time, ~c" ", :pid, ~c" ", :module, ~c" ", :msg, ~c"\n"], single_line: true}}
     }}
  ]

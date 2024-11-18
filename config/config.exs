import Config

config :ca,
  issuer:   8107,
  wallet:   8108,
  verifier: 8109,
  est:  8047,
  cmp:  8829,
  cmc:  5318,
  mad:  8088,
  ocsp: 8020,
  tsp:  8021,
  ldap: 8389,
  logger_level: :info,
  logger: [{:handler, :default2, :logger_std_h,
            %{level: :info,
              id: :synrc,
              max_size: 2000,
              module: :logger_std_h,
              config: %{type: :file, file: 'ca.log'},
              formatter: {:logger_formatter,
                          %{template: [:time,' ',:pid,' ',:module,' ',:msg,'\n'],
                            single_line: true,}}}}]


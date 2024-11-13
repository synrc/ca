import Config

config :ca,
  est:  8047,
  cmp:  8829,
  mad:  8088,
  ocsp: 1000,
  tsp:  1001,
  ldap: 1389,
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


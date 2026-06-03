defmodule CA.Sys do
  @moduledoc """
  Карта систем і програмного забезпечення (Software Asset Taxonomy).
  Класифікує ОС, СУБД, інфраструктурне та прикладне ПЗ.
  """

  @doc """
  Перелік програмних активів, які вимагають специфічних контролів захисту.
  """
  def inventory do
    %{
      os: [
        %{id: "SYS-OS-01", name: "Серверні ОС (Linux, Windows Server)", controls: ["CM", "SI", "AC"]},
        %{id: "SYS-OS-02", name: "Клієнтські ОС (Windows 11, macOS)", controls: ["CM", "SI", "AC"]}
      ],
      db: [
        %{id: "SYS-DB-01", name: "Реляційні СУБД (PostgreSQL, Oracle)", controls: ["SC", "AC", "AU", "CP"]},
        %{id: "SYS-DB-02", name: "NoSQL та кеші (Redis, MongoDB)", controls: ["SC", "AC", "AU"]}
      ],
      middleware: [
        %{id: "SYS-MW-01", name: "Веб-сервери та балансувальники (Nginx, HAProxy)", controls: ["SC", "CM", "AU"]},
        %{id: "SYS-MW-02", name: "Сервіси каталогів (Active Directory, FreeIPA)", controls: ["IA", "AC", "SC"]}
      ],
      app: [
        %{id: "SYS-APP-01", name: "Програмні комплекси ЦСК (Сайфер, ІІТ)", controls: ["SI", "SC", "AU", "CP"]},
        %{id: "SYS-APP-02", name: "Системи моніторингу та логування (SIEM, Zabbix)", controls: ["AU", "IR"]}
      ]
    }
  end
end

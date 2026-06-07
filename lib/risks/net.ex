defmodule CA.Net do
  @moduledoc """
  Карта мережевої топології та зонування (Network Zoning).
  На базі концепцій Defense-in-Depth.
  """

  @doc """
  Перелік мережевих сегментів та зон з відповідними контролями.

  Джерело: NIST SP 800-41 (Guidelines on Firewalls and Firewall Policy), концепції Zero Trust Architecture.
  Завдання: Описати типи зон (DMZ, Air-gapped, Management VLAN).
  """
  def zones do
    %{
      dmz: %{
        id: "Z-DMZ",
        name: "Демілітаризована зона (DMZ)",
        desc: "Сервери, доступні з інтернету (Web, OCSP, CRL endpoints).",
        controls: ["SC", "AU", "AC"]
      },
      internal: %{
        id: "Z-INT",
        name: "Внутрішня мережа",
        desc: "Сервери баз даних, внутрішні портали, робочі станції операторів.",
        controls: ["SC", "AC", "PE"]
      },
      management: %{
        id: "Z-MGT",
        name: "Мережа управління (OOB Management)",
        desc: "Виділений VLAN для адміністрування (SSH, IPMI) без прямого доступу з інших мереж.",
        controls: ["IA", "AC", "SC", "AU"]
      },
      air_gapped: %{
        id: "Z-AIR",
        name: "Ізольоване середовище (Air-gapped)",
        desc: "Офлайн-Вузол ЦСК (Кореневий ЦСК), фізично відключений від мереж передачі даних.",
        controls: ["PE", "MP", "AC", "CM"]
      }
    }
  end
end

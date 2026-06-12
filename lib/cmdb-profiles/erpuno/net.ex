defmodule CA.Net do
  @moduledoc """
  Карта мережевої топології та зонування (Network Zoning).
  На базі концепцій Defense-in-Depth та NIST SP 800-41.
  Уніфікована 2-рівнева структура: група -> :instances.
  """

  @doc """
  Перелік мережевих сегментів та зон з відповідними контролями.
  """
  def zones do
    %{
      zones: [
        %{
          id: "NET-DMZ",
          name: "Демілітаризована зона (DMZ)",
          desc: "Сервери, доступні з інтернету (Web, OCSP, CRL endpoints).",
          controls: ["SC", "AU", "AC"],
          instances: [
            %{id: "NET-DMZ-01", name: "OCSP / CRL публічний ендпоінт", subnet: "публічна підмережа"},
            %{id: "NET-DMZ-02", name: "Веб-портал ЦСК", subnet: "публічна підмережа"}
          ]
        },
        %{
          id: "NET-INT",
          name: "Внутрішня мережа",
          desc: "Сервери баз даних, внутрішні портали, робочі станції операторів.",
          controls: ["SC", "AC", "PE"],
          instances: [
            %{id: "NET-INT-01", name: "Сегмент серверів БД", subnet: "внутрішня підмережа БД"},
            %{id: "NET-INT-02", name: "Сегмент робочих станцій операторів", subnet: "внутрішня підмережа АРМ"}
          ]
        },
        %{
          id: "NET-MGT",
          name: "Мережа управління (OOB Management)",
          desc: "Виділений VLAN для адміністрування (SSH, IPMI) без прямого доступу з інших мереж.",
          controls: ["IA", "AC", "SC", "AU"],
          instances: [
            %{id: "NET-MGT-01", name: "VLAN IPMI / iLO адміністрування", subnet: "management VLAN"}
          ]
        },
        %{
          id: "NET-AIR",
          name: "Ізольоване середовище (Air-gapped)",
          desc: "Офлайн-Вузол ЦСК (Кореневий ЦСК), фізично відключений від мереж.",
          controls: ["PE", "MP", "AC", "CM"],
          instances: [
            %{id: "NET-AIR-01", name: "Кореневий ЦСК (офлайн вузол)", subnet: "N/A"}
          ]
        }
      ]
    }
  end
end

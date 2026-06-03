defmodule CA.HW do
  @moduledoc """
  Карта апаратного забезпечення (Hardware Inventory Taxonomy).
  Визначає фізичні та віртуальні ресурси та автоматично підтягує
  вимоги до їх захисту згідно NIST SP 800-53 (контролі PE, MP, SC).
  """

  @doc """
  Перелік апаратних активів, згрупований за класами обладнання.

  Джерело: NIST SP 800-53 (Control CM-8: System Component Inventory), NIST Cybersecurity Framework (ID.AM - Asset Management).
  Завдання: Визначити стандартизовані категорії обладнання (СЗД, Сервери, КЗІ, Мережеве обладнання, Мобільні пристрої) та ПЗ (ОС, СУБД, Middleware, Клієнтські додатки).

  """
  def inventory do
    %{
      servers: [
        %{id: "HW-SRV-01", name: "Фізичні сервери (On-Premise)", controls: ["PE", "CP", "CM"]},
        %{id: "HW-SRV-02", name: "Віртуальні машини / Гіпервізори", controls: ["SC", "CM", "SI"]}
      ],
      kzi: [
        %{
          id: "HW-KZI-01",
          name: "Апаратні криптомодулі (HSM / Гряда)",
          controls: ["PE", "MP", "SC", "IA"]
        },
        %{
          id: "HW-KZI-02",
          name: "Захищені носії ключової інформації (е-Токени, Смарт-карти)",
          controls: ["MP", "PE", "IA"]
        }
      ],
      network: [
        %{
          id: "HW-NET-01",
          name: "Маршрутизатори та комутатори ядра",
          controls: ["SC", "CM", "PE"]
        },
        %{
          id: "HW-NET-02",
          name: "Міжмережеві екрани (Firewalls, IDS/IPS)",
          controls: ["SC", "AU", "CM"]
        }
      ],
      endpoints: [
        %{
          id: "HW-END-01",
          name: "Робочі станції операторів / адміністраторів",
          controls: ["PE", "AC", "SI"]
        },
        %{id: "HW-END-02", name: "Мобільні пристрої", controls: ["AC", "SC", "MP"]}
      ]
    }
  end
end

defmodule CA.ABAC do
  @moduledoc """
  Карта ролей і правил управління доступом (ABAC / RBAC).
  Розроблена на базі NIST SP 800-162 та НД ТЗІ.
  Уніфікована 2-рівнева структура: група -> :instances.
  """

  @doc """
  Структурований перелік системних та людських ролей.

  Джерело: NIST SP 800-162 (Guide to Attribute Based Access Control), NIST SP 800-92.
  """
  def roles do
    %{
      roles: [
        %{
          id: "ROLE-ADM",
          name: "Адміністратори безпеки",
          desc: "Повний контроль над конфігурацією систем захисту, але без доступу до бізнес-даних.",
          controls: ["AC", "IA", "AU"],
          instances: [
            %{
              id: "ROLE-ADM-01",
              name: "Адміністратор безпеки",
              users: ["security_admin"]
            }
          ]
        },
        %{
          id: "ROLE-AUD",
          name: "Аудитори",
          desc: "Право на читання журналів подій та конфігурацій (Read-Only).",
          controls: ["AU", "AC"],
          instances: [
            %{
              id: "ROLE-AUD-01",
              name: "Аудитор",
              users: ["auditor"]
            }
          ]
        },
        %{
          id: "ROLE-OPR",
          name: "Оператори реєстрації",
          desc: "Права на генерацію запитів на сертифікати, перевірку документів підписників.",
          controls: ["AC", "IA"],
          instances: [
            %{
              id: "ROLE-OPR-01",
              name: "Оператор реєстрації",
              users: ["reg_operator"]
            }
          ]
        },
        %{
          id: "ROLE-SYS",
          name: "Системні процеси (M2M)",
          desc: "Автоматичні сервіси (OCSP-респондер, CRL-генератор).",
          controls: ["SC", "IA"],
          instances: [
            %{
              id: "ROLE-SYS-01",
              name: "Системний процес (Machine-to-Machine)",
              users: ["ocsp_service", "crl_generator"]
            }
          ]
        },
        %{
          id: "ROLE-SADM",
          name: "Суперадміністратори інфраструктури",
          desc: "Повний привілейований доступ до всіх систем (root/administrator).",
          controls: ["AC", "IA", "AU", "PE"],
          instances: [
            %{
              id: "ROLE-SADM-01",
              name: "Глобальний суперадміністратор (root/administrator)",
              users: ["global_root_admin", "infra_super_user"]
            }
          ]
        }
      ]
    }
  end

  @doc """
  Політики управління доступом на основі атрибутів.
  """
  def policies do
    %{
      "POL-01" => "Багатофакторна автентифікація (MFA) обов'язкова для ROLE-ADM.",
      "POL-02" => "ROLE-OPR може створювати запити лише в межах своєї локації (Location-based ABAC).",
      "POL-03" => "Доступ до систем керування ключами вимагає 'Правила двох осіб' (Dual Control / Split Knowledge)."
    }
  end
end

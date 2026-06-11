defmodule CA.ABAC do
  @moduledoc """
  Карта ролей і правил управління доступом (ABAC / RBAC).
  Розроблена на базі NIST SP 800-162 та НД ТЗІ.
  """

  @doc """
  Структурований перелік системних та людських ролей.

  Джерело: NIST SP 800-162 (Guide to Attribute Based Access Control), NIST SP 800-92 (Access Control).
  Завдання: Сформувати матрицю ABAC/RBAC, включаючи типові ролі ЦСК (Адміністратор безпеки, Аудитор, Оператор реєстрації) та їхні атрибути доступу.
  """
  def roles do
    %{
      admin: %{
        id: "R-ADM",
        name: "Адміністратор безпеки",
        desc:
          "Повний контроль над конфігурацією систем захисту, але без доступу до бізнес-даних.",
        permissions: ["manage:firewall", "manage:audit", "manage:roles"],
        controls: ["AC", "IA", "AU"]
      },
      auditor: %{
        id: "R-AUD",
        name: "Аудитор",
        desc: "Право на читання журналів подій та конфігурацій (Read-Only).",
        permissions: ["read:audit", "read:config"],
        controls: ["AU", "AC"]
      },
      operator: %{
        id: "R-OPR",
        name: "Оператор реєстрації",
        desc: "Права на генерацію запитів на сертифікати, перевірку документів підписників.",
        permissions: ["create:certificate_request", "read:subscriber_data"],
        controls: ["AC", "IA"]
      },
      system: %{
        id: "R-SYS",
        name: "Системний процес (Machine-to-Machine)",
        desc: "Автоматичні сервіси (OCSP-респондер, CRL-генератор).",
        permissions: ["sign:ocsp", "sign:crl"],
        controls: ["SC", "IA"]
      }
    }
  end

  @doc """
  Політики управління доступом на основі атрибутів.
  """
  def policies do
    %{
      "POL-01" => "Багатофакторна автентифікація (MFA) обов'язкова для R-ADM.",
      "POL-02" => "R-OPR може створювати запити лише в межах своєї локації (Location-based ABAC).",
      "POL-03" => "Доступ до систем керування ключами вимагає 'Правила двох осіб' (Dual Control / Split Knowledge)."
    }
  end
end

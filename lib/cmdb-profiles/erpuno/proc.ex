defmodule CA.Proc do
  @moduledoc """
  Карта бізнес-процесів (Business Process Criticality).
  Дозволяє визначати вимоги до резервного копіювання (CP)
  на основі RTO (Recovery Time Objective) та RPO (Recovery Point Objective).
  """

  @doc """
  Перелік критичних процесів та їхніх параметрів доступності.

  Джерело: NIST SP 800-34 (Contingency Planning Guide).
  Завдання: Формування параметрів RTO/RPO та їх вплив на Availability controls.
  """
  def processes do
    %{
      certificate_issuance: %{
        id: "P-ISSUE",
        name: "Видача сертифікатів",
        desc: "Процес обробки CSR та формування підписаного сертифіката.",
        criticality: :high,
        rto_hours: 4,
        rpo_hours: 1,
        controls: ["CP", "SI"]
      },
      ocsp_response: %{
        id: "P-OCSP",
        name: "Формування OCSP-відповідей",
        desc: "Надання інформації про статус сертифіката в реальному часі.",
        criticality: :critical,
        # HA cluster
        rto_hours: 0,
        rpo_hours: 0,
        controls: ["CP", "SC"]
      },
      audit_logging: %{
        id: "P-AUDIT",
        name: "Логування та моніторинг",
        desc: "Запис подій безпеки у централізоване сховище (SIEM).",
        criticality: :high,
        rto_hours: 24,
        rpo_hours: 0,
        controls: ["AU", "CP"]
      },
      root_key_ceremony: %{
        id: "P-ROOT",
        name: "Церемонія генерації кореневого ключа",
        desc: "Рідкісний, але гіперкритичний офлайн-процес.",
        criticality: :critical,
        rto_hours: 72,
        rpo_hours: 0,
        controls: ["PE", "AC", "PS", "AU"]
      },
      document_management: %{
        id: "P-DOC",
        name: "Електронний документообіг (Судові справи)",
        desc: "Обробка, зберігання та обіг електронних судових документів, ухвал, рішень.",
        criticality: :high,
        rto_hours: 8,
        rpo_hours: 2,
        controls: ["SI", "AC", "CP", "AU"]
      },
      backup_process: %{
        id: "P-BKP",
        name: "Резервне копіювання та відновлення",
        desc: "Процес створення, верифікації та безпечного зберігання бекапів.",
        criticality: :critical,
        rto_hours: 24,
        rpo_hours: 0,
        controls: ["CP", "MP", "SI"]
      }
    }
  end
end

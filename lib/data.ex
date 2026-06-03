defmodule CA.Data do
  @moduledoc """
  Карта класифікації даних та інформаційних активів.
  На базі FIPS 199 (CIA Triad: Confidentiality, Integrity, Availability) та законодавства України.
  """

  @doc """
  Класифікація інформаційних масивів системи.

  Джерело: FIPS 199 (Standards for Security Categorization of Federal Information), GDPR, Закон України "Про захист персональних даних".
  Завдання: Розробити матрицю класифікації (Публічна, Внутрішня, Конфіденційна, Таємна, Персональні дані, Ключові дані ЦСК) та рівні впливу (High, Moderate, Low).

  """
  def classification do
    %{
      public: %{
        id: "D-PUB",
        name: "Публічна інформація",
        desc: "Дані, розкриття яких не несе ризиків (публічні сертифікати, CRL, політики ЦСК).",
        impact: %{confidentiality: :low, integrity: :high, availability: :high},
        controls: ["SI", "CP"]
      },
      pii: %{
        id: "D-PII",
        name: "Персональні дані",
        desc: "Паспортні дані, РНОКПП, адреси підписників.",
        impact: %{confidentiality: :high, integrity: :high, availability: :medium},
        controls: ["SC", "AC", "PE", "AU"]
      },
      internal: %{
        id: "D-INT",
        name: "Службова інформація",
        desc: "Внутрішні накази, конфігураційні файли, журнали аудиту.",
        impact: %{confidentiality: :medium, integrity: :high, availability: :high},
        controls: ["AC", "AU", "CM"]
      },
      secret_key: %{
        id: "D-KEY",
        name: "Ключова інформація",
        desc: "Особисті ключі ЦСК, сесійні ключі шифрування, паролі адміністраторів.",
        impact: %{confidentiality: :high, integrity: :high, availability: :high},
        # Найсуворіший захист
        controls: ["SC", "PE", "MP", "IA"]
      },
      court_docs: %{
        id: "D-CRT",
        name: "Електронні судові справи",
        desc: "Матеріали судових проваджень, ухвали, рішення, докази (в т.ч. з обмеженим доступом).",
        impact: %{confidentiality: :high, integrity: :high, availability: :high},
        controls: ["AC", "SC", "SI", "CP"]
      },
      backups: %{
        id: "D-BKP",
        name: "Резервні копії (Backups)",
        desc: "Снапшоти баз даних, образи ВМ, архіви судових документів.",
        impact: %{confidentiality: :high, integrity: :high, availability: :high},
        controls: ["CP", "MP", "PE", "SC"]
      }
    }
  end
end

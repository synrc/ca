defmodule CA.Data do
  @moduledoc """
  Карта класифікації даних та інформаційних активів.
  На базі FIPS 199 (CIA Triad) та законодавства України.
  Уніфікована 2-рівнева структура: група -> :instances.
  """

  @doc """
  Класифікація інформаційних масивів системи.

  Джерело: FIPS 199, GDPR, Закон України "Про захист персональних даних".
  """
  def classification do
    %{
      classifications: [
        %{
          id: "DATA-PUB",
          name: "Публічна інформація",
          desc: "Дані, розкриття яких не несе ризиків (публічні сертифікати, CRL, політики ЦСК).",
          controls: ["SI", "CP"],
          instances: [
            %{id: "DATA-PUB-01", name: "Публічні сертифікати та CRL", storage: "Public CDN / web server"},
            %{id: "DATA-PUB-02", name: "Політики ЦСК (CPS, CP)", storage: "Public web server"}
          ]
        },
        %{
          id: "DATA-PII",
          name: "Персональні дані",
          desc: "Паспортні дані, РНОКПП, адреси підписників.",
          controls: ["SC", "AC", "PE", "AU"],
          instances: [
            %{id: "DATA-PII-01", name: "Реєстр підписників (паспорти, РНОКПП)", storage: "Encrypted DB (PostgreSQL)"},
            %{id: "DATA-PII-02", name: "Адресні та контактні дані підписників", storage: "Encrypted DB (PostgreSQL)"}
          ]
        },
        %{
          id: "DATA-INT",
          name: "Службова інформація",
          desc: "Внутрішні накази, конфігураційні файли, журнали аудиту.",
          controls: ["AC", "AU", "CM"],
          instances: [
            %{id: "DATA-INT-01", name: "Внутрішні накази та регламенти", storage: "Internal file server"},
            %{id: "DATA-INT-02", name: "Журнали аудиту (SIEM logs)", storage: "SIEM (Elasticsearch)"}
          ]
        },
        %{
          id: "DATA-KEY",
          name: "Ключова інформація",
          desc: "Особисті ключі ЦСК, сесійні ключі шифрування, паролі адміністраторів.",
          controls: ["SC", "PE", "MP", "IA"],
          instances: [
            %{id: "DATA-KEY-01", name: "Кореневі та підпорядковані ключі ЦСК", storage: "HSM (Гряда / IIT)"},
            %{id: "DATA-KEY-02", name: "Паролі та секрети адміністраторів", storage: "Password Manager (Vault)"}
          ]
        },
        %{
          id: "DATA-CRT",
          name: "Електронні судові справи",
          desc: "Матеріали судових проваджень, ухвали, рішення, докази.",
          controls: ["AC", "SC", "SI", "CP"],
          instances: [
            %{id: "DATA-CRT-01", name: "Матеріали судових проваджень та ухвали", storage: "Encrypted DB (Oracle / PostgreSQL)"},
            %{id: "DATA-CRT-02", name: "Електронні докази (обмежений доступ)", storage: "Encrypted storage (Scality RING)"}
          ]
        },
        %{
          id: "DATA-BKP",
          name: "Резервні копії",
          desc: "Снапшоти баз даних, образи ВМ, архіви судових документів.",
          controls: ["CP", "MP", "PE", "SC"],
          instances: [
            %{id: "DATA-BKP-01", name: "Снапшоти БД та образи ВМ", storage: "Tape Library (MSL3040)"},
            %{id: "DATA-BKP-02", name: "Офлайн-архіви судових документів", storage: "Air-gapped Tape (offline)"}
          ]
        }
      ]
    }
  end
end

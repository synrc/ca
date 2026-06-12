defmodule CA.Proc do
  @moduledoc """
  Карта бізнес-процесів (Business Process Criticality).
  RTO/RPO параметри відповідно до NIST SP 800-34.
  Уніфікована 2-рівнева структура: група -> :instances.
  """

  @doc """
  Перелік критичних процесів та їхніх параметрів доступності.

  Джерело: NIST SP 800-34 (Contingency Planning Guide).
  """
  def processes do
    %{
      processes: [
        %{
          id: "PROC-CERT",
          name: "Процеси видачі сертифікатів",
          desc: "Обробка CSR та формування підписаного сертифіката. RTO: 4h, RPO: 1h.",
          controls: ["CP", "SI"],
          instances: [
            %{id: "PROC-CERT-01", name: "Видача кваліфікованих сертифікатів", owner: "Оператор реєстрації ЦСК"}
          ]
        },
        %{
          id: "PROC-OCSP",
          name: "Процеси онлайн-перевірки статусу",
          desc: "Надання інформації про статус сертифіката в реальному часі. RTO: 0h, RPO: 0h (HA cluster).",
          controls: ["CP", "SC"],
          instances: [
            %{id: "PROC-OCSP-01", name: "Формування OCSP-відповідей (24/7)", owner: "Автоматичний сервіс ЦСК"}
          ]
        },
        %{
          id: "PROC-AUDIT",
          name: "Процеси логування та моніторингу",
          desc: "Запис подій безпеки у централізоване сховище (SIEM). RTO: 24h, RPO: 0h.",
          controls: ["AU", "CP"],
          instances: [
            %{id: "PROC-AUDIT-01", name: "Логування та моніторинг подій безпеки", owner: "Адміністратор безпеки / SIEM"}
          ]
        },
        %{
          id: "PROC-ROOT",
          name: "Церемонії генерації кореневих ключів",
          desc: "Рідкісний, але гіперкритичний офлайн-процес. RTO: 72h, RPO: 0h.",
          controls: ["PE", "AC", "PS", "AU"],
          instances: [
            %{id: "PROC-ROOT-01", name: "Церемонія генерації кореневого ключа", owner: "Комісія ЦСК (Dual Control)"}
          ]
        },
        %{
          id: "PROC-DOC",
          name: "Процеси електронного документообігу",
          desc: "Обробка, зберігання та обіг електронних судових документів. RTO: 8h, RPO: 2h.",
          controls: ["SI", "AC", "CP", "AU"],
          instances: [
            %{id: "PROC-DOC-01", name: "Реєстрація та розгляд судових справ", owner: "Судова влада України / ДП ІСС"}
          ]
        },
        %{
          id: "PROC-BKP",
          name: "Процеси резервного копіювання",
          desc: "Процес створення, верифікації та безпечного зберігання бекапів. RTO: 24h, RPO: 0h.",
          controls: ["CP", "MP", "SI"],
          instances: [
            %{id: "PROC-BKP-01", name: "Резервне копіювання та відновлення", owner: "Адміністратор резервного копіювання"}
          ]
        }
      ]
    }
  end
end

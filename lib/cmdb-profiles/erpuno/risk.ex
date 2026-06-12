defmodule CA.Risk do
  @moduledoc """
  Деталізована таксономія та карта ризиків інформаційної безпеки.
  Базується на MITRE ATT&CK, NIST SP 800-30, ISO/IEC 27005 та НД ТЗІ.
  Уніфікована 2-рівнева структура: група -> :instances.
  """

  @doc """
  Повертає таксономію ризиків у уніфікованому форматі (risks: [...]).
  """
  def taxonomy do
    %{
      risks: [
        %{
          id: "RISK-OS",
          name: "Ризики операційних систем",
          desc: "Вразливості ОС Windows, Linux, macOS.",
          controls: ["AC", "SI", "CM", "IA"],
          instances: [
            %{id: "RISK-OS-01", name: "Вразливості Active Directory (Kerberoasting, Pass-the-Hash, Golden Ticket)", controls: ["AC", "IA", "SC"]},
            %{id: "RISK-OS-02", name: "Зловживання WMI та PowerShell (Fileless-методи)", controls: ["SI", "SC", "CM"]},
            %{id: "RISK-OS-03", name: "Вразливості на рівні ядра (BYOVD, Ring 0)", controls: ["SI", "CM"]},
            %{id: "RISK-OS-04", name: "Маніпуляція маркерами доступу (Token Stealing)", controls: ["AC", "AU"]},
            %{id: "RISK-OS-05", name: "Некоректні дозволи NTFS / Share (Orphaned SIDs)", controls: ["AC", "CM"]},
            %{id: "RISK-OS-06", name: "Підвищення привілеїв Linux (Kernel, SUID, Dirty COW)", controls: ["AC", "SI"]},
            %{id: "RISK-OS-07", name: "Втеча з контейнерів Docker/Kubernetes", controls: ["SC", "CM"]},
            %{id: "RISK-OS-08", name: "Зловживання eBPF (прихований моніторинг)", controls: ["AU", "SI"]},
            %{id: "RISK-OS-09", name: "Ін'єкції динамічних бібліотек (LD_PRELOAD)", controls: ["SI", "CM"]},
            %{id: "RISK-OS-10", name: "Вразливості PAM (обхід автентифікації)", controls: ["IA", "AC"]},
            %{id: "RISK-OS-11", name: "Обхід XProtect / Gatekeeper / SIP (macOS)", controls: ["CM", "SI"]},
            %{id: "RISK-OS-12", name: "Компрометація macOS Keychain", controls: ["IA", "SC"]},
            %{id: "RISK-OS-13", name: "TCC Bypass & Spyware (macOS)", controls: ["SI", "PE"]},
            %{id: "RISK-OS-14", name: "Dyld Hijacking (macOS)", controls: ["SI"]},
            %{id: "RISK-OS-15", name: "Обхід Pointer Authentication PAC (Apple Silicon)", controls: ["SI", "SA"]}
          ]
        },
        %{
          id: "RISK-CRY",
          name: "Криптографічні ризики та ризики КЗІ",
          desc: "Вразливості криптографічних алгоритмів, HSM (ІІТ Гряда), Сайфер та Автор.",
          controls: ["SC", "PE", "SA", "IA"],
          instances: [
            %{id: "RISK-CRY-01", name: "Пост-квантові загрози SNDL (Store Now, Decrypt Later)", controls: ["SC", "RA", "SA"]},
            %{id: "RISK-CRY-02", name: "Атаки сторонніми каналами (DPA, таймінг, EM)", controls: ["SC", "PE", "SA"]},
            %{id: "RISK-CRY-03", name: "Fault Injection (Glitching, Voltage Drop)", controls: ["PE", "SI", "SC"]},
            %{id: "RISK-CRY-04", name: "Компрометація ПАК «Гряда» (ІІТ HSM)", controls: ["PE", "SC", "AC"]},
            %{id: "RISK-CRY-05", name: "Екстракція ключів з НКІ е-Токен (ІІТ)", controls: ["PE", "SC"]},
            %{id: "RISK-CRY-06", name: "Вразливості ASN.1 парсерів X.509 / CMS", controls: ["SI", "SA"]},
            %{id: "RISK-CRY-07", name: "Вразливості криптобібліотек ДСТУ (Калина, Купина, Padding Oracle)", controls: ["SA", "SI"]},
            %{id: "RISK-CRY-08", name: "Недостатня ентропія генератора псевдовипадкових чисел (PRNG)", controls: ["SC"]},
            %{id: "RISK-CRY-09", name: "Втрата або перехоплення PIN-кодів HSM (кейлогери)", controls: ["IA", "AT", "PE"]},
            %{id: "RISK-CRY-10", name: "Фізична деструкція носіїв «Автор» (CryptoCard)", controls: ["PE", "MP"]},
            %{id: "RISK-CRY-11", name: "Вразливості CCID драйверів токенів (ескалація привілеїв)", controls: ["SI", "CM"]},
            %{id: "RISK-CRY-12", name: "Підміна сесій PKCS#11 (MitM між ПЗ ЦСК та HSM)", controls: ["SC", "SI"]}
          ]
        },
        %{
          id: "RISK-NET",
          name: "Мережеві ризики",
          desc: "Вразливості мережевої інфраструктури, протоколів та периметра.",
          controls: ["SC", "SI", "AC", "IR"],
          instances: [
            %{id: "RISK-NET-01", name: "BGP Hijacking & Route Leaks (підміна анонсів AS)", controls: ["SC", "SI"]},
            %{id: "RISK-NET-02", name: "Атаки L2 (VLAN Hopping, ARP Spoofing, STP атаки)", controls: ["SC", "AC"]},
            %{id: "RISK-NET-03", name: "Вразливості IPSec / VPN (IKE downgrade, PSK витік)", controls: ["SC", "IA"]},
            %{id: "RISK-NET-04", name: "DDoS (Slowloris, SYN Flood, ампліфікація DNS/NTP)", controls: ["SC", "IR"]},
            %{id: "RISK-NET-05", name: "Компрометація Wi-Fi (KRACK, PMKID, Evil Twin)", controls: ["SC", "IA"]},
            %{id: "RISK-NET-06", name: "Вразливості DNSSEC (DNS Spoofing, помилки конфігурації)", controls: ["SC", "SI"]},
            %{id: "RISK-NET-07", name: "Відкриті інтерфейси управління (SNMPv1/v2, Telnet, REST API)", controls: ["CM", "AC", "SC"]}
          ]
        },
        %{
          id: "RISK-INF",
          name: "Інфраструктурні ризики",
          desc: "Вразливості апаратної інфраструктури, BMC, Firmware та фізичні загрози.",
          controls: ["PE", "SI", "CP", "SC"],
          instances: [
            %{id: "RISK-INF-01", name: "Компрометація BMC (IPMI, iDRAC, iLO)", controls: ["AC", "SC"]},
            %{id: "RISK-INF-02", name: "Вразливості Firmware / UEFI Bootkits", controls: ["SI", "SA"]},
            %{id: "RISK-INF-03", name: "Атаки на мікроархітектуру CPU (Spectre, Meltdown)", controls: ["SI", "SC"]},
            %{id: "RISK-INF-04", name: "Cold Boot & Rowhammer атаки на пам'ять", controls: ["PE", "SI"]},
            %{id: "RISK-INF-05", name: "Відмова дискових масивів SAN/NAS (Split-brain)", controls: ["CP", "SI"]},
            %{id: "RISK-INF-06", name: "Електромагнітне випромінювання TEMPEST", controls: ["PE", "SC"]},
            %{id: "RISK-INF-07", name: "Відмова інженерних систем (UPS, дизель, чиллер, пожежогасіння)", controls: ["PE", "CP"]}
          ]
        },
        %{
          id: "RISK-PER",
          name: "Кадрові та соціально-інженерні ризики",
          desc: "Людський фактор, фішинг, інсайдери та соціальна інженерія.",
          controls: ["AT", "PS", "AU", "AC"],
          instances: [
            %{id: "RISK-PER-01", name: "Spear Phishing & Whaling (цільовий фішинг адміністраторів)", controls: ["AT", "IR", "SI"]},
            %{id: "RISK-PER-02", name: "Watering Hole Attacks (компрометація профільних ресурсів)", controls: ["SI", "AT"]},
            %{id: "RISK-PER-03", name: "Інсайдерський саботаж та ексфільтрація (логічні бомби)", controls: ["PS", "AU", "AC"]},
            %{id: "RISK-PER-04", name: "Pretexting / Baiting / Tailgating (фізичний доступ)", controls: ["AT", "PE", "PS"]},
            %{id: "RISK-PER-05", name: "Credential Stuffing (словники та бази паролів)", controls: ["IA", "AT"]}
          ]
        },
        %{
          id: "RISK-SYNC",
          name: "Ризики синхронізації та конкурентного доступу",
          desc: "Race Condition, TOCTOU, десинхронізація часу та Split-brain.",
          controls: ["SI", "AC", "CP", "SC"],
          instances: [
            %{id: "RISK-SYNC-01", name: "Race Condition (стан гонитви у спільних ресурсах)", controls: ["SI", "SA"]},
            %{id: "RISK-SYNC-02", name: "TOCTOU (Time-of-Check to Time-of-Use)", controls: ["SI", "AC"]},
            %{id: "RISK-SYNC-03", name: "NTP Spoofing (десинхронізація часу)", controls: ["SC", "AU", "SI"]},
            %{id: "RISK-SYNC-04", name: "Split-Brain у кластерах СУБД", controls: ["CP", "SI"]},
            %{id: "RISK-SYNC-05", name: "Replication Lag (вікно доступу до застарілих даних)", controls: ["SI", "SC"]}
          ]
        },
        %{
          id: "RISK-DAT",
          name: "Ризики даних та резервних копій",
          desc: "Втрата, пошкодження або витік даних та резервних копій.",
          controls: ["CP", "MP", "SI", "AC"],
          instances: [
            %{id: "RISK-DAT-01", name: "Втрата резервних копій (Ransomware, Backup Corruption)", controls: ["CP", "MP", "SI"]},
            %{id: "RISK-DAT-02", name: "Витік електронних судових справ (несанкціонований доступ)", controls: ["AC", "SC", "PE"]}
          ]
        }
      ]
    }
  end

  @doc """
  Відображення ідентифікаторів сімейств контролів NIST SP 800-53.
  """
  def control_families do
    %{
      "AC" => "Access Control (Управління доступом)",
      "AT" => "Awareness and Training (Навчання та обізнаність)",
      "AU" => "Audit and Accountability (Аудит та підзвітність)",
      "CA" => "Security Assessment and Authorization (Оцінка безпеки)",
      "CM" => "Configuration Management (Управління конфігураціями)",
      "CP" => "Contingency Planning (Планування на випадок збоїв)",
      "IA" => "Identification and Authentication (Ідентифікація та автентифікація)",
      "IR" => "Incident Response (Реагування на інциденти)",
      "MA" => "Maintenance (Технічне обслуговування)",
      "MP" => "Media Protection (Захист носіїв інформації)",
      "PE" => "Physical and Environmental Protection (Фізичний захист)",
      "PL" => "Planning (Планування)",
      "PS" => "Personnel Security (Безпека персоналу)",
      "RA" => "Risk Assessment (Оцінка ризиків)",
      "SA" => "System and Services Acquisition (Придбання систем і послуг)",
      "SC" => "System and Communications Protection (Захист систем та комунікацій)",
      "SI" => "System and Information Integrity (Цілісність систем)",
      "SR" => "Supply Chain Risk Management (Управління ризиками ланцюга постачань)"
    }
  end

  @doc """
  Оцінка ризику за матрицею (Ймовірність × Наслідки).
  """
  def evaluate_risk(probability, impact) when probability in 1..5 and impact in 1..5 do
    score = probability * impact
    level =
      cond do
        score >= 15 -> :high
        score >= 8  -> :medium
        score >= 1  -> :low
      end
    %{score: score, level: level}
  end
end

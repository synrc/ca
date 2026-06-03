defmodule CA.Mitre do
  @moduledoc """
  Таксономія технік та тактик за фреймворком MITRE ATT&CK (Enterprise).
  Цей модуль слугує довідником для маппінгу загроз та інцидентів інформаційної безпеки,
  надаючи структурований перелік ключових етапів кібератак (Kill Chain).
  """

  @doc """
  Повертає структуру тактик (Tactics) та ключових технік (Techniques) MITRE ATT&CK.
  """
  @spec enterprise_matrix() :: map()
  def enterprise_matrix do
    %{
      reconnaissance: %{
        id: "TA0043",
        name: "Reconnaissance (Розвідка)",
        desc: "Збір інформації про цільову організацію для підготовки до атаки.",
        techniques: [
          %{id: "T1592", name: "Gather Victim Host Information", desc: "Збір даних про хости."},
          %{id: "T1589", name: "Gather Victim Identity Information", desc: "Збір даних про співробітників (імена, email)."},
          %{id: "T1595", name: "Active Scanning", desc: "Сканування мережі та вразливостей."}
        ]
      },
      resource_development: %{
        id: "TA0042",
        name: "Resource Development (Розробка ресурсів)",
        desc: "Створення, купівля або крадіжка ресурсів, необхідних для атаки (домени, інфраструктура).",
        techniques: [
          %{id: "T1583", name: "Acquire Infrastructure", desc: "Оренда VPS, реєстрація доменів."},
          %{id: "T1588", name: "Obtain Capabilities", desc: "Придбання експлойтів, малварі або сертифікатів."},
          %{id: "T1608", name: "Stage Capabilities", desc: "Розміщення шкідливого ПЗ на ресурсах (Watering Hole)."}
        ]
      },
      initial_access: %{
        id: "TA0001",
        name: "Initial Access (Початковий доступ)",
        desc: "Вектори, які використовує зловмисник для отримання доступу до мережі.",
        techniques: [
          %{id: "T1189", name: "Drive-by Compromise", desc: "Компрометація через веб-браузер."},
          %{id: "T1190", name: "Exploit Public-Facing Application", desc: "Експлуатація вразливостей публічних сервісів."},
          %{id: "T1566", name: "Phishing", desc: "Фішинг (Spear Phishing, Attachment, Link)."},
          %{id: "T1078", name: "Valid Accounts", desc: "Використання дійсних облікових записів (в т.ч. дефолтних)."}
        ]
      },
      execution: %{
        id: "TA0002",
        name: "Execution (Виконання)",
        desc: "Запуск шкідливого коду на локальній або віддаленій системі.",
        techniques: [
          %{id: "T1059", name: "Command and Scripting Interpreter", desc: "PowerShell, Bash, CMD, Python, AppleScript."},
          %{id: "T1203", name: "Exploitation for Client Execution", desc: "Експлуатація клієнтського ПЗ (Office, Browser)."},
          %{id: "T1053", name: "Scheduled Task/Job", desc: "Використання Cron або Windows Task Scheduler."},
          %{id: "T1047", name: "Windows Management Instrumentation", desc: "Виконання через WMI."}
        ]
      },
      persistence: %{
        id: "TA0003",
        name: "Persistence (Закріплення)",
        desc: "Збереження доступу до системи попри перезавантаження або зміну облікових даних.",
        techniques: [
          %{id: "T1547", name: "Boot or Logon Autostart Execution", desc: "Ключі реєстру Run/RunOnce, Startup папки."},
          %{id: "T1543", name: "Create or Modify System Process", desc: "Створення системних служб (Services, Daemons)."},
          %{id: "T1546", name: "Event Triggered Execution", desc: "WMI Event Subscriptions, IFEO."},
          %{id: "T1505", name: "Server Software Component", desc: "Встановлення веб-шеллів (Web Shell)."}
        ]
      },
      privilege_escalation: %{
        id: "TA0004",
        name: "Privilege Escalation (Підвищення привілеїв)",
        desc: "Отримання вищих прав доступу (SYSTEM, root).",
        techniques: [
          %{id: "T1548", name: "Abuse Elevation Control Mechanism", desc: "Обхід UAC, SUID/SGID, sudo caching."},
          %{id: "T1134", name: "Access Token Manipulation", desc: "Маніпуляція маркерами (Token Stealing)."},
          %{id: "T1068", name: "Exploitation for Privilege Escalation", desc: "Експлуатація вразливостей ОС або ядра."},
          %{id: "T1574", name: "Hijack Execution Flow", desc: "DLL Hijacking, LD_PRELOAD."}
        ]
      },
      defense_evasion: %{
        id: "TA0005",
        name: "Defense Evasion (Обхід захисту)",
        desc: "Техніки уникнення виявлення засобами захисту (Антивіруси, EDR/XDR).",
        techniques: [
          %{id: "T1140", name: "Deobfuscate/Decode Files or Information", desc: "Деобфускація коду під час виконання."},
          %{id: "T1070", name: "Indicator Removal on Host", desc: "Очищення журналів (Event Logs), видалення файлів."},
          %{id: "T1036", name: "Masquerading", desc: "Маскування під легітимні системні процеси (напр., svchost.exe)."},
          %{id: "T1055", name: "Process Injection", desc: "Ін'єкція коду у легітимні процеси (DLL Injection, Process Hollowing)."},
          %{id: "T1218", name: "System Binary Proxy Execution", desc: "Використання LOLBins (rundll32.exe, mshta.exe)."}
        ]
      },
      credential_access: %{
        id: "TA0006",
        name: "Credential Access (Доступ до облікових даних)",
        desc: "Викрадення паролів, хешів, квитків Kerberos або токенів.",
        techniques: [
          %{id: "T1110", name: "Brute Force", desc: "Перебір паролів (Credential Stuffing, Password Spraying)."},
          %{id: "T1003", name: "OS Credential Dumping", desc: "Екстракція з LSASS, SAM, /etc/shadow."},
          %{id: "T1558", name: "Steal or Forge Kerberos Tickets", desc: "Golden/Silver Ticket, Kerberoasting."},
          %{id: "T1056", name: "Input Capture", desc: "Keylogging, перехоплення вводу з екрану."}
        ]
      },
      discovery: %{
        id: "TA0007",
        name: "Discovery (Розвідка в мережі)",
        desc: "Вивчення скомпрометованої системи та внутрішньої мережі.",
        techniques: [
          %{id: "T1087", name: "Account Discovery", desc: "Збір списків локальних або доменних користувачів."},
          %{id: "T1046", name: "Network Service Scanning", desc: "Сканування відкритих портів у внутрішній мережі."},
          %{id: "T1082", name: "System Information Discovery", desc: "Отримання даних про версію ОС, архітектуру."},
          %{id: "T1016", name: "System Network Configuration Discovery", desc: "Збір даних про IP, маршрутизацію, DNS."}
        ]
      },
      lateral_movement: %{
        id: "TA0008",
        name: "Lateral Movement (Бічне переміщення)",
        desc: "Просування по мережі від однієї системи до іншої.",
        techniques: [
          %{id: "T1210", name: "Exploitation of Remote Services", desc: "Експлуатація вразливостей у віддалених сервісах (SMB, RDP)."},
          %{id: "T1550", name: "Use Alternate Authentication Material", desc: "Pass-the-Hash, Pass-the-Ticket."},
          %{id: "T1021", name: "Remote Services", desc: "Використання легітимних RDP, SSH, VNC, WinRM."}
        ]
      },
      collection: %{
        id: "TA0009",
        name: "Collection (Збір даних)",
        desc: "Пошук та агрегація цінної інформації для викрадення.",
        techniques: [
          %{id: "T1560", name: "Archive Collected Data", desc: "Архівація та шифрування даних перед викраденням."},
          %{id: "T1119", name: "Automated Collection", desc: "Автоматизований пошук файлів за розширеннями."},
          %{id: "T1114", name: "Email Collection", desc: "Збір електронних листів з локальних клієнтів або Exchange сервісу."},
          %{id: "T1056", name: "Input Capture", desc: "Перехоплення натискань клавіш та екрану."}
        ]
      },
      command_and_control: %{
        id: "TA0011",
        name: "Command and Control (Управління та контроль)",
        desc: "Комунікація шкідливого ПЗ із серверами зловмисників (C2).",
        techniques: [
          %{id: "T1071", name: "Application Layer Protocol", desc: "Комунікація через веб-протоколи (HTTP/HTTPS, DNS)."},
          %{id: "T1573", name: "Encrypted Channel", desc: "Шифрування трафіку C2 для уникнення IDS."},
          %{id: "T1090", name: "Proxy", desc: "Використання проксі-серверів для приховування IP."},
          %{id: "T1105", name: "Ingress Tool Transfer", desc: "Завантаження додаткових інструментів з C2 сервера."}
        ]
      },
      exfiltration: %{
        id: "TA0010",
        name: "Exfiltration (Ексфільтрація)",
        desc: "Викрадення даних з мережі організації.",
        techniques: [
          %{id: "T1041", name: "Exfiltration Over C2 Channel", desc: "Передача даних через існуючий канал управління."},
          %{id: "T1567", name: "Exfiltration Over Web Service", desc: "Вивантаження даних у хмарні сховища (Google Drive, Dropbox)."},
          %{id: "T1048", name: "Exfiltration Over Alternative Protocol", desc: "Використання інших протоколів (ICMP, DNS tunneling)."}
        ]
      },
      impact: %{
        id: "TA0040",
        name: "Impact (Вплив)",
        desc: "Деструктивні дії: шифрування, видалення, саботаж систем.",
        techniques: [
          %{id: "T1485", name: "Data Destruction", desc: "Незворотне видалення або затирання даних."},
          %{id: "T1486", name: "Data Encrypted for Impact", desc: "Шифрування файлів для вимагання викупу (Ransomware)."},
          %{id: "T1490", name: "Inhibit System Recovery", desc: "Видалення тіньових копій (vssadmin), вимкнення відновлення."},
          %{id: "T1498", name: "Network Denial of Service", desc: "DDoS атаки для виведення систем з ладу."}
        ]
      }
    }
  end

  @doc """
  Функція для пошуку техніки за її ідентифікатором (наприклад, "T1003").
  Повертає карту знайденої техніки та назву тактики, до якої вона належить.
  """
  @spec find_technique(String.t()) :: map() | nil
  def find_technique(technique_id) do
    enterprise_matrix()
    |> Enum.find_value(fn {tactic_key, tactic_data} ->
      case Enum.find(tactic_data.techniques, &(&1.id == technique_id)) do
        nil -> nil
        technique -> Map.put(technique, :tactic, tactic_key)
      end
    end)
  end
end

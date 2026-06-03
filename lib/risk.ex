defmodule CA.Risk do
  @moduledoc """
  Деталізована таксономія та карта ризиків інформаційної безпеки.
  Розроблена для комплексної оцінки ризиків та впровадження заходів захисту (RA-1, RA-3, RA-5).
  Включає поглиблений аналіз апаратних, програмних, мережевих, криптографічних
  (зокрема КЗІ ІІТ, Сайфер, Автор) та людських векторів атак, базуючись на сучасних
  дослідженнях, класифікаціях MITRE ATT&CK, NIST SP 800-30, ISO/IEC 27005 та НД ТЗІ.
  """

  @spec taxonomy() :: %{
          cryptography_and_kzi: %{
            author: [map(), ...],
            cipher: [map(), ...],
            general: [map(), ...],
            iit: [map(), ...]
          },
          infrastructure: [
            %{controls: [...], desc: <<_::64, _::_*8>>, id: <<_::64>>, name: <<_::64, _::_*8>>},
            ...
          ],
          network: [
            %{controls: [...], desc: <<_::64, _::_*8>>, id: <<_::64>>, name: <<_::64, _::_*8>>},
            ...
          ],
          os: %{linux: [map(), ...], macos: [map(), ...], windows: [map(), ...]},
          personnel: [
            %{controls: [...], desc: <<_::64, _::_*8>>, id: <<_::64>>, name: <<_::64, _::_*8>>},
            ...
          ],
          synchronization: [
            %{controls: [...], desc: <<_::64, _::_*8>>, id: <<_::64>>, name: <<_::64, _::_*8>>},
            ...
          ]
        }
  @doc """
  Повертає максимально повну та розширену таксономію ризиків, згруповану за доменами.
  """
  def taxonomy do
    %{
      os: %{
        windows: [
          %{
            id: "R-OS-W-01",
            name: "Вразливості Active Directory (Advanced)",
            desc:
              "Атаки Kerberoasting, AS-REP Roasting, Pass-the-Hash, Golden/Silver Ticket, DCSync, DCShadow.",
            controls: ["AC", "IA", "SC"]
          },
          %{
            id: "R-OS-W-02",
            name: "Зловживання WMI та PowerShell",
            desc:
              "Використання Windows Management Instrumentation та Fileless-методів для виконання коду та персистентності.",
            controls: ["SI", "SC", "CM"]
          },
          %{
            id: "R-OS-W-03",
            name: "Вразливості на рівні ядра (Ring 0)",
            desc:
              "Експлуатація вразливостей сторонніх драйверів (BYOVD) для обходу EDR та PatchGuard.",
            controls: ["SI", "CM"]
          },
          %{
            id: "R-OS-W-04",
            name: "Маніпуляція маркерами доступу",
            desc:
              "Token Stealing, маніпуляція привілеями (SeDebugPrivilege, SeImpersonatePrivilege) для ескалації.",
            controls: ["AC", "AU"]
          },
          %{
            id: "R-OS-W-05",
            name: "Некоректні дозволи NTFS / Share",
            desc:
              "Отримання доступу до файлів через помилки в налаштуваннях ACL або залишкові права (Orphaned SIDs).",
            controls: ["AC", "CM"]
          }
        ],
        linux: [
          %{
            id: "R-OS-L-01",
            name: "Підвищення привілеїв (Kernel & SUID)",
            desc:
              "Експлуатація локальних вразливостей ядра (Dirty COW, Dirty Pipe), SUID-бінарників та Capabilities.",
            controls: ["AC", "SI"]
          },
          %{
            id: "R-OS-L-02",
            name: "Втеча з контейнерів (Container Escape)",
            desc:
              "Прорив ізоляції Docker/Kubernetes через зловживання просторами імен (Namespaces), cgroups, або сокетом Docker.",
            controls: ["SC", "CM"]
          },
          %{
            id: "R-OS-L-03",
            name: "Зловживання eBPF",
            desc:
              "Використання Extended Berkeley Packet Filter для прихованого моніторингу та маніпуляції системними викликами.",
            controls: ["AU", "SI"]
          },
          %{
            id: "R-OS-L-04",
            name: "Ін'єкції динамічних бібліотек",
            desc:
              "Перехоплення викликів через LD_PRELOAD або маніпуляція RPATH/RUNPATH для виконання шкідливого коду.",
            controls: ["SI", "CM"]
          },
          %{
            id: "R-OS-L-05",
            name: "Вразливості PAM",
            desc:
              "Некоректна конфігурація Pluggable Authentication Modules, що дозволяє обхід автентифікації.",
            controls: ["IA", "AC"]
          }
        ],
        macos: [
          %{
            id: "R-OS-M-01",
            name: "Обхід XProtect / Gatekeeper / SIP",
            desc:
              "Запуск шкідливого ПЗ шляхом маніпуляції підписами (Code Signing), обходу System Integrity Protection.",
            controls: ["CM", "SI"]
          },
          %{
            id: "R-OS-M-02",
            name: "Компрометація Keychain",
            desc:
              "Екстракція збережених паролів та криптографічного матеріалу з Keychain через вразливості процесів.",
            controls: ["IA", "SC"]
          },
          %{
            id: "R-OS-M-03",
            name: "TCC Bypass & Spyware",
            desc:
              "Обхід Transparency, Consent, and Control для доступу до мікрофона, камери чи даних без згоди користувача.",
            controls: ["SI", "PE"]
          },
          %{
            id: "R-OS-M-04",
            name: "Dyld Hijacking",
            desc: "Перехоплення динамічного завантаження бібліотек в середовищі macOS.",
            controls: ["SI"]
          },
          %{
            id: "R-OS-M-05",
            name: "Обхід Pointer Authentication (PAC)",
            desc:
              "Специфічні атаки на архітектуру Apple Silicon (ARM64) для підміни вказівників управління пам'яттю.",
            controls: ["SI", "SA"]
          }
        ]
      },
      cryptography_and_kzi: %{
        general: [
          %{
            id: "R-CRY-01",
            name: "Пост-квантові загрози (SNDL)",
            desc:
              "Store Now, Decrypt Later атаки на асиметричну криптографію з огляду на розвиток квантових обчислень (алгоритм Шора).",
            controls: ["SC", "RA", "SA"]
          },
          %{
            id: "R-CRY-02",
            name: "Атаки сторонніми каналами (Side-Channel)",
            desc:
              "Диференціальний аналіз енергоспоживання (DPA), таймінг-атаки, електромагнітні випромінювання на процесі шифрування.",
            controls: ["SC", "PE", "SA"]
          },
          %{
            id: "R-CRY-03",
            name: "Атаки внесення помилок (Fault Injection)",
            desc:
              "Апаратне внесення збоїв (Glitching, Voltage Drop) для пропуску інструкцій автентифікації або перевірки підпису.",
            controls: ["PE", "SI", "SC"]
          }
        ],
        iit: [
          %{
            id: "R-KZI-IIT-01",
            name: "Компрометація ПАК «Гряда»",
            desc: "Фізичний або логічний доступ до мережевого шифратора або криптомодуля.",
            controls: ["PE", "SC", "AC"]
          },
          %{
            id: "R-KZI-IIT-02",
            name: "Екстракція ключів з НКІ (е-Токен)",
            desc:
              "Спроби апаратного зчитування закритого ключа за допомогою мікроскопів або хімічного травлення.",
            controls: ["PE", "SC"]
          },
          %{
            id: "R-KZI-IIT-03",
            name: "Вразливості ASN.1 парсерів",
            desc:
              "Переповнення буфера або DoS при обробці специфічних або зловмисних структур X.509 та CMS інфраструктурою ЦСК.",
            controls: ["SI", "SA"]
          }
        ],
        cipher: [
          %{
            id: "R-KZI-CIP-01",
            name: "Вразливості криптобібліотек (ДСТУ)",
            desc:
              "Помилки при програмній реалізації алгоритмів (Калина, Купина), можливість атак типу Padding Oracle.",
            controls: ["SA", "SI"]
          },
          %{
            id: "R-KZI-CIP-02",
            name: "Недостатня ентропія ГВЧ",
            desc:
              "Генерація передбачуваних ключів через проблеми з апаратним або програмним генератором псевдовипадкових чисел (PRNG).",
            controls: ["SC"]
          },
          %{
            id: "R-KZI-CIP-03",
            name: "Втрата або перехоплення PIN-кодів",
            desc:
              "Витік аутентифікаційних параметрів адміністраторів HSM через кейлогери або плече-серфінг.",
            controls: ["IA", "AT", "PE"]
          }
        ],
        author: [
          %{
            id: "R-KZI-AUT-01",
            name: "Фізична деструкція носіїв «Автор»",
            desc:
              "Виведення з ладу захищених смарт-карт (CryptoCard) через електростатичні розряди або механічне пошкодження.",
            controls: ["PE", "MP"]
          },
          %{
            id: "R-KZI-AUT-02",
            name: "Вразливості CCID драйверів",
            desc:
              "Експлуатація драйверів токенів для ескалації привілеїв у хост-операційній системі.",
            controls: ["SI", "CM"]
          },
          %{
            id: "R-KZI-AUT-03",
            name: "Підміна сесій PKCS#11",
            desc:
              "Атаки посередника (Man-in-the-Middle) на інтерфейс між програмним забезпеченням ЦСК та модулем HSM.",
            controls: ["SC", "SI"]
          }
        ]
      },
      network: [
        %{
          id: "R-NET-01",
          name: "BGP Hijacking & Route Leaks",
          desc:
            "Підміна анонсів автономних систем (AS) для перехоплення або Blackholing трафіку.",
          controls: ["SC", "SI"]
        },
        %{
          id: "R-NET-02",
          name: "Атаки на протоколи 2-го рівня (L2)",
          desc:
            "VLAN Hopping, ARP Spoofing, MAC Flooding, атаки на STP (Spanning Tree Protocol) для перехоплення трафіку в LAN.",
          controls: ["SC", "AC"]
        },
        %{
          id: "R-NET-03",
          name: "Вразливості IPSec / VPN",
          desc:
            "Атаки на узгодження IKE, downgrade атак на алгоритми шифрування, витік IKE PSK (Pre-Shared Keys).",
          controls: ["SC", "IA"]
        },
        %{
          id: "R-NET-04",
          name: "Мережеве виснаження ресурсів",
          desc:
            "Складні DDoS атаки рівня додатків (Slowloris), TCP SYN Flood, атаки ампліфікації через DNS, NTP, Memcached.",
          controls: ["SC", "IR"]
        },
        %{
          id: "R-NET-05",
          name: "Компрометація Wi-Fi інфраструктури",
          desc:
            "Атаки KRACK, PMKID ексфільтрація (WPA2/WPA3), Evil Twin (підробні точки доступу).",
          controls: ["SC", "IA"]
        },
        %{
          id: "R-NET-06",
          name: "Вразливості протоколу DNSSEC",
          desc:
            "Підробка відповідей DNS (DNS Spoofing), обхід валідації DNSSEC через помилки конфігурації зон.",
          controls: ["SC", "SI"]
        },
        %{
          id: "R-NET-07",
          name: "Відкриті інтерфейси управління",
          desc:
            "Експлуатація вразливостей в SNMPv1/v2, Telnet, неавтентифікованих REST API на граничному обладнанні.",
          controls: ["CM", "AC", "SC"]
        }
      ],
      infrastructure: [
        %{
          id: "R-INF-01",
          name: "Експлуатація Baseboard Management Controller (BMC)",
          desc:
            "Компрометація інтерфейсів IPMI, iDRAC, iLO для повного контролю над сервером поза межами ОС.",
          controls: ["AC", "SC"]
        },
        %{
          id: "R-INF-02",
          name: "Вразливості Firmware / UEFI Bootkits",
          desc:
            "Впровадження шкідливого коду (Bootkits) на рівні материнської плати або контролерів для персистенції.",
          controls: ["SI", "SA"]
        },
        %{
          id: "R-INF-03",
          name: "Атаки на мікроархітектуру CPU",
          desc:
            "Спекулятивне виконання (Spectre, Meltdown) та маніпуляції з кешем для екстракції криптоключів з інших ВМ.",
          controls: ["SI", "SC"]
        },
        %{
          id: "R-INF-04",
          name: "Атаки Cold Boot & Rowhammer",
          desc:
            "Фізичний зріз пам'яті після перезавантаження (Cold Boot) або зміна бітів пам'яті сусідніх комірок (Rowhammer).",
          controls: ["PE", "SI"]
        },
        %{
          id: "R-INF-05",
          name: "Відмова дискових масивів (SAN/NAS)",
          desc:
            "Синхронна відмова множини дисків (Split-brain в кластерах), корупція метаданих файлових систем.",
          controls: ["CP", "SI"]
        },
        %{
          id: "R-INF-06",
          name: "Електромагнітне випромінювання (TEMPEST)",
          desc:
            "Перехоплення даних шляхом аналізу побічних електромагнітних випромінювань від моніторів або кабелів.",
          controls: ["PE", "SC"]
        },
        %{
          id: "R-INF-07",
          name: "Відмова інженерних систем життєзабезпечення",
          desc:
            "Синхронна відмова ДЖБ (UPS), дизель-генераторів, систем чиллерів або установок газового пожежогасіння.",
          controls: ["PE", "CP"]
        }
      ],
      personnel: [
        %{
          id: "R-PER-01",
          name: "Spear Phishing & Whaling",
          desc:
            "Цільовий фішинг на ключових осіб (адміністраторів ЦСК) з використанням висококонтекстуальних повідомлень.",
          controls: ["AT", "IR", "SI"]
        },
        %{
          id: "R-PER-02",
          name: "Watering Hole Attacks",
          desc:
            "Компрометація профільних веб-ресурсів, які часто відвідує цільова аудиторія, для зараження їх робочих станцій.",
          controls: ["SI", "AT"]
        },
        %{
          id: "R-PER-03",
          name: "Інсайдерський саботаж та ексфільтрація",
          desc:
            "Свідома шкода, логічні бомби, крадіжка комерційної таємниці або приватних ключів авторизованими співробітниками.",
          controls: ["PS", "AU", "AC"]
        },
        %{
          id: "R-PER-04",
          name: "Зловживання когнітивними упередженнями",
          desc:
            "Методи претекстінгу (Pretexting), Baiting та Tailgating для отримання фізичного доступу до чистих зон (Clean Rooms).",
          controls: ["AT", "PE", "PS"]
        },
        %{
          id: "R-PER-05",
          name: "Компрометація облікових даних (Credential Stuffing)",
          desc:
            "Використання словників та викрадених баз паролів, експлуатація явища повторного використання паролів.",
          controls: ["IA", "AT"]
        }
      ],
      synchronization: [
        %{
          id: "R-SYNC-01",
          name: "Стан гонитви (Race Condition)",
          desc:
            "Експлуатація неодночасності доступу до спільних ресурсів, що дозволяє несанкціоновану зміну стану або обхід перевірок.",
          controls: ["SI", "SA"]
        },
        %{
          id: "R-SYNC-02",
          name: "Time-of-Check to Time-of-Use (TOCTOU)",
          desc:
            "Маніпуляція даними (наприклад, файловими посиланнями) між моментом їх перевірки та фактичним використанням системою.",
          controls: ["SI", "AC"]
        },
        %{
          id: "R-SYNC-03",
          name: "Десинхронізація часу (NTP Spoofing)",
          desc:
            "Підміна відповідей NTP для зсуву системного часу, що призводить до валідації прострочених сертифікатів або відмови автентифікації.",
          controls: ["SC", "AU", "SI"]
        },
        %{
          id: "R-SYNC-04",
          name: "Split-Brain у кластерах",
          desc:
            "Втрата зв'язку між вузлами кластера з наступною незалежною модифікацією даних (порушення консистентності баз даних).",
          controls: ["CP", "SI"]
        },
        %{
          id: "R-SYNC-05",
          name: "Затримки реплікації (Replication Lag)",
          desc:
            "Експлуатація часового вікна доступу до застарілих даних на Read-репліках СУБД перед їх остаточним оновленням.",
          controls: ["SI", "SC"]
        }
      ]
    }
  end

  @doc """
  Відображення ідентифікаторів сімейств контролів (NIST SP 800-53 / НД ТЗІ) у їх опис.
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
  Науково обґрунтована оцінка ризику на базі метрик FAIR або класичної матриці (Ймовірність х Наслідки).
  """
  def evaluate_risk(probability, impact) when probability in 1..5 and impact in 1..5 do
    score = probability * impact

    level =
      cond do
        score >= 15 -> :high
        score >= 8 -> :medium
        score >= 1 -> :low
      end

    %{score: score, level: level}
  end
end
